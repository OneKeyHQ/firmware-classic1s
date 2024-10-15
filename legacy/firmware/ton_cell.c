#include <stdbool.h>

#include "fsm.h"
#include "messages-ton.pb.h"
#include "messages.h"
#include "messages.pb.h"
#include "sha2.h"
#include "ton_address.h"
#include "ton_cell.h"
#include "util.h"

static const uint8_t REACH_BOC_MAGIC_PREFIX[4] = {0xb5, 0xee, 0x9c, 0x72};

bool ton_hash_cell(BitString_t* bits, CellRef_t* refs, uint8_t refs_count,
                   CellRef_t* out) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);

  // Data and descriptors
  uint16_t len = bits->data_cursor;
  uint8_t d1 = refs_count;                     // refs descriptor
  uint8_t d2 = (len >> 3) + ((len + 7) >> 3);  // bits descriptor
  uint8_t d[2] = {d1, d2};
  bitstring_final(bits);

  sha256_Update(&ctx, d, 2);
  sha256_Update(&ctx, bits->data, (bits->data_cursor + 7) / 8);

  // Hash ref depths
  for (int i = 0; i < refs_count; i++) {
    struct CellRef_t md = refs[i];
    uint8_t mdd[2] = {md.max_depth / 256, md.max_depth % 256};
    sha256_Update(&ctx, mdd, 2);
  }

  // Hash ref digests
  for (int i = 0; i < refs_count; i++) {
    struct CellRef_t md = refs[i];
    sha256_Update(&ctx, md.hash, HASH_LEN);
  }

  // Finalize
  sha256_Final(&ctx, out->hash);

  // Depth
  out->max_depth = 0;
  if (refs_count > 0) {
    for (int i = 0; i < refs_count; i++) {
      struct CellRef_t md = refs[i];
      if (md.max_depth > out->max_depth) {
        out->max_depth = md.max_depth;
      }
    }
    out->max_depth = out->max_depth + 1;
  }

  return true;
}

bool ton_create_transfer_body(const char* memo, CellRef_t* payload) {
  if (memo == NULL || strlen(memo) == 0) {
    return false;
  }

  BitString_t bits;

  bitstring_init(&bits);
  bitstring_write_uint(&bits, 0, 32);  // text comment tag
  bitstring_write_buffer(&bits, (uint8_t*)memo, strlen(memo));

  ton_hash_cell(&bits, NULL, 0, payload);

  char payload_ref_hash_hex[HASH_LEN * 2 + 1];
  data2hexaddr(payload->hash, HASH_LEN, payload_ref_hash_hex);

  return true;
}

bool ton_create_jetton_transfer_body(uint8_t dest_workchain, uint8_t* dest_hash,
                                     uint64_t jetton_value,
                                     uint64_t forward_amount,
                                     const char* forward_payload,
                                     uint8_t resp_workchain, uint8_t* resp_hash,
                                     CellRef_t* payload) {
  BitString_t bits;

  bitstring_init(&bits);
  bitstring_write_uint(&bits, 0xf8a7ea5, 32);  // jetton transfer op-code
  bitstring_write_uint(&bits, 0, 64);          // query id
  bitstring_write_coins(&bits, jetton_value);
  bitstring_write_address(&bits, dest_workchain, dest_hash);  // to addr
  bitstring_write_address(&bits, resp_workchain, resp_hash);  // response addr
  bitstring_write_bit(&bits, 0);                 // no custom payload
  bitstring_write_coins(&bits, forward_amount);  // forward amount
  bitstring_write_bit(&bits, 0);  // forward payload in this cell, not separate
  if (forward_payload != NULL && strlen(forward_payload) > 0) {
    bitstring_write_uint(&bits, 0x00000000, 32);  // text comment op-code
    bitstring_write_buffer(&bits, (uint8_t*)forward_payload,
                           strlen(forward_payload));
  }
  ton_hash_cell(&bits, NULL, 0, payload);
  return true;
}

bool build_message_ref(bool is_bounceable, uint8_t dest_workchain,
                       uint8_t* dest_hash, uint64_t value,
                       CellRef_t* payload, const char* payload_str, CellRef_t* out_message_ref) {
  BitString_t bits;
  bitstring_init(&bits);

  bitstring_write_bit(&bits, 0);                              // tag
  bitstring_write_bit(&bits, 1);                              // ihr_disabled
  bitstring_write_bit(&bits, is_bounceable ? 1 : 0);          // bounce
  bitstring_write_bit(&bits, 0);                              // bounced
  bitstring_write_null_address(&bits);                        // from
  bitstring_write_address(&bits, dest_workchain, dest_hash);  // to
  bitstring_write_coins(&bits, value);                        // amount
  bitstring_write_bit(&bits, 0);       // Currency collection (not supported)
  bitstring_write_coins(&bits, 0);     // ihr_fees
  bitstring_write_coins(&bits, 0);     // fwd_fees
  bitstring_write_uint(&bits, 0, 64);  // CreatedLT
  bitstring_write_uint(&bits, 0, 32);  // CreatedAt

  if (payload_str != NULL && strlen(payload_str) > 0) {
    bitstring_write_bit(&bits, 0);  // no state-init
    bitstring_write_bit(&bits, 0);  // body in line

    bitstring_write_uint(&bits, 0x00000000, 32);  // text comment transfer op-code
    bitstring_write_buffer(&bits, (uint8_t*)payload_str, strlen(payload_str));

    return ton_hash_cell(&bits, NULL, 0, out_message_ref);

  } else if (payload != NULL) {
    bitstring_write_bit(&bits, 0);  // no state-init
    bitstring_write_bit(&bits, 1);  // body in ref

    struct CellRef_t refs[1] = {*payload};
    return ton_hash_cell(&bits, refs, 1, out_message_ref);
  } else {
    bitstring_write_bit(&bits, 0);  // no state-init
    bitstring_write_bit(&bits, 0);  // body inline

    return ton_hash_cell(&bits, NULL, 0, out_message_ref);
  }
}

bool ton_create_message_digest(uint32_t expire_at, uint32_t seqno,
                               bool is_bounceable, uint8_t dest_workchain,
                               uint8_t* dest_hash, uint64_t value, uint8_t mode,
                               CellRef_t* payload,
                               const char* payload_str,
                               const char** ext_dest,
                               const uint64_t* ext_ton_amount,
                               const char** ext_payload, uint8_t ext_dest_count,
                               uint8_t* digest) {
  // Build Internal Message
  struct CellRef_t internalMessageRef;
  if (!build_message_ref(is_bounceable, dest_workchain, dest_hash, value,
                         payload, payload_str, &internalMessageRef)) {
    return false;
  }

  // Build Ext Messages (if any)
  struct CellRef_t extMessageRefs[3];
  int ext_message_count = 0;

  for (int i = 0; i < ext_dest_count && i < 3; i++) {
    TON_PARSED_ADDRESS parsed_addr;

    if (!ton_parse_addr(ext_dest[i], &parsed_addr)) {
      return false;
    }

    CellRef_t ext_payload_ref;
    if (ext_payload && ext_payload[i] && strlen(ext_payload[i]) > 0) {
      if (strlen(ext_payload[i]) >= 8 &&
          memcmp(ext_payload[i], "b5ee9c72", 8) == 0) {
        unsigned int data_len = strlen(ext_payload[i]) / 2;
        uint8_t raw_data[data_len];
        hex2data(ext_payload[i], raw_data, &data_len);
        if (!ton_parse_boc(raw_data, data_len, &ext_payload_ref)) {
          return false;
        }
      } else {
        if (!ton_create_transfer_body(ext_payload[i], &ext_payload_ref)) {
          return false;
        }
      }
      char payload_ref_hash_hex[HASH_LEN * 2 + 1];
      data2hexaddr(ext_payload_ref.hash, HASH_LEN, payload_ref_hash_hex);
    } else {
      memset(&ext_payload_ref, 0, sizeof(CellRef_t));
    }

    if (!build_message_ref(parsed_addr.is_bounceable,
                           (uint8_t)parsed_addr.workchain, parsed_addr.hash,
                           ext_ton_amount[i],
                           ext_payload[i] ? &ext_payload_ref : NULL, NULL,
                           &extMessageRefs[ext_message_count])) {
      return false;
    }
    ext_message_count++;
  }

  // Build Order
  BitString_t order_bits;
  bitstring_init(&order_bits);
  bitstring_write_uint(&order_bits, 698983191, 32);  // Wallet ID

  if (seqno > 0) {
    bitstring_write_uint(&order_bits, expire_at, 32);  // Timeout
  } else {
    bitstring_write_uint(&order_bits, 0xFFFFFFFF, 32);
  }
  bitstring_write_uint(&order_bits, seqno, 32);  // Seqno
  bitstring_write_uint(&order_bits, 0, 8);       // Simple order
  bitstring_write_uint(&order_bits, mode, 8);    // Send Mode

  // Prepare all message refs
  struct CellRef_t allMessageRefs[4];  // 1 internal + up to 3 external
  int total_refs =
      1;  // Start from 1 because there's always an internal message
  allMessageRefs[0] = internalMessageRef;

  for (int i = 0; i < ext_message_count; i++) {
    bitstring_write_uint(&order_bits, mode, 8);  // Send Mode
    allMessageRefs[total_refs++] = extMessageRefs[i];
  }

  // Hash the order
  struct CellRef_t orderRef;
  if (!ton_hash_cell(&order_bits, allMessageRefs, total_refs, &orderRef)) {
    return false;
  }

  // Result
  memcpy(digest, orderRef.hash, HASH_LEN);
  return true;
}

void set_top_upped_array(uint8_t* array, size_t array_len,
                         bool fullfilled_bytes, uint16_t* cursor) {
  *cursor =
      array_len * 8;  // Initialize cursor to the length of the array times 8

  if (fullfilled_bytes || array_len == 0) {
    return;  // If it's a fully filled byte or the array is empty, return
             // directly
  }

  // Start from the end, check up to 7 bits
  for (int i = 0; i < 7; i++) {
    (*cursor)--;
    size_t byte_index = *cursor / 8;

    if ((array[byte_index] & (1 << i)) != 0) {
      // Found a bit set to 1, set it to 0
      array[byte_index] &= ~(1 << i);

      return;
    }
  }

  // If no bit set to 1 is found within 7 bits, throw an error
  fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid top-upped array");
}

bool ton_parse_boc(const uint8_t* input_boc, size_t input_boc_len,
                   CellRef_t* payload) {
  if (input_boc_len < 5 || input_boc_len > 1024) {
    return false;
  }

  // Compare BOC with magic prefix
  if (memcmp(input_boc, REACH_BOC_MAGIC_PREFIX, 4) != 0) {
    return false;  // Does not match
  }

  // Record BOC data
  uint8_t boc[input_boc_len];
  memcpy(boc, input_boc, input_boc_len);

  size_t index = 0;
  index += 4;  // Remove the first four bytes of the BOC prefix

  // Parse BOC header
  uint8_t flags_byte = boc[index++];
  // bool has_idx = flags_byte & 0x80;
  // bool hash_crc32 = flags_byte & 0x40;
  // bool has_cache_bits = flags_byte & 0x20;
  // uint8_t flags = ((flags_byte & 0x10) << 1) | (flags_byte & 0x08);
  uint8_t size_bytes = flags_byte & 0x07;

  // Read offset_bytes
  uint8_t offset_bytes = boc[index++];

  // Read cells_num
  uint32_t cells_num = 0;
  for (int i = 0; i < size_bytes; i++) {
    cells_num = (cells_num << 8) | boc[index++];
  }

  if (cells_num > 4) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid cells number");
    return false;
  }

  // Read roots_num
  uint32_t roots_num = 0;
  for (int i = 0; i < size_bytes; i++) {
    roots_num = (roots_num << 8) | boc[index++];
  }

  // Read absent_num
  uint32_t absent_num = 0;
  for (int i = 0; i < size_bytes; i++) {
    absent_num = (absent_num << 8) | boc[index++];
  }

  // Read tot_cells_size
  uint32_t tot_cells_size = 0;
  for (int i = 0; i < offset_bytes; i++) {
    tot_cells_size = (tot_cells_size << 8) | boc[index++];
  }

  // Read root list (always zero)
  uint32_t root_cell_index = 0;
  if (roots_num > 0) {
    for (int i = 0; i < offset_bytes; i++) {
      root_cell_index = (root_cell_index << 8) | boc[index++];
    }
  }

  // First pass: Record data and references for each cell
  CellData_t cell_data[cells_num];
  for (uint32_t i = 0; i < cells_num; i++) {
    bitstring_init(&cell_data[i].bits);
    uint8_t d1 = boc[index++];
    uint8_t d2 = boc[index++];

    cell_data[i].refs_count = d1 & 0x07;
    uint16_t data_bytes = (d2 + 1) / 2;
    bool is_fullfilled_bytes = !(d2 & 1);

    // Read cell data
    memcpy(cell_data[i].bits.data, &boc[index], data_bytes);
    index += data_bytes;

    uint16_t data_cursor;
    set_top_upped_array(cell_data[i].bits.data, data_bytes, is_fullfilled_bytes,
                        &data_cursor);
    cell_data[i].bits.data_cursor = data_cursor;

    // Read reference indices
    for (int j = 0; j < cell_data[i].refs_count; j++) {
      uint32_t ref_index = 0;
      for (int k = 0; k < offset_bytes; k++) {
        ref_index = (ref_index << 8) | boc[index++];
      }
      cell_data[i].ref_indices[j] = ref_index;
    }
  }

  // Second pass: Calculate hash from the end
  for (int i = cells_num - 1; i >= 0; i--) {
    CellRef_t refs[cell_data[i].refs_count];
    for (int j = 0; j < cell_data[i].refs_count; j++) {
      refs[j] = cell_data[cell_data[i].ref_indices[j]].cell_ref;
    }
    if (!ton_hash_cell(&cell_data[i].bits, refs, cell_data[i].refs_count,
                       &cell_data[i].cell_ref)) {
      fsm_sendFailure(FailureType_Failure_ProcessError, "Hash cell failed");
      return false;
    }
  }

  // Assign the value of cell[0] to payload
  if (cells_num > 0) {
    CellRef_t temp_payload = cell_data[0].cell_ref;
    memcpy(payload, &temp_payload, sizeof(CellRef_t));
  } else {
    // If no cells found in BOC, return false to indicate failure
    fsm_sendFailure(FailureType_Failure_ProcessError, "No cells found in BOC");
    return false;
  }

  return true;
}