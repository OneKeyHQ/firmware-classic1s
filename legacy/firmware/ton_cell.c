#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fsm.h"
#include "sha2.h"
#include "ton_address.h"
#include "ton_cell.h"
#include "util.h"

static const uint8_t REACH_BOC_MAGIC_PREFIX[4] = {0xb5, 0xee, 0x9c, 0x72};

static bool ton_boc_read_uint(const uint8_t* boc, size_t boc_len, size_t* index,
                              uint8_t width, uint32_t* out) {
  if (width == 0 || width > 4 || *index + width > boc_len) {
    return false;
  }

  uint32_t value = 0;
  for (uint8_t i = 0; i < width; i++) {
    value = (value << 8) | boc[(*index)++];
  }

  *out = value;
  return true;
}

static bool ton_boc_read_uint64(const uint8_t* boc, size_t boc_len,
                                size_t* index, uint8_t width, uint64_t* out) {
  if (width == 0 || width > 8 || *index + width > boc_len) {
    return false;
  }

  uint64_t value = 0;
  for (uint8_t i = 0; i < width; i++) {
    value = (value << 8) | boc[(*index)++];
  }

  *out = value;
  return true;
}

static bool ton_boc_require_bytes(size_t index, size_t need, size_t boc_len) {
  return need <= boc_len && index <= boc_len - need;
}

static uint32_t ton_boc_read_le32(const uint8_t* data) {
  return ((uint32_t)data[0]) | ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint32_t ton_boc_crc32c(const uint8_t* data, size_t len) {
  uint32_t crc = 0xffffffff;

  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0x82F63B78;
      } else {
        crc >>= 1;
      }
    }
  }

  return crc ^ 0xffffffff;
}

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
                                     const uint8_t* jetton_value,
                                     uint8_t jetton_value_len,
                                     uint64_t forward_amount,
                                     const char* forward_payload,
                                     uint8_t resp_workchain, uint8_t* resp_hash,
                                     CellRef_t* payload) {
  BitString_t bits;

  bitstring_init(&bits);
  bitstring_write_uint(&bits, 0xf8a7ea5, 32);  // jetton transfer op-code
  bitstring_write_uint(&bits, 0, 64);          // query id
  bitstring_write_coins_bytes(&bits, jetton_value, jetton_value_len);

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
                       uint8_t* dest_hash, uint64_t value, CellRef_t* payload,
                       bool is_jetton, const char* payload_str,
                       BitString_t* payload_bits, CellRef_t* payload_ref,
                       CellRef_t* out_message_ref) {
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

    bitstring_write_uint(&bits, 0x00000000,
                         32);  // text comment transfer op-code
    bitstring_write_buffer(&bits, (uint8_t*)payload_str, strlen(payload_str));

    return ton_hash_cell(&bits, NULL, 0, out_message_ref);

  } else if (payload != NULL) {
    // check if raw data inline
    // if (false) {
    if (bits.data_cursor + payload_bits->data_cursor <= 1023 && !is_jetton) {
      bitstring_write_bit(&bits, 0);  // no state-init
      bitstring_write_bit(&bits, 0);  // body in line

      for (int i = 0; i < payload_bits->data_cursor; i++) {
        int src_byte = i / 8;
        int src_bit = 7 - (i % 8);
        int src_value = (payload_bits->data[src_byte] >> src_bit) & 1;
        bitstring_write_bit(&bits, src_value);
      }

      // append payload ref in message ref
      if (payload->max_depth > 0) {
        struct CellRef_t refs[1] = {*payload_ref};
        return ton_hash_cell(&bits, refs, 1, out_message_ref);

      } else {
        return ton_hash_cell(&bits, NULL, 0, out_message_ref);
      }

    } else {
      bitstring_write_bit(&bits, 0);  // no state-init
      bitstring_write_bit(&bits, 1);  // body in ref

      struct CellRef_t refs[1] = {*payload};
      return ton_hash_cell(&bits, refs, 1, out_message_ref);
    }
  } else {
    bitstring_write_bit(&bits, 0);  // no state-init
    bitstring_write_bit(&bits, 0);  // body inline

    return ton_hash_cell(&bits, NULL, 0, out_message_ref);
  }
}

bool ton_create_message_digest(
    uint32_t expire_at, uint32_t seqno, bool is_bounceable,
    uint8_t dest_workchain, uint8_t* dest_hash, uint64_t value, uint8_t mode,
    CellRef_t* payload, bool is_jetton, const char* payload_str,
    BitString_t* payload_bits, CellRef_t* payload_ref, const char** ext_dest,
    const uint64_t* ext_ton_amount, const char** ext_payload,
    uint8_t ext_dest_count, uint8_t* digest) {
  // Build Internal Message
  struct CellRef_t internalMessageRef;
  if (!build_message_ref(is_bounceable, dest_workchain, dest_hash, value,
                         payload, is_jetton, payload_str, payload_bits,
                         payload_ref, &internalMessageRef)) {
    return false;
  }

  // Build Ext Messages (if any)
  struct CellRef_t extMessageRefs[3];
  int ext_message_count = 0;

  for (int i = 0; i < ext_dest_count && i < 3; i++) {
    TON_PARSED_ADDRESS parsed_addr;

    if (!ton_decode_addr(ext_dest[i], &parsed_addr)) {
      return false;
    }

    CellRef_t ext_payload_ref;
    if (ext_payload && ext_payload[i] && strlen(ext_payload[i]) > 0) {
      if (strlen(ext_payload[i]) >= 8 &&
          memcmp(ext_payload[i], "b5ee9c72", 8) == 0) {
        unsigned int data_len = strlen(ext_payload[i]) / 2;
        uint8_t raw_data[data_len];
        hex2data(ext_payload[i], raw_data, &data_len);
        if (!ton_parse_boc(raw_data, data_len, &ext_payload_ref, NULL, NULL)) {
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

    if (!build_message_ref(
            parsed_addr.is_bounceable, (uint8_t)parsed_addr.workchain,
            parsed_addr.hash, ext_ton_amount[i],
            ext_payload[i] ? &ext_payload_ref : NULL, false, NULL, NULL, NULL,
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

static bool ton_boc_strip_top_upped_array(uint8_t* array, size_t array_len,
                                          bool has_full_bytes,
                                          uint16_t* cursor) {
  *cursor = array_len * 8;

  if (has_full_bytes || array_len == 0) {
    return true;
  }

  for (int i = 0; i < 7; i++) {
    (*cursor)--;
    size_t byte_index = *cursor / 8;

    if ((array[byte_index] & (1 << i)) != 0) {
      array[byte_index] &= ~(1 << i);
      return true;
    }
  }

  fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid top-upped array");
  return false;
}

bool ton_parse_boc(const uint8_t* input_boc, size_t input_boc_len,
                   CellRef_t* payload, BitString_t* payload_bits,
                   CellRef_t* payload_ref) {
  bool ok = false;
  CellData_t* cell_data = NULL;

  if (payload == NULL || input_boc_len < 6) {
    goto cleanup;
  }

  if (memcmp(input_boc, REACH_BOC_MAGIC_PREFIX, 4) != 0) {
    goto cleanup;
  }

  const uint8_t* boc = input_boc;
  size_t boc_len = input_boc_len;

  size_t index = 4;
  uint8_t flags_byte = boc[index++];
  bool has_idx = (flags_byte & 0x80) != 0;
  bool has_crc32 = (flags_byte & 0x40) != 0;
  bool has_cache_bits = (flags_byte & 0x20) != 0;
  uint8_t flags = (flags_byte >> 3) & 0x03;
  uint8_t size_bytes = flags_byte & 0x07;
  uint8_t offset_bytes = boc[index++];

  if (flags != 0 || size_bytes == 0 || size_bytes > 4 || offset_bytes == 0 ||
      offset_bytes > 8 || (has_cache_bits && !has_idx)) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Unsupported BOC format");
    goto cleanup;
  }

  if (has_crc32) {
    uint32_t expected_crc = ton_boc_read_le32(&boc[boc_len - 4]);
    uint32_t actual_crc = ton_boc_crc32c(boc, boc_len - 4);
    if (expected_crc != actual_crc) {
      fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid BOC CRC32C");
      goto cleanup;
    }
    boc_len -= 4;
  }

  uint32_t cells_num = 0;
  uint32_t roots_num = 0;
  uint32_t absent_num = 0;
  uint64_t tot_cells_size = 0;
  if (!ton_boc_read_uint(boc, boc_len, &index, size_bytes, &cells_num) ||
      !ton_boc_read_uint(boc, boc_len, &index, size_bytes, &roots_num) ||
      !ton_boc_read_uint(boc, boc_len, &index, size_bytes, &absent_num) ||
      !ton_boc_read_uint64(boc, boc_len, &index, offset_bytes,
                           &tot_cells_size)) {
    goto cleanup;
  }

  if (cells_num == 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid cells number");
    goto cleanup;
  }

  if (roots_num == 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid root cell");
    goto cleanup;
  }

  if (absent_num != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Unsupported absent cells");
    goto cleanup;
  }

  uint32_t root_cell_index = 0;
  for (uint32_t i = 0; i < roots_num; i++) {
    uint32_t current_root = 0;
    if (!ton_boc_read_uint(boc, boc_len, &index, size_bytes, &current_root) ||
        current_root >= cells_num) {
      fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid root cell");
      goto cleanup;
    }
    if (i == 0) {
      root_cell_index = current_root;
    }
  }

  if (has_idx) {
    size_t index_bytes = (size_t)cells_num * offset_bytes;
    if (!ton_boc_require_bytes(index, index_bytes, boc_len)) {
      goto cleanup;
    }
    index += index_bytes;
  }

  if (tot_cells_size > boc_len ||
      !ton_boc_require_bytes(index, (size_t)tot_cells_size, boc_len)) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid BOC size");
    goto cleanup;
  }

  size_t cells_end = index + (size_t)tot_cells_size;
  cell_data = calloc(cells_num, sizeof(CellData_t));
  if (cell_data == NULL) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Out of memory");
    goto cleanup;
  }

  for (uint32_t i = 0; i < cells_num; i++) {
    bitstring_init(&cell_data[i].bits);

    if (!ton_boc_require_bytes(index, 2, cells_end)) {
      goto cleanup;
    }

    uint8_t d1 = boc[index++];
    uint8_t d2 = boc[index++];
    uint8_t refs_count = d1 & 0x07;

    if (refs_count > 4) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Unsupported cell descriptor");
      goto cleanup;
    }

    uint16_t data_bytes = (d2 + 1) / 2;
    bool has_full_bytes = (d2 & 1) == 0;

    if (data_bytes > sizeof(cell_data[i].bits.data) ||
        !ton_boc_require_bytes(
            index, data_bytes + (size_t)refs_count * size_bytes, cells_end)) {
      fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid BOC cell");
      goto cleanup;
    }

    cell_data[i].refs_count = refs_count;
    memcpy(cell_data[i].bits.data, &boc[index], data_bytes);
    index += data_bytes;

    uint16_t data_cursor;
    if (!ton_boc_strip_top_upped_array(cell_data[i].bits.data, data_bytes,
                                       has_full_bytes, &data_cursor)) {
      goto cleanup;
    }
    cell_data[i].bits.data_cursor = data_cursor;

    for (uint8_t j = 0; j < refs_count; j++) {
      uint32_t ref_index = 0;
      if (!ton_boc_read_uint(boc, cells_end, &index, size_bytes, &ref_index) ||
          ref_index >= cells_num || ref_index <= i) {
        fsm_sendFailure(FailureType_Failure_ProcessError,
                        "Invalid BOC reference");
        goto cleanup;
      }
      cell_data[i].ref_indices[j] = ref_index;
    }
  }

  if (index != cells_end) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid BOC payload");
    goto cleanup;
  }

  for (int i = (int)cells_num - 1; i >= 0; i--) {
    CellRef_t refs[4];
    for (uint8_t j = 0; j < cell_data[i].refs_count; j++) {
      refs[j] = cell_data[cell_data[i].ref_indices[j]].cell_ref;
    }

    if (!ton_hash_cell(&cell_data[i].bits, refs, cell_data[i].refs_count,
                       &cell_data[i].cell_ref)) {
      fsm_sendFailure(FailureType_Failure_ProcessError, "Hash cell failed");
      goto cleanup;
    }
  }

  if (payload_bits != NULL) {
    uint16_t root_bytes = (cell_data[root_cell_index].bits.data_cursor + 7) / 8;
    memcpy(payload_bits->data, cell_data[root_cell_index].bits.data,
           root_bytes);
    payload_bits->data_cursor = cell_data[root_cell_index].bits.data_cursor;
  }

  if (payload_ref != NULL) {
    memset(payload_ref, 0, sizeof(CellRef_t));
    if (cell_data[root_cell_index].refs_count > 0) {
      *payload_ref =
          cell_data[cell_data[root_cell_index].ref_indices[0]].cell_ref;
    }
  }

  *payload = cell_data[root_cell_index].cell_ref;
  ok = true;

cleanup:
  if (cell_data != NULL) {
    free(cell_data);
  }
  return ok;
}
