#include "psbt.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "hasher.h"
#include "util.h"

static const uint8_t PSBT_MAGIC_BYTES[5] = {'p', 's', 'b', 't', 0xff};

static const uint8_t PSBT_SEPARATOR = 0x00;

// PSBT Global Types
const uint8_t PSBT_GLOBAL_UNSIGNED_TX = 0x00;
const uint8_t PSBT_GLOBAL_XPUB = 0x01;
const uint8_t PSBT_GLOBAL_TX_VERSION = 0x02;
const uint8_t PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03;
const uint8_t PSBT_GLOBAL_INPUT_COUNT = 0x04;
const uint8_t PSBT_GLOBAL_OUTPUT_COUNT = 0x05;
const uint8_t PSBT_GLOBAL_TX_MODIFIABLE = 0x06;
const uint8_t PSBT_GLOBAL_VERSION = 0xFB;

// PSBT Input Types
const uint8_t PSBT_IN_NON_WITNESS_UTXO = 0x00;
const uint8_t PSBT_IN_WITNESS_UTXO = 0x01;
const uint8_t PSBT_IN_PARTIAL_SIG = 0x02;
const uint8_t PSBT_IN_SIGHASH_TYPE = 0x03;
const uint8_t PSBT_IN_REDEEM_SCRIPT = 0x04;
const uint8_t PSBT_IN_WITNESS_SCRIPT = 0x05;
const uint8_t PSBT_IN_BIP32_DERIVATION = 0x06;
const uint8_t PSBT_IN_FINAL_SCRIPTSIG = 0x07;
const uint8_t PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
const uint8_t PSBT_IN_PREVIOUS_TXID = 0x0e;
const uint8_t PSBT_IN_OUTPUT_INDEX = 0x0f;
const uint8_t PSBT_IN_SEQUENCE = 0x10;
const uint8_t PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11;
const uint8_t PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12;
const uint8_t PSBT_IN_TAP_KEY_SIG = 0x13;
const uint8_t PSBT_IN_TAP_SCRIPT_SIG = 0x14;
const uint8_t PSBT_IN_TAP_LEAF_SCRIPT = 0x15;
const uint8_t PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
const uint8_t PSBT_IN_TAP_INTERNAL_KEY = 0x17;
const uint8_t PSBT_IN_TAP_MERKLE_ROOT = 0x18;

// PSBT Output Types
const uint8_t PSBT_OUT_REDEEM_SCRIPT = 0x00;
const uint8_t PSBT_OUT_WITNESS_SCRIPT = 0x01;
const uint8_t PSBT_OUT_BIP32_DERIVATION = 0x02;
const uint8_t PSBT_OUT_AMOUNT = 0x03;
const uint8_t PSBT_OUT_SCRIPT = 0x04;
const uint8_t PSBT_OUT_TAP_INTERNAL_KEY = 0x05;
const uint8_t PSBT_OUT_TAP_TREE = 0x06;
const uint8_t PSBT_OUT_TAP_BIP32_DERIVATION = 0x07;

uint64_t deser_compact_size(BufferReader* s) {
  uint8_t first;
  if (!read_bytes(s, &first, 1)) {
    return 0;
  }

  if (first < 253) {
    return first;
  }

  uint64_t value = 0;
  size_t bytes_to_read = 1 << (first - 252);

  if (!read_bytes(s, (uint8_t*)&value, bytes_to_read)) {
    return 0;
  }

  return value;
}

int ser_compact_size(uint64_t value, BufferWriter* writer) {
  uint8_t buffer[9] = {0};
  size_t size;

  if (value < 253) {
    buffer[0] = (uint8_t)value;
    size = 1;
  } else if (value < 0x10000) {
    buffer[0] = 253;
    buffer[1] = (uint8_t)(value & 0xff);
    buffer[2] = (uint8_t)((value >> 8) & 0xff);
    size = 3;
  } else if (value < 0x100000000) {
    buffer[0] = 254;
    buffer[1] = (uint8_t)(value & 0xff);
    buffer[2] = (uint8_t)((value >> 8) & 0xff);
    buffer[3] = (uint8_t)((value >> 16) & 0xff);
    buffer[4] = (uint8_t)((value >> 24) & 0xff);
    size = 5;
  } else {
    buffer[0] = 255;
    buffer[1] = (uint8_t)(value & 0xff);
    buffer[2] = (uint8_t)((value >> 8) & 0xff);
    buffer[3] = (uint8_t)((value >> 16) & 0xff);
    buffer[4] = (uint8_t)((value >> 24) & 0xff);
    buffer[5] = (uint8_t)((value >> 32) & 0xff);
    buffer[6] = (uint8_t)((value >> 40) & 0xff);
    buffer[7] = (uint8_t)((value >> 48) & 0xff);
    buffer[8] = (uint8_t)((value >> 56) & 0xff);
    size = 9;
  }

  return write_bytes(buffer, size, writer);
}

int deser_string(BufferReader* f, uint8_t* out_buffer, size_t buffer_size,
                 size_t* out_len) {
  uint64_t length = deser_compact_size(f);
  if (length == 0 || length > f->length - f->position || length > buffer_size) {
    *out_len = 0;
    return 0;
  }

  if (!read_bytes(f, out_buffer, length)) {
    *out_len = 0;
    return 0;
  }

  *out_len = length;
  return 1;
}

int ser_string(const uint8_t* src, size_t count, BufferWriter* writer) {
  if (!ser_compact_size(count, writer)) return 0;
  if (count == 0) return 1;
  if (!write_bytes(src, count, writer)) return 0;
  return 1;
}

int deser_string_to_buffer_reader(BufferReader* f, BufferReader* out_reader) {
  uint8_t buffer[1024];
  size_t length;
  if (!deser_string(f, buffer, sizeof(buffer), &length)) {
    return 0;
  }

  init_buffer_reader(out_reader, buffer, length);
  return 1;
}

bool deser_ctx_in(BufferReader* reader, CTxIn* input) {
  if (!read_bytes(reader, input->prevout.hash, sizeof(input->prevout.hash)))
    return false;
  if (!read_bytes(reader, (uint8_t*)&input->prevout.n,
                  sizeof(input->prevout.n)))
    return false;
  uint64_t scriptSig_len = deser_compact_size(reader);
  if (scriptSig_len > sizeof(input->scriptSig)) return false;
  input->scriptSig_len = scriptSig_len;
  if (!read_bytes(reader, input->scriptSig, scriptSig_len)) return false;
  if (!read_bytes(reader, (uint8_t*)&input->nSequence,
                  sizeof(input->nSequence)))
    return false;
  return true;
}
bool deser_ctx_out(BufferReader* reader, CTxOut* output) {
  if (!read_bytes(reader, (uint8_t*)&output->nValue, sizeof(output->nValue)))
    return false;
  uint64_t scriptPubKey_len = deser_compact_size(reader);
  if (scriptPubKey_len > sizeof(output->scriptPubKey)) return false;
  output->scriptPubKey_len = scriptPubKey_len;
  if (!read_bytes(reader, output->scriptPubKey, scriptPubKey_len)) return false;
  return true;
}
bool deser_transaction(BufferReader* reader, CTransaction* tx) {
  // Read version
  if (!read_bytes(reader, (uint8_t*)&tx->nVersion, 4)) {
    return false;
  }

  // Read input count
  uint8_t flag = 0;
  uint64_t vin_count = deser_compact_size(reader);
  if (vin_count == 0) {
    if (!read_bytes(reader, &flag, 1)) return false;
    if (flag == 0) return false;  // flag must be 1
    vin_count = deser_compact_size(reader);
  }
  if (vin_count == 0 || vin_count > MAX_INPUTS) {
    return false;
  }
  tx->vin_len = vin_count;
  // Read inputs
  for (size_t i = 0; i < vin_count; i++) {
    CTxIn* input = &tx->vin[i];
    if (!deser_ctx_in(reader, input)) return false;
  }

  // Read output count
  uint64_t vout_count = deser_compact_size(reader);
  if (vout_count > MAX_OUTPUTS) {
    return false;
  }
  tx->vout_len = vout_count;

  // Read outputs
  for (size_t i = 0; i < vout_count; i++) {
    CTxOut* output = &tx->vout[i];
    if (!deser_ctx_out(reader, output)) return false;
  }

  // Read nLockTime
  if (!read_bytes(reader, (uint8_t*)&tx->nLockTime, 4)) {
    return false;
  }

  return true;
}

bool deser_hd_keypath(BufferReader* key_origin_info_reader,
                      KeyOriginInfo* key_origin) {
  size_t key_origin_info_reader_len =
      key_origin_info_reader->length - key_origin_info_reader->position;
  if (key_origin_info_reader_len % 4 != 0) return false;
  if (!read_bytes(key_origin_info_reader, (uint8_t*)&key_origin->fingerprint,
                  4)) {
    return false;
  }
  key_origin->path_len = key_origin_info_reader_len / 4 - 1;
  for (size_t i = 0; i < key_origin->path_len; i++) {
    if (!read_bytes(key_origin_info_reader, (uint8_t*)&key_origin->path[i],
                    4)) {
      return false;
    }
  }
  return true;
}
bool deser_tap_bip32_derivation(BufferReader* reader,
                                TAP_BIP32_DERIVATION* tap_bip32_derivation) {
  BufferReader value_reader = {0};
  if (!deser_string_to_buffer_reader(reader, &value_reader)) return false;
  uint64_t num_hashes = deser_compact_size(&value_reader);
  if (num_hashes > (sizeof(tap_bip32_derivation->tap_leaf_hashs) /
                    sizeof(tap_bip32_derivation->tap_leaf_hashs[0])))
    return false;
  for (size_t i = 0; i < num_hashes; i++) {
    if (!read_bytes(&value_reader, tap_bip32_derivation->tap_leaf_hashs[i], 32))
      return false;
  }
  tap_bip32_derivation->tap_leaf_hashs_len = num_hashes;
  if (!deser_hd_keypath(&value_reader, &tap_bip32_derivation->key_origin))
    return false;
  return true;
}

bool ser_key_origin(const KeyOriginInfo* key_origin, BufferWriter* writer) {
  if (!write_bytes((uint8_t*)&key_origin->fingerprint, 4, writer)) return false;
  for (size_t i = 0; i < key_origin->path_len; i++) {
    if (!write_bytes((uint8_t*)&key_origin->path[i], 4, writer)) return false;
  }
  return true;
}
bool ser_tap_bip32_derivation(const TAP_BIP32_DERIVATION* tap_bip32_derivation,
                              BufferWriter* writer) {
  BufferWriter dummy_writer = {0};
  init_buffer_writer(&dummy_writer, NULL, 0);
  if (!ser_key_origin(&tap_bip32_derivation->key_origin, &dummy_writer))
    return false;
  uint64_t value_len =
      1 + tap_bip32_derivation->tap_leaf_hashs_len * 32 + dummy_writer.position;
  if (!ser_compact_size(value_len, writer)) return false;
  if (!ser_compact_size(tap_bip32_derivation->tap_leaf_hashs_len, writer))
    return false;
  for (size_t i = 0; i < tap_bip32_derivation->tap_leaf_hashs_len; i++) {
    if (!write_bytes(tap_bip32_derivation->tap_leaf_hashs[i], 32, writer))
      return false;
  }
  if (!ser_key_origin(&tap_bip32_derivation->key_origin, writer)) return false;
  return true;
}
bool deser_tap_script_sig(BufferReader* reader, BufferReader* key_reader,
                          TAP_SCRIPT_SIG* tap_script_sig) {
  if (!read_bytes(key_reader, tap_script_sig->x_only_pubkey, 32)) return false;
  if (!read_bytes(key_reader, tap_script_sig->leaf_hash, 32)) return false;
  uint64_t signature_len = deser_compact_size(reader);
  if (signature_len != 64 && signature_len != 65) return false;
  if (!read_bytes(reader, tap_script_sig->signature, signature_len))
    return false;
  tap_script_sig->signature_len = signature_len;
  return true;
}
bool deser_tap_leaf_script(BufferReader* reader, BufferReader* key_reader,
                           TAP_LEAF_SCRIPT* tap_leaf_script) {
  uint64_t control_block_len = key_reader->length - 1;
  if (control_block_len > sizeof(tap_leaf_script->control_block)) return false;
  if (!read_bytes(key_reader, tap_leaf_script->control_block,
                  control_block_len))
    return false;
  tap_leaf_script->control_block_len = control_block_len;
  uint64_t script_len = deser_compact_size(reader);
  if (script_len > sizeof(tap_leaf_script->script)) return false;
  if (!read_bytes(reader, tap_leaf_script->script, script_len - 1))
    return false;
  tap_leaf_script->script_len = script_len - 1;
  if (!read_bytes(reader, (uint8_t*)&tap_leaf_script->leaf_version, 1))
    return false;
  return true;
}
bool deser_partial_sig(BufferReader* reader, BufferReader* key_reader,
                       Partial_Sig* partial_sig) {
  if (key_reader->length != 34 && key_reader->length != 66) return false;
  uint8_t key_len = key_reader->length - 1;
  if (!read_bytes(key_reader, partial_sig->pubkey, key_len)) return false;
  partial_sig->pubkey_len = key_len;
  if (!deser_string(reader, partial_sig->sig, sizeof(partial_sig->sig),
                    &partial_sig->sig_len))
    return false;
  return true;
}
bool ser_partial_sig(BufferWriter* writer, const Partial_Sig* partial_sig) {
  uint8_t key[66] = {0};
  uint8_t key_len = partial_sig->pubkey_len + 1;
  key[0] = PSBT_IN_PARTIAL_SIG;
  memcpy(key + 1, partial_sig->pubkey, partial_sig->pubkey_len);
  if (!ser_string(key, key_len, writer)) return false;
  if (!ser_string(partial_sig->sig, partial_sig->sig_len, writer)) return false;
  return true;
}
bool deser_psbt_input(BufferReader* reader, PartiallySignedInput* input) {
  while (1) {
    uint8_t key[193] = {0};
    size_t key_len = 0;
    if (!deser_string(reader, key, sizeof(key), &key_len)) break;
    if (key_len == 0) break;  // Separator (key_len of 0)
    uint8_t key_type;
    BufferReader key_reader = {0};
    init_buffer_reader(&key_reader, key, key_len);
    if (!read_bytes(&key_reader, &key_type, 1)) return false;
    switch (key_type) {
      case PSBT_IN_NON_WITNESS_UTXO:
        if (input->non_witness_utxo_lookuped || key_len > 1) return false;
        BufferReader tx_reader = {0};
        if (!deser_string_to_buffer_reader(reader, &tx_reader)) return false;
        if (!deser_transaction(&tx_reader, &input->non_witness_utxo))
          return false;
        input->non_witness_utxo_lookuped = true;
        break;
      case PSBT_IN_WITNESS_UTXO:
        if (input->witness_utxo_lookuped || key_len > 1) return false;
        BufferReader out_reader = {0};
        if (!deser_string_to_buffer_reader(reader, &out_reader)) return false;
        if (!deser_ctx_out(&out_reader, &input->witness_utxo)) return false;
        input->witness_utxo_lookuped = true;
        break;
      case PSBT_IN_PARTIAL_SIG:
        // TODO: check the duplicate partial_sig
        if (input->partial_sigs_len >= MAX_INPUTS - 1) return false;
        if (!deser_partial_sig(reader, &key_reader,
                               &input->partial_sigs[input->partial_sigs_len]))
          return false;
        input->partial_sigs_len++;
        break;
      case PSBT_IN_SIGHASH_TYPE:
        if (input->sighash_type_lookuped || key_len > 1) return false;
        uint64_t sighash_type_len = deser_compact_size(reader);
        if (sighash_type_len != 4) return false;
        if (!read_bytes(reader, (uint8_t*)&input->sighash_type, 4))
          return false;
        input->sighash_type_lookuped = true;
        break;
      case PSBT_IN_REDEEM_SCRIPT:
        // ignore
        return false;
        if (input->redeem_script_lookuped || key_len > 1) return false;
        if (!deser_string(reader, input->redeem_script,
                          sizeof(input->redeem_script),
                          &input->redeem_script_len))
          return false;
        input->redeem_script_lookuped = true;
        break;
      case PSBT_IN_WITNESS_SCRIPT:
        // ignore
        return false;
        if (input->witness_script_lookuped || key_len > 1) return false;
        if (!deser_string(reader, input->witness_script,
                          sizeof(input->witness_script),
                          &input->witness_script_len))
          return false;
        input->witness_script_lookuped = true;
        break;
      case PSBT_IN_BIP32_DERIVATION:
        if (input->bip32_path_lookuped || (key_len != 34 && key_len != 66))
          return false;
        if (!read_bytes(&key_reader, (uint8_t*)input->bip32_path.pubkey,
                        key_len - 1))
          return false;
        input->bip32_path.pubkey_len = key_len - 1;
        if (!deser_hd_keypath(reader, &input->bip32_path.key_origin))
          return false;
        input->bip32_path_lookuped = true;
        break;
      case PSBT_IN_FINAL_SCRIPTSIG:
        // ignore
        return false;
        if (input->final_script_sig_lookuped || key_len > 1) return false;
        if (!deser_string(reader, input->final_script_sig,
                          sizeof(input->final_script_sig),
                          &input->final_script_sig_len))
          return false;
        input->final_script_sig_lookuped = true;
        break;
      case PSBT_IN_FINAL_SCRIPTWITNESS:
        // ignore
        return false;
        if (input->final_script_witness_lookuped || key_len > 1) return false;
        if (!deser_string(reader, input->final_script_witness,
                          sizeof(input->final_script_witness),
                          &input->final_script_witness_len))
          return false;
        input->final_script_witness_lookuped = true;
        break;
      case PSBT_IN_PREVIOUS_TXID:
        if (input->prev_txid_lookuped || key_len > 1) return false;
        uint64_t prev_txid_len = deser_compact_size(reader);
        if (prev_txid_len != 32) return false;
        if (!read_bytes(reader, input->prev_txid, sizeof(input->prev_txid)))
          return false;
        input->prev_txid_lookuped = true;
        break;
      case PSBT_IN_OUTPUT_INDEX:
        if (input->prev_out_index_lookuped || key_len > 1) return false;
        uint64_t prev_out_index_len = deser_compact_size(reader);
        if (prev_out_index_len != 4) return false;
        if (!read_bytes(reader, (uint8_t*)&input->prev_out_index, 4))
          return false;
        input->prev_out_index_lookuped = true;
        break;
      case PSBT_IN_SEQUENCE:
        if (input->sequence_lookuped || key_len > 1) return false;
        uint64_t sequence_len = deser_compact_size(reader);
        if (sequence_len != 4) return false;
        if (!read_bytes(reader, (uint8_t*)&input->sequence, 4)) return false;
        input->sequence_lookuped = true;
        break;
      case PSBT_IN_REQUIRED_TIME_LOCKTIME:
        if (input->time_locktime_lookuped || key_len > 1) return false;
        uint64_t time_locktime_len = deser_compact_size(reader);
        if (time_locktime_len != 4) return false;
        if (!read_bytes(reader, (uint8_t*)&input->time_locktime, 4))
          return false;
        input->time_locktime_lookuped = true;
        break;
      case PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
        if (input->height_locktime_lookuped || key_len > 1) return false;
        uint64_t height_locktime_len = deser_compact_size(reader);
        if (height_locktime_len != 4) return false;
        if (!read_bytes(reader, (uint8_t*)&input->height_locktime, 4))
          return false;
        input->height_locktime_lookuped = true;
        break;
      case PSBT_IN_TAP_KEY_SIG:
        if (input->tap_key_sig_lookuped || key_len > 1) return false;
        uint64_t tap_key_sig_len = deser_compact_size(reader);
        if (tap_key_sig_len != 64 && tap_key_sig_len != 65) return false;
        if (!read_bytes(reader, input->tap_key_sig, tap_key_sig_len))
          return false;
        input->tap_key_sig_len = tap_key_sig_len;
        input->tap_key_sig_lookuped = true;
        break;
      case PSBT_IN_TAP_SCRIPT_SIG:
        if (input->tap_script_sig_lookuped || key_len != 65) return false;
        if (!deser_tap_script_sig(reader, &key_reader, &input->tap_script_sig))
          return false;
        input->tap_script_sig_lookuped = true;
        break;
      case PSBT_IN_TAP_LEAF_SCRIPT:
        if (input->tap_leaf_script_lookuped || key_len < 34 ||
            (key_len - 2) % 32 != 0)
          return false;
        if (!deser_tap_leaf_script(reader, &key_reader,
                                   &input->tap_leaf_script))
          return false;
        input->tap_leaf_script_lookuped = true;
        break;
      case PSBT_IN_TAP_BIP32_DERIVATION:
        if (input->tap_bip32_path_lookuped || key_len != 33) return false;
        if (!read_bytes(&key_reader, input->tap_bip32_path.x_only_pubkey, 32))
          return false;
        if (!deser_tap_bip32_derivation(reader, &input->tap_bip32_path))
          return false;
        input->tap_bip32_path_lookuped = true;
        break;
      case PSBT_IN_TAP_INTERNAL_KEY:
        if (input->tap_internal_key_lookuped || key_len > 1) return false;
        uint64_t tap_internal_key_len = deser_compact_size(reader);
        if (tap_internal_key_len != 32) return false;
        if (!read_bytes(reader, input->tap_internal_key, 32)) return false;
        input->tap_internal_key_lookuped = true;
        break;
      case PSBT_IN_TAP_MERKLE_ROOT:
        if (input->tap_merkle_root_lookuped || key_len > 1) return false;
        uint64_t tap_merkle_root_len = deser_compact_size(reader);
        if (tap_merkle_root_len != 32) return false;
        if (!read_bytes(reader, input->tap_merkle_root, 32)) return false;
        input->tap_merkle_root_lookuped = true;
        break;
      default:
        // TODO: handle unknown key type
        return false;
    }
  }
  return true;
}
bool deser_psbt_output(BufferReader* reader, PartiallySignedOutput* output) {
  while (1) {
    uint8_t key[66] = {0};
    size_t key_len = 0;
    if (!deser_string(reader, key, sizeof(key), &key_len)) break;
    if (key_len == 0) break;  // Separator (key_len of 0)
    uint8_t key_type;
    BufferReader key_reader = {0};
    init_buffer_reader(&key_reader, key, key_len);
    if (!read_bytes(&key_reader, &key_type, 1)) return false;
    switch (key_type) {
      case PSBT_OUT_REDEEM_SCRIPT:
        // ignore
        return false;
        if (output->redeem_script_lookuped || key_len > 1) return false;
        if (!deser_string(reader, output->redeem_script,
                          sizeof(output->redeem_script),
                          &output->redeem_script_len))
          return false;
        output->redeem_script_lookuped = true;
        break;
      case PSBT_OUT_WITNESS_SCRIPT:
        // ignore
        return false;
        if (output->witness_script_lookuped || key_len > 1) return false;
        if (!deser_string(reader, output->witness_script,
                          sizeof(output->witness_script),
                          &output->witness_script_len))
          return false;
        output->witness_script_lookuped = true;
        break;
      case PSBT_OUT_BIP32_DERIVATION:
        if (output->bip32_path_lookuped || (key_len != 34 && key_len != 66))
          return false;
        if (!read_bytes(&key_reader, (uint8_t*)output->bip32_path.pubkey,
                        key_len - 1))
          return false;
        output->bip32_path.pubkey_len = key_len - 1;
        if (!deser_hd_keypath(reader, &output->bip32_path.key_origin))
          return false;
        output->bip32_path_lookuped = true;
        break;
      case PSBT_OUT_AMOUNT:
        if (output->amount_lookuped || key_len > 1) return false;
        uint64_t amount_len = deser_compact_size(reader);
        if (amount_len != 8) return false;
        if (!read_bytes(reader, (uint8_t*)&output->amount, 8)) return false;
        output->amount_lookuped = true;
        break;
      case PSBT_OUT_SCRIPT:
        if (output->script_lookuped || key_len > 1) return false;
        if (!deser_string(reader, output->script, sizeof(output->script),
                          &output->script_len))
          return false;
        output->script_lookuped = true;
        break;
      case PSBT_OUT_TAP_INTERNAL_KEY:
        if (output->tap_internal_key_lookuped || key_len > 1) return false;
        uint64_t tap_internal_key_len = deser_compact_size(reader);
        if (tap_internal_key_len != 32) return false;
        if (!read_bytes(reader, output->tap_internal_key, 32)) return false;
        output->tap_internal_key_lookuped = true;
        break;
      case PSBT_OUT_TAP_TREE:
        // ignore
        return false;
        if (output->tap_tree_lookuped || key_len > 1) return false;
        if (!deser_string(reader, output->tap_tree, sizeof(output->tap_tree),
                          &output->tap_tree_len))
          return false;
        output->tap_tree_lookuped = true;
        break;
      case PSBT_OUT_TAP_BIP32_DERIVATION:
        if (output->tap_bip32_path_lookuped || key_len != 33) return false;
        if (!read_bytes(&key_reader, output->tap_bip32_path.x_only_pubkey, 32))
          return false;
        if (!deser_tap_bip32_derivation(reader, &output->tap_bip32_path))
          return false;
        output->tap_bip32_path_lookuped = true;
        break;
      default:
        // TODO: handle unknown key type
        return false;
    }
  }
  return true;
}
bool ser_ctx_in(BufferWriter* writer, const CTxIn* input) {
  if (!write_bytes(input->prevout.hash, 32, writer)) return false;
  if (!write_bytes((uint8_t*)&input->prevout.n, 4, writer)) return false;
  if (!ser_compact_size(input->scriptSig_len, writer)) return false;
  if (!write_bytes(input->scriptSig, input->scriptSig_len, writer))
    return false;
  if (!write_bytes((uint8_t*)&input->nSequence, 4, writer)) return false;
  return true;
}

bool ser_ctx_out(BufferWriter* writer, const CTxOut* output) {
  if (!write_bytes((uint8_t*)&output->nValue, 8, writer)) return false;
  if (!ser_compact_size(output->scriptPubKey_len, writer)) return false;
  if (!write_bytes(output->scriptPubKey, output->scriptPubKey_len, writer))
    return false;
  return true;
}

bool ser_transaction(BufferWriter* writer, const CTransaction* tx) {
  // without witness
  if (!write_bytes((uint8_t*)&tx->nVersion, 4, writer)) return false;
  if (!ser_compact_size(tx->vin_len, writer)) return false;

  for (size_t i = 0; i < tx->vin_len; i++) {
    const CTxIn* input = &tx->vin[i];
    if (!ser_ctx_in(writer, input)) return false;
  }
  if (!ser_compact_size(tx->vout_len, writer)) return false;

  for (size_t i = 0; i < tx->vout_len; i++) {
    const CTxOut* output = &tx->vout[i];
    if (!ser_ctx_out(writer, output)) return false;
  }
  if (!write_bytes((uint8_t*)&tx->nLockTime, 4, writer)) return false;

  return true;
}

bool ser_psbt_input(BufferWriter* writer, const PartiallySignedInput* input) {
  if (input->non_witness_utxo_lookuped) {
    if (!ser_string((uint8_t*)&PSBT_IN_NON_WITNESS_UTXO, 1, writer))
      return false;
    BufferWriter dummy_writer = {0};
    init_buffer_writer(&dummy_writer, NULL, 0);
    if (!ser_transaction(&dummy_writer, &input->non_witness_utxo)) return false;
    if (!ser_compact_size(dummy_writer.position, writer)) return false;
    if (!ser_transaction(writer, &input->non_witness_utxo)) return false;
  }
  if (input->witness_utxo_lookuped) {
    if (!ser_string((uint8_t*)&PSBT_IN_WITNESS_UTXO, 1, writer)) return false;
    BufferWriter dummy_writer = {0};
    init_buffer_writer(&dummy_writer, NULL, 0);
    if (!ser_ctx_out(&dummy_writer, &input->witness_utxo)) return false;
    if (!ser_compact_size(dummy_writer.position, writer)) return false;
    if (!ser_ctx_out(writer, &input->witness_utxo)) return false;
  }
  if (input->final_script_sig_len == 0 &&
      input->final_script_witness_len == 0) {
    for (size_t i = 0; i < input->partial_sigs_len; i++) {
      if (!ser_partial_sig(writer, &input->partial_sigs[i])) return false;
    }
    if (input->sighash_type_lookuped) {
      if (!ser_string((uint8_t*)&PSBT_IN_SIGHASH_TYPE, 1, writer)) return false;
      if (!ser_string((uint8_t*)&input->sighash_type, 4, writer)) return false;
    }
    if (input->redeem_script_len > 0) {
      if (!ser_string((uint8_t*)&PSBT_IN_REDEEM_SCRIPT, 1, writer))
        return false;
      if (!ser_string(input->redeem_script, input->redeem_script_len, writer))
        return false;
    }
    if (input->witness_script_len > 0) {
      if (!ser_string((uint8_t*)&PSBT_IN_WITNESS_SCRIPT, 1, writer))
        return false;
      if (!ser_string(input->witness_script, input->witness_script_len, writer))
        return false;
    }
    if (input->bip32_path_lookuped && input->bip32_path.pubkey_len > 0) {
      uint8_t key[66] = {0};
      uint8_t key_len = input->bip32_path.pubkey_len + 1;
      key[0] = PSBT_IN_BIP32_DERIVATION;
      memcpy(key + 1, input->bip32_path.pubkey, input->bip32_path.pubkey_len);
      if (!ser_string(key, key_len, writer)) return false;
      BufferWriter dummy_writer = {0};
      init_buffer_writer(&dummy_writer, NULL, 0);
      if (!ser_key_origin(&input->bip32_path.key_origin, &dummy_writer))
        return false;
      if (dummy_writer.position % 4 != 0) return false;
      if (!ser_compact_size(dummy_writer.position, writer)) return false;
      if (!ser_key_origin(&input->bip32_path.key_origin, writer)) return false;
    }
    if (input->tap_key_sig_len != 0) {
      if (!ser_string((uint8_t*)&PSBT_IN_TAP_KEY_SIG, 1, writer)) return false;
      if (!ser_string(input->tap_key_sig, input->tap_key_sig_len, writer))
        return false;
    }
    if (input->tap_script_sig.signature_len > 0) {
      uint8_t key[65] = {0};
      key[0] = PSBT_IN_TAP_SCRIPT_SIG;
      memcpy(key + 1, input->tap_script_sig.x_only_pubkey, 32);
      memcpy(key + 33, input->tap_script_sig.leaf_hash, 32);
      if (!ser_string(key, sizeof(key), writer)) return false;
      if (!ser_string(input->tap_script_sig.signature,
                      input->tap_script_sig.signature_len, writer))
        return false;
    }
    if (input->tap_leaf_script_lookuped &&
        input->tap_leaf_script.script_len > 0) {
      uint8_t key[194] = {0};
      size_t key_len = 1 + input->tap_leaf_script.control_block_len;
      key[0] = PSBT_IN_TAP_LEAF_SCRIPT;
      memcpy(key + 1, input->tap_leaf_script.control_block,
             input->tap_leaf_script.control_block_len);
      if (!ser_string(key, key_len, writer)) return false;
      if (!ser_compact_size(input->tap_leaf_script.script_len + 1, writer))
        return false;
      if (!write_bytes(input->tap_leaf_script.script,
                       input->tap_leaf_script.script_len, writer))
        return false;
      if (!write_bytes(&input->tap_leaf_script.leaf_version, 1, writer))
        return false;
    }
    if (input->tap_bip32_path_lookuped &&
        input->tap_bip32_path.key_origin.path_len > 0) {
      uint8_t key[33] = {0};
      key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
      memcpy(key + 1, input->tap_bip32_path.x_only_pubkey, 32);
      if (!ser_string(key, sizeof(key), writer)) return false;
      if (!ser_tap_bip32_derivation(&input->tap_bip32_path, writer))
        return false;
    }
    if (input->tap_internal_key_lookuped) {
      if (!ser_string((uint8_t*)&PSBT_IN_TAP_INTERNAL_KEY, 1, writer))
        return false;
      if (!ser_string(input->tap_internal_key, 32, writer)) return false;
    }
    if (input->tap_merkle_root_lookuped) {
      if (!ser_string((uint8_t*)&PSBT_IN_TAP_MERKLE_ROOT, 1, writer))
        return false;
      if (!ser_string(input->tap_merkle_root, 32, writer)) return false;
    }
  }
  if (input->final_script_sig_len > 0) {
    if (!ser_string((uint8_t*)&PSBT_IN_FINAL_SCRIPTSIG, 1, writer))
      return false;
    if (!ser_string(input->final_script_sig, input->final_script_sig_len,
                    writer))
      return false;
  }
  if (input->final_script_witness_len > 0) {
    if (!ser_string((uint8_t*)&PSBT_IN_FINAL_SCRIPTWITNESS, 1, writer))
      return false;
    if (!ser_string(input->final_script_witness,
                    input->final_script_witness_len, writer))
      return false;
  }
  if (input->version >= 2) {
    if (!ser_string((uint8_t*)&PSBT_IN_PREVIOUS_TXID, 1, writer)) return false;
    if (!ser_string(input->prev_txid, 32, writer)) return false;

    if (!ser_string((uint8_t*)&PSBT_IN_OUTPUT_INDEX, 1, writer)) return false;
    if (!ser_string((uint8_t*)&input->prev_out_index, 4, writer)) return false;

    if (!ser_string((uint8_t*)&PSBT_IN_SEQUENCE, 1, writer)) return false;
    if (!ser_string((uint8_t*)&input->sequence, 4, writer)) return false;

    if (!ser_string((uint8_t*)&PSBT_IN_REQUIRED_TIME_LOCKTIME, 1, writer))
      return false;
    if (!ser_string((uint8_t*)&input->time_locktime, 4, writer)) return false;

    if (!ser_string((uint8_t*)&PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, 1, writer))
      return false;
    if (!ser_string((uint8_t*)&input->height_locktime, 4, writer)) return false;
  }
  // separator
  if (!write_bytes((uint8_t*)&PSBT_SEPARATOR, 1, writer)) return false;
  return true;
}
bool ser_psbt_output(BufferWriter* writer,
                     const PartiallySignedOutput* output) {
  if (output->redeem_script_lookuped && output->redeem_script_len > 0) {
    if (!ser_string((uint8_t*)&PSBT_OUT_REDEEM_SCRIPT, 1, writer)) return false;
    if (!ser_string(output->redeem_script, output->redeem_script_len, writer))
      return false;
  }
  if (output->witness_script_lookuped && output->witness_script_len > 0) {
    if (!ser_string((uint8_t*)&PSBT_OUT_WITNESS_SCRIPT, 1, writer))
      return false;
    if (!ser_string(output->witness_script, output->witness_script_len, writer))
      return false;
  }
  if (output->bip32_path_lookuped && output->bip32_path.pubkey_len > 0) {
    uint8_t key[66] = {0};
    uint8_t key_len = output->bip32_path.pubkey_len + 1;
    key[0] = PSBT_OUT_BIP32_DERIVATION;
    memcpy(key + 1, output->bip32_path.pubkey, output->bip32_path.pubkey_len);
    if (!ser_string(key, key_len, writer)) return false;
    BufferWriter dummy_writer = {0};
    init_buffer_writer(&dummy_writer, NULL, 0);
    if (!ser_key_origin(&output->bip32_path.key_origin, &dummy_writer))
      return false;
    if (dummy_writer.position % 4 != 0) return false;
    if (!ser_compact_size(dummy_writer.position, writer)) return false;
    if (!ser_key_origin(&output->bip32_path.key_origin, writer)) return false;
  }
  if (output->version >= 2) {
    if (!ser_string((uint8_t*)&PSBT_OUT_AMOUNT, 1, writer)) return false;
    if (!ser_string((uint8_t*)&output->amount, 8, writer)) return false;
    if (!ser_string((uint8_t*)&PSBT_OUT_SCRIPT, 1, writer)) return false;
    if (!ser_string(output->script, output->script_len, writer)) return false;
  }
  if (output->tap_internal_key_lookuped) {
    if (!ser_string((uint8_t*)&PSBT_OUT_TAP_INTERNAL_KEY, 1, writer))
      return false;
    if (!ser_string(output->tap_internal_key, 32, writer)) return false;
  }
  if (output->tap_tree_lookuped && output->tap_tree_len > 0) {
    if (!ser_string((uint8_t*)&PSBT_OUT_TAP_TREE, 1, writer)) return false;
    if (!ser_string(output->tap_tree, output->tap_tree_len, writer))
      return false;
  }
  if (output->tap_bip32_path_lookuped &&
      output->tap_bip32_path.key_origin.path_len > 0) {
    uint8_t key[33] = {0};
    key[0] = PSBT_OUT_TAP_BIP32_DERIVATION;
    memcpy(key + 1, output->tap_bip32_path.x_only_pubkey, 32);
    if (!ser_string(key, sizeof(key), writer)) return false;
    if (!ser_tap_bip32_derivation(&output->tap_bip32_path, writer))
      return false;
  }
  // separator
  if (!write_bytes((uint8_t*)&PSBT_SEPARATOR, 1, writer)) return false;
  return true;
}
// PSBT parsing function
bool psbt_deserialize(const uint8_t* psbt_bytes, size_t psbt_len, PSBT* psbt) {
  BufferReader reader = {0};
  init_buffer_reader(&reader, psbt_bytes, psbt_len);

  // Check magic bytes
  uint8_t magic[5] = {0};
  if (!read_bytes(&reader, magic, sizeof(magic))) {
    return false;
  }
  if (memcmp(magic, PSBT_MAGIC_BYTES, sizeof(PSBT_MAGIC_BYTES)) != 0) {
    return false;
  }

  // Parse global map
  while (1) {
    // Read key
    uint8_t key[80] = {0};
    size_t key_len = 0;
    if (!deser_string(&reader, key, sizeof(key), &key_len)) break;
    if (key_len == 0) break;  // Separator (key_len of 0)

    // Read key type
    uint8_t key_type;
    BufferReader key_reader = {0};
    init_buffer_reader(&key_reader, key, key_len);
    if (!read_bytes(&key_reader, &key_type, 1)) return false;

    // Process key-value pair
    switch (key_type) {
      case PSBT_GLOBAL_UNSIGNED_TX:
        if (psbt->tx_lookuped || key_len > 1) return false;
        BufferReader tx_reader = {0};
        if (!deser_string_to_buffer_reader(&reader, &tx_reader)) return false;
        if (!deser_transaction(&tx_reader, &psbt->tx)) return false;
        psbt->tx_lookuped = true;
        break;
      case PSBT_GLOBAL_XPUB:
        // not support
        return false;
        if (key_reader.length != 79) return false;
        if (psbt->xpubs_len >= (sizeof(psbt->xpubs) / sizeof(psbt->xpubs[0])))
          return false;
        if (!read_bytes(&key_reader, psbt->xpubs[psbt->xpubs_len].pubkey, 78)) {
          return false;
        }
        psbt->xpubs[psbt->xpubs_len].pubkey_len = 78;
        BufferReader key_origin_reader = {0};
        if (!deser_string_to_buffer_reader(&reader, &key_origin_reader))
          return false;
        if (!deser_hd_keypath(&key_origin_reader,
                              &psbt->xpubs[psbt->xpubs_len].key_origin))
          return false;
        psbt->xpubs_len++;
        break;
      case PSBT_GLOBAL_TX_VERSION:
        psbt->tx_version_lookuped = true;
        if (psbt->tx_version_lookuped || key_len > 1) return false;
        uint16_t tx_version_len = deser_compact_size(&reader);
        if (tx_version_len != 4) return false;
        if (!read_bytes(&reader, (uint8_t*)&psbt->tx_version, 4)) return false;
        break;
      case PSBT_GLOBAL_FALLBACK_LOCKTIME:
        psbt->fallback_locktime_lookuped = true;
        if (psbt->fallback_locktime_lookuped || key_len > 1) return false;
        uint16_t fallback_locktime_len = deser_compact_size(&reader);
        if (fallback_locktime_len != 4) return false;
        if (!read_bytes(&reader, (uint8_t*)&psbt->fallback_locktime, 4))
          return false;
        break;
      case PSBT_GLOBAL_INPUT_COUNT:
        psbt->inputs_len_lookuped = true;
        if (psbt->inputs_len_lookuped || key_len > 1) return false;
        deser_compact_size(&reader);
        uint16_t inputs_len = deser_compact_size(&reader);
        if (inputs_len > MAX_INPUTS) return false;
        psbt->inputs_len = inputs_len;
        break;
      case PSBT_GLOBAL_OUTPUT_COUNT:
        psbt->outputs_len_lookuped = true;
        if (psbt->outputs_len_lookuped || key_len > 1) return false;
        deser_compact_size(&reader);
        uint16_t outputs_len = deser_compact_size(&reader);
        if (outputs_len > MAX_OUTPUTS) return false;
        psbt->outputs_len = outputs_len;
        break;
      case PSBT_GLOBAL_TX_MODIFIABLE:
        psbt->tx_modifiable_lookuped = true;
        if (psbt->tx_modifiable_lookuped || key_len > 1) return false;
        uint8_t tx_modifiable_len = deser_compact_size(&reader);
        if (tx_modifiable_len != 1) return false;
        if (!read_bytes(&reader, (uint8_t*)&psbt->tx_modifiable, 1))
          return false;
        break;
      case PSBT_GLOBAL_VERSION:
        psbt->global_version_lookuped = true;
        if (psbt->global_version_lookuped || key_len > 1) return false;
        uint16_t version_len = deser_compact_size(&reader);
        if (version_len != 4) return false;
        if (!read_bytes(&reader, (uint8_t*)&psbt->global_version, 4))
          return false;
        psbt->explicit_version = true;
        break;
      default:
        // TODO: handle unknown key type
        return false;
    }
  }
  if (psbt->global_version == 0) {
    if (psbt->tx.vin_len == 0 && psbt->tx.vout_len == 0) return false;
    if (psbt->tx_version != 0) return false;
    if (psbt->fallback_locktime != 0) return false;
    if (psbt->inputs_len != 0) return false;
    if (psbt->outputs_len != 0) return false;
    if (psbt->tx_modifiable != 0) return false;
  } else if (psbt->global_version == 1) {
    return false;
  } else if (psbt->global_version >= 2) {
    if (psbt->tx_version == 0) return false;
    if (psbt->inputs_len == 0) return false;
    if (psbt->outputs_len == 0) return false;
    if (psbt->tx.vin_len != 0 && psbt->tx.vout_len != 0) return false;
  }
  // Parse inputs
  if (psbt->inputs_len == 0) {
    psbt->inputs_len = psbt->tx.vin_len;
  }
  for (size_t i = 0; i < psbt->inputs_len; i++) {
    if (reader.position >= reader.length) break;
    PartiallySignedInput* input = &psbt->inputs[i];
    if (!deser_psbt_input(&reader, input)) return false;
    if (psbt->global_version >= 2) {
      if (!input->prev_txid_lookuped) return false;
      if (!input->prev_out_index_lookuped) return false;
    }
    input->version = psbt->global_version;
    uint8_t prev_txid[32] = {0};
    if (psbt->global_version >= 2) {
      memcpy(prev_txid, input->prev_txid, 32);
    } else {
      memcpy(prev_txid, psbt->tx.vin[i].prevout.hash, 32);
    }
    if (input->non_witness_utxo_lookuped) {
      BufferWriter tx_writer = {0};
      uint8_t tx_buffer[1024] = {0};
      uint8_t calc_prev_txid[32] = {0};
      init_buffer_writer(&tx_writer, tx_buffer, sizeof(tx_buffer));
      if (!ser_transaction(&tx_writer, &input->non_witness_utxo)) return false;
      hasher_Raw(HASHER_SHA2D, tx_buffer, tx_writer.position, calc_prev_txid);
      if (memcmp(calc_prev_txid, prev_txid, 32) != 0) return false;
    }
  }
  // Parse outputs
  if (psbt->outputs_len == 0) {
    psbt->outputs_len = psbt->tx.vout_len;
  }
  for (size_t i = 0; i < psbt->outputs_len; i++) {
    if (reader.position >= reader.length) break;
    PartiallySignedOutput* output = &psbt->outputs[i];
    if (!deser_psbt_output(&reader, output)) return false;
    if (psbt->global_version >= 2) {
      if (!output->amount_lookuped) return false;
      if (!output->script_lookuped) return false;
    }
    output->version = psbt->global_version;
  }

  if (psbt->tx_lookuped) {
    psbt->tx_version = psbt->tx.nVersion;
    psbt->fallback_locktime = psbt->tx.nLockTime;
    for (size_t i = 0; i < psbt->tx.vin_len; i++) {
      memcpy(psbt->inputs[i].prev_txid, psbt->tx.vin[i].prevout.hash, 32);
      psbt->inputs[i].prev_out_index = psbt->tx.vin[i].prevout.n;
      psbt->inputs[i].sequence = psbt->tx.vin[i].nSequence;
    }
    for (size_t i = 0; i < psbt->tx.vout_len; i++) {
      psbt->outputs[i].amount = psbt->tx.vout[i].nValue;
      psbt->outputs[i].script_len = psbt->tx.vout[i].scriptPubKey_len;
      memcpy(psbt->outputs[i].script, psbt->tx.vout[i].scriptPubKey,
             psbt->tx.vout[i].scriptPubKey_len);
    }
  }
  return true;
}

// PSBT serialization function
bool psbt_serialize(const PSBT* psbt, uint8_t* buffer, size_t buffer_size,
                    size_t* psbt_size) {
  BufferWriter writer = {0};
  init_buffer_writer(&writer, buffer, buffer_size);
  // Serialize magic bytes
  if (!write_bytes(PSBT_MAGIC_BYTES, sizeof(PSBT_MAGIC_BYTES), &writer))
    return false;
  if (psbt->global_version == 0) {
    // Serialize unsigned tx flag
    if (!ser_string((uint8_t*)&PSBT_GLOBAL_UNSIGNED_TX, 1, &writer))
      return false;
    // Serialize unsigned tx
    BufferWriter dummy_writer = {0};
    init_buffer_writer(&dummy_writer, NULL, 0);
    if (!ser_transaction(&dummy_writer, &psbt->tx)) return false;
    if (!ser_compact_size(dummy_writer.position, &writer)) return false;
    if (!ser_transaction(&writer, &psbt->tx)) return false;
  }
  // Serialize xpubs
  for (size_t i = 0; i < psbt->xpubs_len; i++) {
    uint8_t key[1 + 78] = {0};
    key[0] = PSBT_GLOBAL_XPUB;
    memcpy(key + 1, psbt->xpubs[i].pubkey, psbt->xpubs[i].pubkey_len);
    if (!ser_string(key, sizeof(key), &writer)) return false;
    BufferWriter dummy_writer = {0};
    init_buffer_writer(&dummy_writer, NULL, 0);
    if (!ser_key_origin(&psbt->xpubs[i].key_origin, &dummy_writer))
      return false;
    if (dummy_writer.position % 4 != 0) return false;
    if (!ser_compact_size(dummy_writer.position, &writer)) return false;
    if (!ser_key_origin(&psbt->xpubs[i].key_origin, &writer)) return false;
  }
  if (psbt->global_version >= 2) {
    if (!psbt->tx_version_lookuped) return false;
    if (!ser_string((uint8_t*)&PSBT_GLOBAL_TX_VERSION, 1, &writer))
      return false;
    if (!ser_string((uint8_t*)&psbt->tx_version, 4, &writer)) return false;

    if (psbt->fallback_locktime_lookuped) {
      if (!ser_string((uint8_t*)&PSBT_GLOBAL_FALLBACK_LOCKTIME, 1, &writer))
        return false;
      if (!ser_string((uint8_t*)&psbt->fallback_locktime, 4, &writer))
        return false;
    }

    if (!ser_string((uint8_t*)&PSBT_GLOBAL_INPUT_COUNT, 1, &writer))
      return false;
    if (!ser_string((uint8_t*)&psbt->inputs_len, 4, &writer)) return false;

    if (!ser_string((uint8_t*)&PSBT_GLOBAL_OUTPUT_COUNT, 1, &writer))
      return false;
    if (!ser_string((uint8_t*)&psbt->outputs_len, 4, &writer)) return false;

    if (psbt->tx_modifiable_lookuped) {
      if (!ser_string((uint8_t*)&PSBT_GLOBAL_TX_MODIFIABLE, 1, &writer))
        return false;
      if (!ser_string((uint8_t*)&psbt->tx_modifiable, 1, &writer)) return false;
    }

    if (psbt->global_version > 0 || psbt->explicit_version) {
      if (!ser_string((uint8_t*)&PSBT_GLOBAL_VERSION, 1, &writer)) return false;
      if (!ser_string((uint8_t*)&psbt->global_version, 4, &writer))
        return false;
    }
  }
  // separator
  if (!write_bytes((uint8_t*)&PSBT_SEPARATOR, 1, &writer)) return false;
  // Serialize inputs
  for (size_t i = 0; i < psbt->inputs_len; i++) {
    if (!ser_psbt_input(&writer, &psbt->inputs[i])) return false;
  }
  // Serialize outputs
  for (size_t i = 0; i < psbt->outputs_len; i++) {
    if (!ser_psbt_output(&writer, &psbt->outputs[i])) return false;
  }
  *psbt_size = writer.position;
  return true;
}

bool locktime_disabled(const PSBT* psbt) {
  for (size_t i = 0; i < psbt->inputs_len; i++) {
    if (psbt->inputs[i].sequence != 0xFFFFFFFF) {
      return false;
    }
  }
  return true;
}

bool compute_locktime(const PSBT* psbt, uint32_t* locktime) {
  int64_t time_lock = 0;
  int64_t height_lock = 0;
  for (size_t i = 0; i < psbt->inputs_len; i++) {
    if (psbt->inputs[i].time_locktime_lookuped &&
        !psbt->inputs[i].height_locktime_lookuped) {
      height_lock = -1;
      if (time_lock == -1) return false;
    } else if (!psbt->inputs[i].height_locktime_lookuped &&
               psbt->inputs[i].time_locktime_lookuped) {
      time_lock = -1;
      if (height_lock == -1) return false;
    }
    if (psbt->inputs[i].time_locktime_lookuped && time_lock != -1) {
      time_lock = MAX(time_lock, psbt->inputs[i].time_locktime);
    }
    if (psbt->inputs[i].height_locktime_lookuped && height_lock != -1) {
      height_lock = MAX(height_lock, psbt->inputs[i].height_locktime);
    }
  }
  if (height_lock > 0) {
    *locktime = (uint32_t)height_lock;
  } else if (time_lock > 0) {
    *locktime = (uint32_t)time_lock;
  } else if (psbt->fallback_locktime > 0) {
    *locktime = psbt->fallback_locktime;
  } else {
    *locktime = 0;
  }
  return true;
}
bool is_witness(const uint8_t* script, size_t script_len,
                uint8_t* witness_version) {
  if (script_len < 4 || script_len > 42) {
    if (witness_version) *witness_version = 0;
    return false;
  }

  if (script[0] != 0 && (script[0] < 81 || script[0] > 96)) {
    if (witness_version) *witness_version = 0;
    return false;
  }

  if ((size_t)(script[1] + 2) == script_len) {
    if (witness_version)
      *witness_version = script[0] != 0 ? script[0] - 0x50 : 0;
    return true;
  }
  if (witness_version) *witness_version = 0;
  return false;
}

bool is_opreturn(const uint8_t* script, size_t script_len) {
  return script_len > 2 && script[0] == 0x6A;
}

bool is_p2sh(const uint8_t* script, size_t script_len) {
  return script_len == 23 && script[0] == 0xA9 && script[1] == 0x14 &&
         script[22] == 0x87;
}

bool is_p2pkh(const uint8_t* script, size_t script_len) {
  return script_len == 25 && script[0] == 0x76 && script[1] == 0xA9 &&
         script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xAC;
}

void* custom_memmem(const void* haystack, size_t haystacklen,
                    const void* needle, size_t needlelen) {
  if (needlelen == 0) return (void*)haystack;
  if (haystacklen < needlelen) return NULL;

  const uint8_t* h = (const uint8_t*)haystack;
  const uint8_t* n = (const uint8_t*)needle;
  size_t last = haystacklen - needlelen + 1;

  for (size_t i = 0; i < last; i++) {
    if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0) {
      return (void*)&h[i];
    }
  }
  return NULL;
}

void sig_hasher_init(BitcoinSigHasher* hasher) {
  hasher_Init(&hasher->hasher_prevouts, HASHER_SHA2);
  hasher_Init(&hasher->hasher_amounts, HASHER_SHA2);
  hasher_Init(&hasher->hasher_scriptpubkeys, HASHER_SHA2);
  hasher_Init(&hasher->hasher_sequences, HASHER_SHA2);
  hasher_Init(&hasher->hasher_outputs, HASHER_SHA2);
}

void sig_hasher_add_input(BitcoinSigHasher* hasher,
                          const PartiallySignedInput* input) {
  hasher_Update(&hasher->hasher_prevouts, input->prev_txid, 32);
  hasher_Update(&hasher->hasher_prevouts,
                (const uint8_t*)&input->prev_out_index, 4);
  hasher_Update(&hasher->hasher_amounts,
                (const uint8_t*)&input->witness_utxo.nValue, 8);
  ser_length_hash(&hasher->hasher_scriptpubkeys,
                  input->witness_utxo.scriptPubKey_len);
  hasher_Update(&hasher->hasher_scriptpubkeys, input->witness_utxo.scriptPubKey,
                input->witness_utxo.scriptPubKey_len);
  hasher_Update(&hasher->hasher_sequences, (const uint8_t*)&input->sequence, 4);
}

void sig_hasher_add_output(BitcoinSigHasher* hasher,
                           const PartiallySignedOutput* output) {
  hasher_Update(&hasher->hasher_outputs, (const uint8_t*)&output->amount, 8);
  ser_length_hash(&hasher->hasher_outputs, output->script_len);
  hasher_Update(&hasher->hasher_outputs, output->script, output->script_len);
}

void sig_hasher_final(BitcoinSigHasher* hasher) {
  hasher_Final(&hasher->hasher_prevouts, hasher->hash_prevouts);
  hasher_Final(&hasher->hasher_amounts, hasher->hash_amounts);
  hasher_Final(&hasher->hasher_scriptpubkeys, hasher->hash_scriptpubkeys);
  hasher_Final(&hasher->hasher_sequences, hasher->hash_sequences);
  hasher_Final(&hasher->hasher_outputs, hasher->hash_outputs);
}
void tagged_hasher_init(Hasher* hasher, const uint8_t* tag, size_t tag_len) {
  uint8_t tag_digest[32] = {0};

  hasher_Raw(HASHER_SHA2, tag, tag_len, tag_digest);

  hasher_Init(hasher, HASHER_SHA2);

  hasher_Update(hasher, tag_digest, sizeof(tag_digest));
  hasher_Update(hasher, tag_digest, sizeof(tag_digest));
}
void sig_hasher_hash_341(const BitcoinSigHasher* hasher, uint32_t i,
                         uint8_t sighash_type, uint8_t* hash, uint32_t version,
                         uint32_t locktime, uint8_t* leaf_hash) {
  const uint8_t zero = 0;
  const uint8_t two = 2;
  Hasher sigmsg_hasher = {0};
  hasher_Init(&sigmsg_hasher, HASHER_SHA2_TAPSIGHASH);
  // sighash epoch 0
  hasher_Update(&sigmsg_hasher, &zero, 1);
  // nHashType
  hasher_Update(&sigmsg_hasher, &sighash_type, 1);
  // nVersion
  hasher_Update(&sigmsg_hasher, (const uint8_t*)&version, 4);
  // nLockTime
  hasher_Update(&sigmsg_hasher, (const uint8_t*)&locktime, 4);
  // sha_prevouts
  hasher_Update(&sigmsg_hasher, hasher->hash_prevouts, 32);
  // sha_amounts
  hasher_Update(&sigmsg_hasher, hasher->hash_amounts, 32);
  // sha_scriptpubkeys
  hasher_Update(&sigmsg_hasher, hasher->hash_scriptpubkeys, 32);
  // sha_sequences
  hasher_Update(&sigmsg_hasher, hasher->hash_sequences, 32);
  // sha_outputs
  hasher_Update(&sigmsg_hasher, hasher->hash_outputs, 32);
  // spend_type 0/2
  hasher_Update(&sigmsg_hasher, leaf_hash ? &two : &zero, 1);
  // input_index
  hasher_Update(&sigmsg_hasher, (const uint8_t*)&i, 4);
  if (leaf_hash) {
    // leaf hash
    hasher_Update(&sigmsg_hasher, leaf_hash, 32);
    // key version
    hasher_Update(&sigmsg_hasher, &zero, 1);
    // codesep_pos (signed int32, default -1)
    int32_t codesep_pos = -1;
    hasher_Update(&sigmsg_hasher, (const uint8_t*)&codesep_pos, 4);
  }
  hasher_Final(&sigmsg_hasher, hash);
}
