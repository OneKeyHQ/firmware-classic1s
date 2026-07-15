/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2021 OneKey Team <core@onekey.so>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ton.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "base64.h"
#include "fsm.h"
#include "layout2.h"
#include "messages-ton.pb.h"
#include "sha2.h"
#include "ton_address.h"
#include "ton_bits.h"
#include "ton_cell.h"
#include "ton_layout.h"
#include "ton_tokens.h"
#include "util.h"

#define V4R2_SIZE 39
#define DATA_PREFIX_SIZE 10
#define SHA256_SIZE 32
#define SIZE_PUBKEY 32
#define USER_FRIENDLY_LEN 36
#define USER_FRIENDLY_B64_LEN 48
#define TON_SUPPORTED_WALLET_ID 698983191u

static const char *ton_boc_error_message(TonBocError error) {
  switch (error) {
    case TON_BOC_ERROR_INVALID_ARGUMENT:
      return "Invalid BOC parser argument";
    case TON_BOC_ERROR_INVALID_FORMAT:
      return "Invalid BOC format";
    case TON_BOC_ERROR_UNSUPPORTED_FORMAT:
      return "Unsupported BOC format";
    case TON_BOC_ERROR_INVALID_CRC:
      return "Invalid BOC CRC32C";
    case TON_BOC_ERROR_INVALID_CELL_COUNT:
      return "Invalid BOC cell count";
    case TON_BOC_ERROR_INVALID_ROOT_COUNT:
      return "Invalid BOC root count";
    case TON_BOC_ERROR_UNSUPPORTED_ABSENT_CELLS:
      return "Unsupported absent BOC cells";
    case TON_BOC_ERROR_INVALID_ROOT:
      return "Invalid BOC root";
    case TON_BOC_ERROR_INVALID_INDEX:
      return "Invalid BOC index";
    case TON_BOC_ERROR_INVALID_SIZE:
      return "Invalid BOC size";
    case TON_BOC_ERROR_OUT_OF_MEMORY:
      return "Out of memory while parsing BOC";
    case TON_BOC_ERROR_UNSUPPORTED_CELL_DESCRIPTOR:
      return "Unsupported BOC cell descriptor";
    case TON_BOC_ERROR_INVALID_CELL:
      return "Invalid BOC cell";
    case TON_BOC_ERROR_INVALID_TOP_UPPED_ARRAY:
      return "Invalid BOC top-upped array";
    case TON_BOC_ERROR_INVALID_REFERENCE:
      return "Invalid BOC reference";
    case TON_BOC_ERROR_UNREACHABLE_CELL:
      return "Unreachable BOC cell";
    case TON_BOC_ERROR_HASH_FAILED:
      return "Failed to hash BOC cell";
    case TON_BOC_OK:
    default:
      return "Invalid BOC payload";
  }
}

static void ton_send_boc_failure(TonBocError error) {
  FailureType failure_type = FailureType_Failure_DataError;
  if (error == TON_BOC_ERROR_INVALID_ARGUMENT ||
      error == TON_BOC_ERROR_OUT_OF_MEMORY ||
      error == TON_BOC_ERROR_HASH_FAILED) {
    failure_type = FailureType_Failure_ProcessError;
  }
  fsm_sendFailure(failure_type, ton_boc_error_message(error));
}

static const uint8_t TON_WALLET_CODE_HASH_V4R2[V4R2_SIZE] = {
    0x02, 0x01, 0x34, 0x00, 0x07, 0x00, 0x00, 0xfe, 0xb5, 0xff,
    0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0, 0xd6,
    0x2c, 0x81, 0x7d, 0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80,
    0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0};

// "0051" + "0000 0000"+ wallet_id(-1 if testnet)
static const uint8_t TON_WALLET_DATA_HASH_PREFIX[DATA_PREFIX_SIZE] = {
    0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x29, 0xa9, 0xa3, 0x17};

void ton_to_user_friendly(TonWorkChain workchain, const char *code_hash,
                          bool is_bounceable, bool is_testnet_only,
                          char *address) {
  ton_encode_addr(workchain, code_hash, is_bounceable, is_testnet_only,
                  address);
}

void ton_append_data_cell_hash(const uint8_t *public_key, SHA256_CTX *ctx) {
  uint8_t data_hash[SHA256_SIZE] = {0};
  SHA256_CTX ctx_data;

  sha256_Init(&ctx_data);

  sha256_Update(&ctx_data, TON_WALLET_DATA_HASH_PREFIX, DATA_PREFIX_SIZE);
  sha256_Update(&ctx_data, public_key, 32);
  sha256_Update(&ctx_data, (const uint8_t *)"\x40", 1);

  sha256_Final(&ctx_data, data_hash);

  // append data cell hash to buf
  sha256_Update(ctx, data_hash, SHA256_SIZE);
}

void ton_get_address_from_public_key(const uint8_t *public_key, char *address) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);

  // append descripter prefix and code cell hash
  sha256_Update(&ctx, TON_WALLET_CODE_HASH_V4R2, V4R2_SIZE);

  ton_append_data_cell_hash(public_key, &ctx);

  sha256_Final(&ctx, (uint8_t *)address);
}

void ton_format_toncoin_amount(const uint64_t amount, char *buf, int buflen) {
  char str_amount[40] = {0};
  bn_format_uint64(amount, NULL, NULL, 9, 0, false, 0, str_amount,
                   sizeof(str_amount));
  snprintf(buf, buflen, "%s TON", str_amount);
}

static bool ton_format_jetton_amount(const uint8_t *value, uint8_t value_len,
                                     char *buf, size_t buflen,
                                     const TonTokenType *token) {
  bignum256 amnt;
  uint8_t pad_val[32] = {0};
  const char *suffix = NULL;
  int decimals = 0;

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);

  bn_read_be(pad_val, &amnt);

  if (token != NULL) {
    suffix = token->name;
    decimals = token->decimals;
  } else {
    return false;
  }

  bn_format(&amnt, NULL, suffix, decimals, 0, false, 0, buf, buflen);

  return true;
}

bool ton_sign_message(const TonSignMessage *msg, const HDNode *node,
                      TonSignedMessage *resp) {
  // get address
  char raw_address[32] = {0};
  char usr_friendly_address[49] = {0};
  ton_get_address_from_public_key(node->public_key + 1, raw_address);
  ton_to_user_friendly(msg->workchain, (const char *)raw_address,
                       msg->is_bounceable, msg->is_testnet_only,
                       usr_friendly_address);
  uint8_t digest[32] = {0};

  // parse dest&resp addr
  TON_PARSED_ADDRESS parsed_dest, parsed_resp = {0};
  if (!ton_decode_addr(msg->destination, &parsed_dest)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to parse destination address");
    layoutHome();
    return false;
  }
  if (!ton_decode_addr(usr_friendly_address, &parsed_resp)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to parse response address");
    layoutHome();
    return false;
  }

  // prepare body ref
  CellRef_t payload_data;
  CellRef_t *payload = &payload_data;

  BitString_t *payload_bits = NULL;
  CellRef_t *payload_refs = NULL;
  uint8_t payload_refs_count = 0;
  TonParsedBoc_t payload_boc;

  unsigned char raw_data[1024];
  bool is_raw_data = false;
  size_t data_len = 0;

  if (msg->has_init_data_initial_chunk) {
    if (!msg->has_signing_message_repr) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "signing message representation is required");
      layoutHome();
      return false;
    }

    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, msg->signing_message_repr.bytes,
                  msg->signing_message_repr.size);
    sha256_Final(&ctx, digest);

    if (!layoutBlindSign("Ton", false, NULL, usr_friendly_address,
                         (const uint8_t *)msg->signing_message_repr.bytes,
                         msg->signing_message_repr.size, NULL, NULL, NULL, NULL,
                         NULL, NULL)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      layoutHome();
      return false;
    }

#if EMULATOR
    ed25519_sign((const unsigned char *)digest, SHA256_SIZE, node->private_key,
                 resp->signature.bytes);
#else
    hdnode_sign(node, (const unsigned char *)digest, SHA256_SIZE, 0,
                resp->signature.bytes, NULL, NULL);
#endif

    resp->signature.size = 64;
    resp->has_signature = true;

    resp->signning_message.size = 32;
    memcpy(resp->signning_message.bytes, digest, resp->signning_message.size);
    resp->has_signning_message = true;

    return true;
  }

  // display
  if (msg->jetton_amount_bytes.size == 0) {
    char amount_str[60];
    ton_format_toncoin_amount(msg->ton_amount, amount_str, sizeof(amount_str));

    if (msg->has_comment) {
      if (strlen(msg->comment) >= 8 &&
          memcmp(msg->comment, "b5ee9c72", 8) == 0) {
        is_raw_data = true;
        data_len = strlen(msg->comment) / 2;
        hex2data(msg->comment, raw_data, &data_len);

        if (!layoutTonSign("Ton", false, amount_str, msg->destination,
                           usr_friendly_address, NULL, NULL,
                           (const uint8_t *)raw_data, data_len, NULL)) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          "Signing cancelled");
          layoutHome();
          return false;
        }
      } else {
        if (!layoutTonSign("Ton", false, amount_str, msg->destination,
                           usr_friendly_address, NULL, NULL, NULL, 0,
                           msg->comment)) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          "Signing cancelled");
          layoutHome();
          return false;
        }
      }
    } else {
      if (!layoutTonSign("Ton", false, amount_str, msg->destination,
                         usr_friendly_address, NULL, NULL, NULL, 0, NULL)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        layoutHome();
        return false;
      }
    }

    // create payload
    if (is_raw_data) {
      TonBocError boc_error =
          ton_parse_boc_full(raw_data, data_len, &payload_boc);
      if (boc_error != TON_BOC_OK) {
        ton_send_boc_failure(boc_error);
        return false;
      }
      payload = &payload_boc.root;
      payload_bits = &payload_boc.root_bits;
      payload_refs = payload_boc.root_refs;
      payload_refs_count = payload_boc.root_refs_count;
    } else {
      if (!ton_create_transfer_body(msg->comment, payload)) {
        payload = NULL;
      }
    }
  } else {
    ConstTonTokenPtr token = NULL;
    token = ton_get_token_by_address(msg->jetton_master_address);

    char amount_str[60];
    if (!ton_format_jetton_amount(msg->jetton_amount_bytes.bytes,
                                  msg->jetton_amount_bytes.size, amount_str,
                                  sizeof(amount_str), token)) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to format jetton amount");
      layoutHome();
      return false;
    }

    if (!layoutTonSign("Ton", true, amount_str, msg->jetton_master_address,
                       usr_friendly_address, msg->destination, NULL, NULL, 0,
                       msg->has_comment ? msg->comment : NULL)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return false;
    }

    if (!ton_create_jetton_transfer_body(
            parsed_dest.workchain, parsed_dest.hash,
            msg->jetton_amount_bytes.bytes, msg->jetton_amount_bytes.size,
            msg->has_comment ? msg->fwd_fee : 0,
            msg->has_comment ? msg->comment : NULL, parsed_resp.workchain,
            parsed_resp.hash, payload)) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to create jetton transfer body");
      layoutHome();
      return false;
    }
  }

  const char *ext_destination_ptrs[3] = {NULL, NULL, NULL};
  const char *ext_payload_ptrs[3] = {NULL, NULL, NULL};
  uint8_t ext_dest_count = 0;

  if (msg->ext_destination_count > 0) {
    ext_dest_count = msg->ext_destination_count;

    for (int i = 0; i < ext_dest_count; i++) {
      ext_destination_ptrs[i] = msg->ext_destination[i];
      ext_payload_ptrs[i] =
          (pb_size_t)i < msg->ext_payload_count ? msg->ext_payload[i] : NULL;

      char amount_str[60];
      ton_format_toncoin_amount(msg->ext_ton_amount[i], amount_str,
                                sizeof(amount_str));

      const uint8_t *display_data = NULL;
      uint16_t display_data_len = 0;
      const char *display_memo = NULL;
      if (ext_payload_ptrs[i] != NULL) {
        size_t ext_payload_len = strlen(ext_payload_ptrs[i]);
        if (ext_payload_len >= 8 &&
            memcmp(ext_payload_ptrs[i], "b5ee9c72", 8) == 0) {
          unsigned int decoded_len = ext_payload_len / 2;
          if (hex2data(ext_payload_ptrs[i], raw_data, &decoded_len) != 0) {
            fsm_sendFailure(FailureType_Failure_DataError,
                            "Invalid extended BOC payload");
            layoutHome();
            return false;
          }
          display_data = raw_data;
          display_data_len = decoded_len;
        } else if (ext_payload_len > 0) {
          display_memo = ext_payload_ptrs[i];
        }
      }

      if (!layoutTonSign("Ton", false, amount_str, ext_destination_ptrs[i],
                         usr_friendly_address, NULL, NULL, display_data,
                         display_data_len, display_memo)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        layoutHome();
        return false;
      }
    }
  }

  if (!confirmFinal()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Transaction cancelled by user");
    layoutHome();
    return false;
  }

  if (msg->jetton_amount_bytes.size != 0) {
    memset(&parsed_dest, 0, sizeof(TON_PARSED_ADDRESS));
    if (!ton_decode_addr(msg->jetton_wallet_address, &parsed_dest)) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to parse jetton wallet address");
      layoutHome();
      return false;
    }
  }
  bool comment_inline = (msg->jetton_amount_bytes.size == 0) && (!is_raw_data);
  bool is_jetton = msg->jetton_amount_bytes.size != 0;

  TonBocError boc_error = TON_BOC_OK;
  bool create_digest = ton_create_message_digest(
      msg->expire_at, msg->seqno, parsed_dest.is_bounceable,
      parsed_dest.workchain, parsed_dest.hash, msg->ton_amount, msg->mode,
      !comment_inline ? payload : NULL, is_jetton,
      comment_inline ? msg->comment : NULL, payload_bits, payload_refs,
      payload_refs_count, ext_destination_ptrs, msg->ext_ton_amount,
      ext_payload_ptrs, ext_dest_count, &boc_error, digest);

  if (!create_digest) {
    if (boc_error != TON_BOC_OK) {
      ton_send_boc_failure(boc_error);
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to create message digest");
    }
    layoutHome();
    return false;
  }

#if EMULATOR
  ed25519_sign((const unsigned char *)digest, SHA256_SIZE, node->private_key,
               resp->signature.bytes);
#else
  hdnode_sign(node, (const unsigned char *)digest, SHA256_SIZE, 0,
              resp->signature.bytes, NULL, NULL);
#endif

  resp->signature.size = 64;
  resp->has_signature = true;

  resp->signning_message.size = 32;
  memcpy(resp->signning_message.bytes, digest, resp->signning_message.size);
  resp->has_signning_message = true;

  return true;
}

bool ton_sign_proof(const TonSignProof *msg, const HDNode *node,
                    TonSignedProof *resp) {
  // get address
  char raw_address[32] = {0};
  char usr_friendly_address[49] = {0};
  ton_get_address_from_public_key(node->public_key + 1, raw_address);
  ton_to_user_friendly(msg->workchain, (const char *)raw_address,
                       msg->is_bounceable, msg->is_testnet_only,
                       usr_friendly_address);

  if (!fsm_layoutSignMessage("Ton", (const char *)usr_friendly_address,
                             msg->comment.bytes, msg->comment.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return false;
  }

  // hash 1
  SHA256_CTX ctx;
  sha256_Init(&ctx);

  const char *message_header = "ton-proof-item-v2/";
  sha256_Update(&ctx, (const uint8_t *)message_header, 18);

  int32_t workchain = (msg->workchain == TonWorkChain_BASECHAIN) ? 0 : -1;
  int32_t *workchain_ptr = &workchain;
  const uint8_t *wc = (const uint8_t *)workchain_ptr;
  sha256_Update(&ctx, wc, 4);

  sha256_Update(&ctx, (const uint8_t *)raw_address, 32);

  uint32_t domain_len = msg->appdomain.size;
  sha256_Update(&ctx, (const uint8_t *)&domain_len, 4);

  sha256_Update(&ctx, (const uint8_t *)msg->appdomain.bytes, domain_len);

  sha256_Update(&ctx, (const uint8_t *)&msg->expire_at, 8);

  uint32_t comment_len = msg->comment.size;
  sha256_Update(&ctx, (const uint8_t *)msg->comment.bytes, comment_len);

  uint8_t message[32] = {0};
  sha256_Final(&ctx, (uint8_t *)message);

  // hash 2
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t *)"\xff\xff", 2);

  const char *message_final_header = "ton-connect";
  sha256_Update(&ctx, (const uint8_t *)message_final_header, 11);

  sha256_Update(&ctx, (const uint8_t *)message, 32);

  uint8_t message_final[32] = {0};
  sha256_Final(&ctx, (uint8_t *)message_final);

#if EMULATOR
  ed25519_sign((const unsigned char *)message_final, SHA256_SIZE,
               node->private_key, resp->signature.bytes);
#else
  hdnode_sign(node, (const unsigned char *)message_final, SHA256_SIZE, 0,
              resp->signature.bytes, NULL, NULL);
#endif

  resp->signature.size = 64;
  resp->has_signature = true;
  return true;
}

static int32_t ton_sign_data_workchain(const TonWorkChain workchain) {
  return (workchain == TonWorkChain_BASECHAIN) ? 0 : -1;
}

static bool ton_build_string_ref_tail(const uint8_t *data, size_t len,
                                      CellRef_t *out) {
  BitString_t bits;
  CellRef_t tail = {0};

  bitstring_init(&bits);

  if (len > 127) {
    if (!ton_build_string_ref_tail(data + 127, len - 127, &tail)) {
      return false;
    }
    bitstring_write_buffer(&bits, (uint8_t *)data, 127);
    return ton_hash_cell(&bits, &tail, 1, out);
  }

  if (len > 0) {
    bitstring_write_buffer(&bits, (uint8_t *)data, (uint8_t)len);
  }

  return ton_hash_cell(&bits, NULL, 0, out);
}

static int encode_domain(const uint8_t *domain, size_t domain_len, uint8_t *buf,
                         size_t buf_len) {
  size_t label_end = domain_len;
  size_t encoded_len = 0;

  if (domain_len == 0) {
    return -1;
  }

  for (size_t i = domain_len; i > 0; i--) {
    if (domain[i - 1] != '.') {
      continue;
    }

    size_t label_start = i;
    size_t label_len = label_end - label_start;
    if (label_len == 0 || buf_len < label_len + 1) {
      return -1;
    }

    memcpy(buf, domain + label_start, label_len);
    buf[label_len] = 0;

    buf += label_len + 1;
    buf_len -= label_len + 1;
    encoded_len += label_len + 1;
    label_end = i - 1;
  }

  if (label_end == 0 || buf_len < label_end + 1) {
    return -1;
  }

  memcpy(buf, domain, label_end);
  buf[label_end] = 0;
  encoded_len += label_end + 1;

  return encoded_len;
}

static bool _build_cell_digest(const TonSignData *msg,
                               const uint8_t *raw_address,
                               const CellRef_t *payload, uint8_t digest[32]) {
  const size_t schema_len = strlen(msg->schema);
  const size_t appdomain_len = strlen(msg->appdomain);
  CellRef_t appdomain_ref = {0};
  BitString_t root_bits;
  CellRef_t root = {0};
  CellRef_t refs[2] = {0};

  uint8_t encoded_domain[126 + 1];
  int encoded_len =
      encode_domain((const uint8_t *)msg->appdomain, appdomain_len,
                    encoded_domain, sizeof(encoded_domain));
  if (encoded_len < 0 ||
      !ton_build_string_ref_tail(encoded_domain, (size_t)encoded_len,
                                 &appdomain_ref)) {
    return false;
  }

  bitstring_init(&root_bits);
  bitstring_write_uint(&root_bits, 0x75569022u, 32);
  bitstring_write_uint(
      &root_bits, legacy_crc32((const uint8_t *)msg->schema, schema_len), 32);
  bitstring_write_uint(&root_bits, msg->timestamp, 64);
  bitstring_write_address(&root_bits,
                          (uint8_t)ton_sign_data_workchain(msg->workchain),
                          (uint8_t *)raw_address);

  refs[0] = appdomain_ref;
  refs[1] = *payload;
  if (!ton_hash_cell(&root_bits, refs, 2, &root)) {
    return false;
  }

  memcpy(digest, root.hash, sizeof(root.hash));
  return true;
}

static void ton_write_u32_be(uint8_t *buffer, uint32_t value) {
  buffer[0] = (uint8_t)(value >> 24);
  buffer[1] = (uint8_t)(value >> 16);
  buffer[2] = (uint8_t)(value >> 8);
  buffer[3] = (uint8_t)value;
}

static void ton_write_u64_be(uint8_t *buffer, uint64_t value) {
  buffer[0] = (uint8_t)(value >> 56);
  buffer[1] = (uint8_t)(value >> 48);
  buffer[2] = (uint8_t)(value >> 40);
  buffer[3] = (uint8_t)(value >> 32);
  buffer[4] = (uint8_t)(value >> 24);
  buffer[5] = (uint8_t)(value >> 16);
  buffer[6] = (uint8_t)(value >> 8);
  buffer[7] = (uint8_t)value;
}

static void _build_bytes_digest(const TonSignData *msg,
                                const uint8_t *raw_address, uint8_t *digest) {
  SHA256_CTX ctx;
  int32_t workchain = ton_sign_data_workchain(msg->workchain);
  uint32_t appdomain_len = (uint32_t)strlen(msg->appdomain);
  uint32_t payload_len = (uint32_t)msg->payload.size;
  uint8_t appdomain_len_bytes[4] = {0};
  uint8_t timestamp_bytes[8] = {0};
  uint8_t payload_len_bytes[4] = {0};
  const uint8_t *type_tag = (msg->type == TonSignDataType_TEXT)
                                ? (const uint8_t *)"txt"
                                : (const uint8_t *)"bin";

  ton_write_u32_be(appdomain_len_bytes, appdomain_len);
  ton_write_u64_be(timestamp_bytes, msg->timestamp);
  ton_write_u32_be(payload_len_bytes, payload_len);

  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t *)"\xff\xff", 2);
  sha256_Update(&ctx, (const uint8_t *)"ton-connect/sign-data/", 22);
  sha256_Update(&ctx, (const uint8_t *)&workchain, 4);
  sha256_Update(&ctx, raw_address, 32);
  sha256_Update(&ctx, appdomain_len_bytes, sizeof(appdomain_len_bytes));
  sha256_Update(&ctx, (const uint8_t *)msg->appdomain, appdomain_len);
  sha256_Update(&ctx, timestamp_bytes, sizeof(timestamp_bytes));
  sha256_Update(&ctx, type_tag, 3);
  sha256_Update(&ctx, payload_len_bytes, sizeof(payload_len_bytes));
  sha256_Update(&ctx, msg->payload.bytes, payload_len);
  sha256_Final(&ctx, digest);
}

static bool ton_validate_sign_data(const TonSignData *msg,
                                   const char *user_friendly_address,
                                   CellRef_t *cell_payload) {
  if (msg->has_from_address &&
      strcmp(msg->from_address, user_friendly_address) != 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "From address mismatch");
    return false;
  }

  if (msg->type == TonSignDataType_TEXT ||
      msg->type == TonSignDataType_BINARY) {
    if (msg->has_schema) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Schema is only allowed for CELL payloads");
      return false;
    }

    if (msg->type == TonSignDataType_TEXT &&
        !is_valid_utf8(msg->payload.bytes, msg->payload.size)) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid UTF-8 text payload");
      return false;
    }

    return true;
  }

  if (msg->type == TonSignDataType_CELL) {
    TonParsedBoc_t parsed_boc;

    if (!msg->has_schema) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Schema is required for CELL payloads");
      return false;
    }

    TonBocError boc_error =
        ton_parse_boc_full(msg->payload.bytes, msg->payload.size, &parsed_boc);
    if (boc_error != TON_BOC_OK) {
      ton_send_boc_failure(boc_error);
      return false;
    }
    *cell_payload = parsed_boc.root;

    return true;
  }

  fsm_sendFailure(FailureType_Failure_DataError, "Invalid TON sign data type");
  return false;
}

bool ton_sign_data(const TonSignData *msg, const HDNode *node,
                   TonSignedData *resp) {
  // reject unsupported wallet params explicitly
  if (msg->wallet_version != TonWalletVersion_V4R2 ||
      msg->wallet_id != TON_SUPPORTED_WALLET_ID) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Unsupported wallet parameters");
    return false;
  }

  // get address
  char raw_address[32] = {0};
  char user_friendly_address[49] = {0};
  ton_get_address_from_public_key(node->public_key + 1, raw_address);
  ton_to_user_friendly(msg->workchain, (const char *)raw_address,
                       msg->is_bounceable, msg->is_testnet_only,
                       user_friendly_address);

  CellRef_t cell_payload = {0};
  if (!ton_validate_sign_data(msg, (const char *)user_friendly_address,
                              &cell_payload)) {
    return false;
  }

  // display
  bool confirmed = false;
  if (msg->type == TonSignDataType_TEXT) {
    confirmed = layoutSignMessage("Ton", false, user_friendly_address,
                                  msg->payload.bytes, msg->payload.size, true,
                                  "App Domain:", msg->appdomain, false);
  } else {
    // BINARY + CELL -> blind sign
    if (msg->type == TonSignDataType_BINARY) {
      confirmed = layoutSignMessage("Ton", false, user_friendly_address,
                                    msg->payload.bytes, msg->payload.size,
                                    false, "App Domain:", msg->appdomain, true);
    } else {
      char ba64_str[1536] = {0};
      bintob64(ba64_str, msg->payload.bytes, msg->payload.size);
      confirmed = layoutSignMessage("Ton", false, user_friendly_address,
                                    (const uint8_t *)ba64_str, strlen(ba64_str),
                                    true, "App Domain:", msg->appdomain, true);
    }
  }

  if (!confirmed) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    return false;
  }

  uint8_t digest[32] = {0};

  if (msg->type == TonSignDataType_TEXT ||
      msg->type == TonSignDataType_BINARY) {
    _build_bytes_digest(msg, (const uint8_t *)raw_address, digest);
  } else {
    if (!_build_cell_digest(msg, (const uint8_t *)raw_address, &cell_payload,
                            digest)) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Failed to hash CELL sign-data payload");
      return false;
    }
  }

#if EMULATOR
  ed25519_sign((const unsigned char *)digest, SHA256_SIZE, node->private_key,
               resp->signature.bytes);
#else
  hdnode_sign(node, (const unsigned char *)digest, SHA256_SIZE, 0,
              resp->signature.bytes, NULL, NULL);
#endif

  resp->signature.size = 64;
  resp->has_signature = true;

  // resp->digest.size = 32;
  // memcpy(resp->digest.bytes, digest, resp->digest.size);
  // resp->has_digest = true;

  return true;
}
