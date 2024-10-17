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
#include <stdio.h>
#include "base32.h"
#include "base64.h"
#include "buttons.h"
#include "config.h"
#include "font.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
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

static const uint8_t TON_WALLET_CODE_HASH_V4R2[V4R2_SIZE] = {
    0x02, 0x01, 0x34, 0x00, 0x07, 0x00, 0x00, 0xfe, 0xb5, 0xff,
    0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0, 0xd6,
    0x2c, 0x81, 0x7d, 0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80,
    0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0};

// "0051" + "0000 0000"+ wallet_id(-1 if testnet)
static const uint8_t TON_WALLET_DATA_HASH_PREFIX[DATA_PREFIX_SIZE] = {
    0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x29, 0xa9, 0xa3, 0x17};

void ton_to_user_friendly(TonWorkChain workchain, const char *hash,
                          bool is_bounceable, bool is_testnet_only,
                          char *address) {
  ton_decode_addr(workchain, hash, is_bounceable, is_testnet_only, address);
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

void ton_format_jetton_amount(const uint64_t amount, char *buf, int buflen,
                              int decimals, const char *jetton_name) {
  char str_amount[40] = {0};
  bn_format_uint64(amount, NULL, NULL, decimals, 0, false, 0, str_amount,
                   sizeof(str_amount));

  snprintf(buf, buflen, "%s %s", str_amount, jetton_name);
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
  if (!ton_parse_addr(msg->destination, &parsed_dest)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to parse destination address");
    layoutHome();
    return false;
  }
  if (!ton_parse_addr(usr_friendly_address, &parsed_resp)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to parse response address");
    layoutHome();
    return false;
  }

  // prepare body ref
  CellRef_t payload_data;
  CellRef_t *payload = &payload_data;

  unsigned char raw_data[1024];
  bool is_raw_data = false;
  size_t data_len = 0;

  // display
  if (msg->jetton_amount == 0) {
    char amount_str[60];
    ton_format_toncoin_amount(msg->ton_amount, amount_str, sizeof(amount_str));

    if (msg->has_comment) {
      if (strlen(msg->comment) >= 8 &&
          memcmp(msg->comment, "b5ee9c72", 8) == 0) {
        is_raw_data = true;
        data_len = strlen(msg->comment) / 2;
        if (data_len > sizeof(raw_data)) {
          fsm_sendFailure(FailureType_Failure_ProcessError,
                          "Raw data too large");
          layoutHome();
          return false;
        }
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
      if (!ton_parse_boc(raw_data, data_len, payload)) {
        fsm_sendFailure(FailureType_Failure_ProcessError,
                        "Failed to create raw data body");
        return false;
      }
    } else {
      if (!ton_create_transfer_body(msg->comment, payload)) {
        payload = NULL;
      }
    }
  } else {
    ConstTonTokenPtr token = NULL;
    token = ton_get_token_by_address(msg->jetton_master_address);

    char amount_str[60];
    ton_format_jetton_amount(msg->jetton_amount, amount_str, sizeof(amount_str),
                             token->decimals, token->name);
    if (msg->has_comment) {
      if (!layoutTonSign("Ton", true, amount_str, msg->jetton_master_address,
                         usr_friendly_address, msg->destination, NULL, NULL, 0,
                         msg->comment)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        layoutHome();
        return false;
      }
    } else {
      if (!layoutTonSign("Ton", true, amount_str, msg->jetton_master_address,
                         usr_friendly_address, msg->destination, NULL, NULL, 0,
                         NULL)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        layoutHome();
        return false;
      }
    }

    if (!msg->has_comment) {
      ton_create_jetton_transfer_body(
          parsed_dest.workchain, parsed_dest.hash, msg->jetton_amount, 0, NULL,
          parsed_resp.workchain, parsed_resp.hash, payload);
    } else {
      ton_create_jetton_transfer_body(parsed_dest.workchain, parsed_dest.hash,
                                      msg->jetton_amount, msg->fwd_fee,
                                      msg->comment, parsed_resp.workchain,
                                      parsed_resp.hash, payload);
    }
  }

  const char *ext_destination_ptrs[3] = {NULL, NULL, NULL};
  const char *ext_payload_ptrs[3] = {NULL, NULL, NULL};
  uint8_t ext_dest_count = 0;

  if (msg->ext_destination_count > 0) {
    ext_dest_count =
        (msg->ext_destination_count <= 3) ? msg->ext_destination_count : 3;

    for (int i = 0; i < ext_dest_count; i++) {
      ext_destination_ptrs[i] = msg->ext_destination[i];
      ext_payload_ptrs[i] = msg->ext_payload[i];

      char amount_str[60];
      ton_format_toncoin_amount(msg->ext_ton_amount[i], amount_str,
                                sizeof(amount_str));

      if (msg->has_comment) {
        if (strlen(msg->comment) >= 8 &&
            memcmp(msg->comment, "b5ee9c72", 8) == 0) {  // raw data
          data_len = strlen(ext_payload_ptrs[i]) / 2;
          if (!layoutTonSign("Ton", false, amount_str, ext_destination_ptrs[i],
                             usr_friendly_address, NULL, NULL,
                             (const uint8_t *)ext_payload_ptrs[i], data_len,
                             NULL)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Signing cancelled");
            layoutHome();
            return false;
          }
        } else {  // memo
          if (!layoutTonSign("Ton", false, amount_str, ext_destination_ptrs[i],
                             usr_friendly_address, NULL, NULL, NULL, 0,
                             ext_payload_ptrs[i])) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Signing cancelled");
            layoutHome();
            return false;
          }
        }
      } else {  // no comment
        if (!layoutTonSign("Ton", false, amount_str, ext_destination_ptrs[i],
                           usr_friendly_address, NULL, NULL, NULL, 0, NULL)) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          "Signing cancelled");
          layoutHome();
          return false;
        }
      }
    }
  }

  if (!confirmFinal()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Transaction cancelled by user");
    layoutHome();
    return false;
  }

  if (msg->jetton_amount != 0) {
    memset(&parsed_dest, 0, sizeof(TON_PARSED_ADDRESS));
    if (!ton_parse_addr(msg->jetton_wallet_address, &parsed_dest)) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to parse jetton wallet address");
      layoutHome();
      return false;
    }
  }

  bool create_digest = ton_create_message_digest(
      msg->expire_at, msg->seqno, parsed_dest.is_bounceable,
      parsed_dest.workchain, parsed_dest.hash, msg->ton_amount, msg->mode,
      msg->jetton_amount != 0 ? payload : NULL,
      msg->jetton_amount == 0 ? msg->comment : NULL, ext_destination_ptrs,
      msg->ext_ton_amount, ext_payload_ptrs, ext_dest_count, digest);

  if (!create_digest) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to create message digest");
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

  resp->signning_message.size = 0;
  memset(resp->signning_message.bytes, 0, resp->signning_message.size);
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