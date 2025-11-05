/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2016 Alex Beregszaszi <alex@rtfs.hu>
 * Copyright (C) 2016 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2016 Jochen Hoenicke <hoenicke@gmail.com>
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
#include <inttypes.h>

#include "address.h"
#include "crypto.h"
#include "curves.h"
#include "ecdsa.h"
#include "eip7702_delegators.h"
#include "ethereum_approveres.h"
#include "ethereum_networks_onekey.h"
#include "ethereum_onekey.h"
#include "ethereum_tokens_onekey.h"
#include "ethereum_typed_data.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "secp256k1.h"
#include "sha3.h"
#include "transaction.h"
#include "util.h"

/* Maximum chain_id which returns the full signature_v (which must fit into an
uint32). chain_ids larger than this will only return one bit and the caller must
recalculate the full value: v = 2 * chain_id + 35 + v_bit */
#define MAX_CHAIN_ID ((0xFFFFFFFF - 36) >> 1)
#define EIP1559_TX_TYPE 2
#define EIP7702_TX_TYPE 4
#define EIP7702_MAGIC 5

static bool ethereum_signing = false;
static uint32_t data_total, data_left;
static EthereumTxRequestOneKey msg_tx_request;
static CONFIDENTIAL HDNode *_node = NULL;
#if EMULATOR
static CONFIDENTIAL uint8_t privkey[32];
#endif
static uint64_t chain_id;
static bool eip1559;
static bool eip7702;
static struct SHA3_CTX keccak_ctx = {0};
static uint8_t *data_left_bytes = NULL;
static uint32_t signing_access_list_count;
static EthereumAccessListOneKey signing_access_list[16];
_Static_assert(sizeof(signing_access_list) ==
                   sizeof(((EthereumSignTxEIP1559OneKey *)NULL)->access_list),
               "access_list buffer size mismatch");
static uint32_t signing_authorization_list_count;
static EthereumAuthorizationOneKey signing_authorization_list[16];
_Static_assert(
    sizeof(signing_authorization_list) ==
        sizeof(((EthereumSignTxEIP7702OneKey *)NULL)->authorization_list),
    "authorization_list buffer size mismatch");

extern HDNode *fsm_getDerivedNode(const char *curve, const uint32_t *address_n,
                                  size_t address_n_count,
                                  uint32_t *fingerprint);
struct signing_params {
  bool pubkeyhash_set;
  uint8_t pubkeyhash[20];
  uint64_t chain_id;

  uint32_t data_length;
  uint32_t data_initial_chunk_size;
  const uint8_t *data_initial_chunk_bytes;

  bool has_to;
  const char *to;

  const TokenType *token;

  uint32_t value_size;
  const uint8_t *value_bytes;
};
typedef enum {
  SafeTxContextType_EXEC,
  SafeTxContextType_APPROVE_HASH,
} SafeTxContextType;
typedef struct {
  SafeTxContextType type;
  union {
    DisplayInfo *display_info;
    char *approve_hash;
  } payload;

} SafeTxContext;
static inline void hash_data_with_ctx(struct SHA3_CTX *ctx, const uint8_t *buf,
                                      size_t size) {
  sha3_Update(ctx, buf, size);
}

static inline void hash_data(const uint8_t *buf, size_t size) {
  sha3_Update(&keccak_ctx, buf, size);
}

/*
 * Push an RLP encoded length to the hash buffer.
 */
static void hash_rlp_length_with_ctx(struct SHA3_CTX *ctx, uint32_t length,
                                     uint8_t firstbyte) {
  uint8_t buf[4] = {0};
  if (length == 1 && firstbyte <= 0x7f) {
    /* empty length header */
  } else if (length <= 55) {
    buf[0] = 0x80 + length;
    hash_data_with_ctx(ctx, buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xb7 + 1;
    buf[1] = length;
    hash_data_with_ctx(ctx, buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xb7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data_with_ctx(ctx, buf, 3);
  } else {
    buf[0] = 0xb7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data_with_ctx(ctx, buf, 4);
  }
}
static void hash_rlp_length(uint32_t length, uint8_t firstbyte) {
  hash_rlp_length_with_ctx(&keccak_ctx, length, firstbyte);
}

/*
 * Push an RLP encoded list length to the hash buffer.
 */
static void hash_rlp_list_length_with_ctx(struct SHA3_CTX *ctx,
                                          uint32_t length) {
  uint8_t buf[4] = {0};
  if (length <= 55) {
    buf[0] = 0xc0 + length;
    hash_data_with_ctx(ctx, buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xf7 + 1;
    buf[1] = length;
    hash_data_with_ctx(ctx, buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xf7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data_with_ctx(ctx, buf, 3);
  } else {
    buf[0] = 0xf7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data_with_ctx(ctx, buf, 4);
  }
}
static void hash_rlp_list_length(uint32_t length) {
  hash_rlp_list_length_with_ctx(&keccak_ctx, length);
}

/*
 * Push an RLP encoded length field and data to the hash buffer.
 */
static void hash_rlp_field_with_ctx(struct SHA3_CTX *ctx, const uint8_t *buf,
                                    size_t size) {
  hash_rlp_length_with_ctx(ctx, size, buf[0]);
  hash_data_with_ctx(ctx, buf, size);
}
static void hash_rlp_field(const uint8_t *buf, size_t size) {
  hash_rlp_field_with_ctx(&keccak_ctx, buf, size);
}

/*
 * Push an RLP encoded number to the hash buffer.
 * Ethereum yellow paper says to convert to big endian and strip leading zeros.
 */
static void hash_rlp_number_with_ctx(struct SHA3_CTX *ctx, uint64_t number) {
  if (number == 0) {
    hash_rlp_length_with_ctx(ctx, 0, 0);
    ;
    return;
  }
  uint8_t data[8] = {0};
  data[0] = (number >> 56) & 0xff;
  data[1] = (number >> 48) & 0xff;
  data[2] = (number >> 40) & 0xff;
  data[3] = (number >> 32) & 0xff;
  data[4] = (number >> 24) & 0xff;
  data[5] = (number >> 16) & 0xff;
  data[6] = (number >> 8) & 0xff;
  data[7] = (number)&0xff;
  int offset = 0;
  while (!data[offset]) {
    offset++;
  }
  hash_rlp_field_with_ctx(ctx, data + offset, 8 - offset);
}

static void hash_rlp_number(uint64_t number) {
  hash_rlp_number_with_ctx(&keccak_ctx, number);
}

/*
 * Calculate the number of bytes needed for an RLP length header.
 * NOTE: supports up to 16MB of data (how unlikely...)
 * FIXME: improve
 */
static int rlp_calculate_length(int length, uint8_t firstbyte) {
  if (length == 1 && firstbyte <= 0x7f) {
    return 1;
  } else if (length <= 55) {
    return 1 + length;
  } else if (length <= 0xff) {
    return 2 + length;
  } else if (length <= 0xffff) {
    return 3 + length;
  } else {
    return 4 + length;
  }
}

/* If number is less than 0x80 the RLP encoding is iteself (1 byte).
 * If it is 0x80 or larger, RLP encoding is 1 + length in bytes.
 */
static int rlp_calculate_number_length(uint64_t number) {
  int length = 1;
  if (number >= 0x80) {
    while (number) {
      length++;
      number = number >> 8;
    }
  }
  return length;
}

static uint32_t rlp_calculate_access_list_keys_length(
    const EthereumAccessListOneKey_storage_keys_t *keys, uint32_t keys_count) {
  uint32_t keys_length = 0;
  for (size_t i = 0; i < keys_count; i++) {
    keys_length += rlp_calculate_length(keys[i].size, keys[i].bytes[0]);
  }
  return keys_length;
}

static uint32_t rlp_calculate_access_list_length(
    const EthereumAccessListOneKey *access_list, uint32_t access_list_count) {
  uint32_t length = 0;
  for (size_t i = 0; i < access_list_count; i++) {
    uint32_t address_length = rlp_calculate_length(20, 0xff);
    uint32_t keys_length = rlp_calculate_access_list_keys_length(
        access_list[i].storage_keys, access_list[i].storage_keys_count);
    length += rlp_calculate_length(
        address_length + rlp_calculate_length(keys_length, 0xff), 0xff);
  }

  return length;
}

static uint32_t rlp_calculate_authorization_list_item_length(
    const EthereumAuthorizationOneKey *authorization, bool with_rlp_length) {
  uint32_t chain_id_length =
      rlp_calculate_number_length(authorization->chain_id);
  uint32_t address_length = rlp_calculate_length(20, 0xff);
  uint32_t nonce_length = rlp_calculate_length(authorization->nonce.size,
                                               authorization->nonce.bytes[0]);
  uint32_t signature_v_length =
      rlp_calculate_number_length(authorization->signature.y_parity);
  uint32_t signature_r_length =
      rlp_calculate_length(authorization->signature.r.size, 0xff);
  uint32_t signature_s_length =
      rlp_calculate_length(authorization->signature.s.size, 0xff);
  uint32_t length = chain_id_length + address_length + nonce_length +
                    signature_v_length + signature_r_length +
                    signature_s_length;
  if (with_rlp_length) {
    length = rlp_calculate_length(length, 0xff);
  }
  return length;
}

static uint32_t rlp_calculate_authorization_list_length(
    const EthereumAuthorizationOneKey *authorization_list,
    uint32_t authorization_list_count) {
  uint32_t length = 0;
  for (size_t i = 0; i < authorization_list_count; i++) {
    length += rlp_calculate_authorization_list_item_length(
        &authorization_list[i], true);
  }
  return length;
}

static bool hash_authorization_list(
    const EthereumAuthorizationOneKey *authorization_list,
    uint32_t authorization_list_count) {
  hash_rlp_list_length(rlp_calculate_authorization_list_length(
      authorization_list, authorization_list_count));
  for (size_t i = 0; i < authorization_list_count; i++) {
    const EthereumAuthorizationOneKey *cur_authorization =
        &authorization_list[i];
    if (!cur_authorization->has_signature) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Authorization list item has no signature");
      return false;
    }
    uint8_t address[20] = {0};
    if (!ethereum_parse_onekey(cur_authorization->address, address)) {
      fsm_sendFailure(FailureType_Failure_DataError, "Malformed address");
      return false;
    }
    hash_rlp_list_length(
        rlp_calculate_authorization_list_item_length(cur_authorization, false));
    hash_rlp_number(cur_authorization->chain_id);
    hash_rlp_field(address, sizeof(address));
    hash_rlp_field(cur_authorization->nonce.bytes,
                   cur_authorization->nonce.size);
    hash_rlp_number(cur_authorization->signature.y_parity);
    hash_rlp_field(cur_authorization->signature.r.bytes,
                   cur_authorization->signature.r.size);
    hash_rlp_field(cur_authorization->signature.s.bytes,
                   cur_authorization->signature.s.size);
  }
  return true;
}

static bool make_authorization_digest(
    const EthereumAuthorizationOneKey *authorization, uint8_t *digest) {
  uint8_t address[20] = {0};
  if (!ethereum_parse_onekey(authorization->address, address)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Malformed address");
    return false;
  }
  struct SHA3_CTX keccak = {0};
  uint8_t magic = EIP7702_MAGIC;
  sha3_256_Init(&keccak);
  sha3_Update(&keccak, &magic, 1);
  uint32_t chain_id_len = rlp_calculate_number_length(authorization->chain_id);
  uint32_t address_len = rlp_calculate_length(20, 0xff);
  uint32_t nonce_len = rlp_calculate_length(authorization->nonce.size,
                                            authorization->nonce.bytes[0]);
  hash_rlp_list_length_with_ctx(&keccak,
                                chain_id_len + address_len + nonce_len);
  hash_rlp_number_with_ctx(&keccak, authorization->chain_id);
  hash_rlp_field_with_ctx(&keccak, address, sizeof(address));
  hash_rlp_field_with_ctx(&keccak, authorization->nonce.bytes,
                          authorization->nonce.size);
  keccak_Final(&keccak, digest);
  return true;
}

static void send_request_chunk(void) {
  int progress = 1000 - (data_total > 1000000 ? data_left / (data_total / 800)
                                              : data_left * 800 / data_total);
  layoutProgressAdapter(_(C__SIGNING), progress);
  msg_tx_request.has_data_length = true;
  msg_tx_request.data_length = data_left <= 1024 ? data_left : 1024;
  msg_write(MessageType_MessageType_EthereumTxRequestOneKey, &msg_tx_request);
}

static int ethereum_is_canonic(uint8_t v, uint8_t signature[64]) {
  (void)signature;
  return (v & 2) == 0;
}

bool sign_authorization_list(const EthereumSignTxEIP7702OneKey *msg,
                             const HDNode *node) {
  uint8_t authorization_digest[32] = {0};
  signing_authorization_list_count = msg->authorization_list_count;
  for (size_t i = 0; i < msg->authorization_list_count; i++) {
    const EthereumAuthorizationOneKey *cur_authorization =
        &msg->authorization_list[i];
    if (!cur_authorization->has_signature) {
      if (!make_authorization_digest(cur_authorization, authorization_digest)) {
        return false;
      }
      if (cur_authorization->address_n_count == 0) {
        _node = (HDNode *)node;
      } else {
        const HDNode *node_ =
            fsm_getDerivedNode(SECP256K1_NAME, cur_authorization->address_n,
                               cur_authorization->address_n_count, NULL);
        if (!node_) {
          fsm_sendFailure(FailureType_Failure_DataError,
                          "Failed to derive node");
          return false;
        }
        _node = (HDNode *)node_;
      }
      uint8_t sig[64] = {0};
      uint8_t v = 0;
#if EMULATOR
      memcpy(privkey, _node->private_key, 32);
      if (ecdsa_sign_digest(&secp256k1, privkey, authorization_digest, sig, &v,
                            ethereum_is_canonic) != 0) {
#else
      if (hdnode_sign_digest(_node, authorization_digest, sig, &v,
                             ethereum_is_canonic) != 0) {
#endif
        fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
        return false;
      }
#if EMULATOR
      memzero(privkey, sizeof(privkey));
#endif
      signing_authorization_list[i].signature.y_parity = v;
      memcpy(signing_authorization_list[i].signature.r.bytes, sig, 32);
      memcpy(signing_authorization_list[i].signature.s.bytes, sig + 32, 32);
    } else {
      memcpy(signing_authorization_list[i].signature.r.bytes,
             cur_authorization->signature.r.bytes,
             cur_authorization->signature.r.size);
      memcpy(signing_authorization_list[i].signature.s.bytes,
             cur_authorization->signature.s.bytes,
             cur_authorization->signature.s.size);
      signing_authorization_list[i].signature.y_parity =
          cur_authorization->signature.y_parity;
    }
    signing_authorization_list[i].has_signature = true;
    signing_authorization_list[i].signature.r.size = 32;
    signing_authorization_list[i].signature.s.size = 32;
    signing_authorization_list[i].chain_id = cur_authorization->chain_id;
    memcpy(signing_authorization_list[i].address, cur_authorization->address,
           43);
    signing_authorization_list[i].nonce.size = cur_authorization->nonce.size;
    memcpy(signing_authorization_list[i].nonce.bytes,
           cur_authorization->nonce.bytes, cur_authorization->nonce.size);
  }
  return true;
}
static void send_signature(void) {
  uint8_t hash[32] = {0}, sig[64] = {0};
  uint8_t v = 0;
  layoutProgressAdapter(_(C__SIGNING), 1000);

  if (eip1559 || eip7702) {
    hash_rlp_list_length(rlp_calculate_access_list_length(
        signing_access_list, signing_access_list_count));
    for (size_t i = 0; i < signing_access_list_count; i++) {
      uint8_t address[20] = {0};
      if (!ethereum_parse_onekey(signing_access_list[i].address, address)) {
        fsm_sendFailure(FailureType_Failure_DataError, "Malformed address");
        ethereum_signing_abort_onekey();
        return;
      }

      uint32_t address_length =
          rlp_calculate_length(sizeof(address), address[0]);
      uint32_t keys_length = rlp_calculate_access_list_keys_length(
          signing_access_list[i].storage_keys,
          signing_access_list[i].storage_keys_count);

      hash_rlp_list_length(address_length +
                           rlp_calculate_length(keys_length, 0xff));
      hash_rlp_field(address, sizeof(address));
      hash_rlp_list_length(keys_length);
      for (size_t j = 0; j < signing_access_list[i].storage_keys_count; j++) {
        hash_rlp_field(signing_access_list[i].storage_keys[j].bytes,
                       signing_access_list[i].storage_keys[j].size);
      }
    }
    if (eip7702) {
      if (!hash_authorization_list(signing_authorization_list,
                                   signing_authorization_list_count)) {
        ethereum_signing_abort_onekey();
        return;
      }
    }
  } else {
    /* eip-155 replay protection */
    /* hash v=chain_id, r=0, s=0 */
    hash_rlp_number(chain_id);
    hash_rlp_length(0, 0);
    hash_rlp_length(0, 0);
  }

  keccak_Final(&keccak_ctx, hash);
#if EMULATOR
  if (ecdsa_sign_digest(&secp256k1, privkey, hash, sig, &v,
                        ethereum_is_canonic) != 0) {
#else
  if (hdnode_sign_digest(_node, hash, sig, &v, ethereum_is_canonic) != 0) {
#endif
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    ethereum_signing_abort_onekey();
    return;
  }
#if EMULATOR
  memzero(privkey, sizeof(privkey));
#endif

  /* Send back the result */
  msg_tx_request.has_data_length = false;

  msg_tx_request.has_signature_v = true;
  if (eip1559 || eip7702 || chain_id > MAX_CHAIN_ID) {
    msg_tx_request.signature_v = v;
  } else {
    msg_tx_request.signature_v = v + 2 * chain_id + 35;
  }
  if (eip7702) {
    msg_tx_request.authorization_signatures_count =
        signing_authorization_list_count;
    for (size_t i = 0; i < signing_authorization_list_count; i++) {
      msg_tx_request.authorization_signatures[i].y_parity =
          signing_authorization_list[i].signature.y_parity;
      msg_tx_request.authorization_signatures[i].r.size = 32;
      memcpy(msg_tx_request.authorization_signatures[i].r.bytes,
             signing_authorization_list[i].signature.r.bytes, 32);
      msg_tx_request.authorization_signatures[i].s.size = 32;
      memcpy(msg_tx_request.authorization_signatures[i].s.bytes,
             signing_authorization_list[i].signature.s.bytes, 32);
    }
  }

  msg_tx_request.has_signature_r = true;
  msg_tx_request.signature_r.size = 32;
  memcpy(msg_tx_request.signature_r.bytes, sig, 32);

  msg_tx_request.has_signature_s = true;
  msg_tx_request.signature_s.size = 32;
  memcpy(msg_tx_request.signature_s.bytes, sig + 32, 32);

  msg_write(MessageType_MessageType_EthereumTxRequestOneKey, &msg_tx_request);

  ethereum_signing_abort_onekey();
}
/* Format a 256 bit number (amount in wei) into a human readable format
 * using standard ethereum units.
 * The buffer must be at least 25 bytes.
 */
static void ethereumFormatAmount(const bignum256 *amnt, const TokenType *token,
                                 char *buf, int buflen) {
  bignum256 bn1e9 = {0};
  bn_read_uint32(1000000000, &bn1e9);
  const char *suffix = NULL;
  int decimals = 18;
  if (token == UnknownToken) {
    suffix = "UNKN";
    decimals = 0;
  } else if (token != NULL) {
    suffix = token->ticker;
    decimals = token->decimals;
  } else if (bn_is_zero(amnt)) {
    ASSIGN_ETHEREUM_SUFFIX(suffix, chain_id);
    decimals = 0;
  } else if (bn_is_less(amnt, &bn1e9)) {
    suffix = " Wei";
    decimals = 0;
  } else {
    ASSIGN_ETHEREUM_SUFFIX(suffix, chain_id);
  }
  bn_format(amnt, NULL, suffix, decimals, 0, false, ',', buf, buflen);
}
extern bool button_request(const ButtonRequestType code);
static bool layoutTransactionSafeExecTx(
    const char *chain_name, const char *to_addr, const char *signer,
    bool is_delegate_call, const DisplayInfo *display_ctx, const char *nonce,
    const char *gas_fee, const char *max_fee_per_gas,
    const char *max_priority_fee_per_gas, const char *chain_id_str) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t bubble_key;
  uint8_t max_index = 7, detail_total_index = 1, detail_index = 0;
  uint8_t detail_total_index_safe_tx = display_ctx->items_count;
  uint8_t detail_index_safe_tx = 0;

  const char **tx_msg = format_tx_message(chain_name);

  if (max_fee_per_gas) detail_total_index++;
  if (max_priority_fee_per_gas) detail_total_index++;

  if (!button_request(ButtonRequestType_ButtonRequest_SignTx)) {
    return false;
  }
  if (is_delegate_call) {
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                                NULL, NULL, _(I_SAFE_DELEGATE_WARNING));
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      return false;
    }
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  bubble_key = KEY_NULL;
  y = 13;
  if (index == 0) {  // view exec transaction
    layoutHeader(_(T_CONFIRM_SAFE_TX));
    oledDrawStringAdapter(0, y, _(I_VIEW_EXEC_TRANSACTION), FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {  // safe transaction details
    detail_index_safe_tx = 0;
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(_(T__TRANSACTION_DETAILS));
      if (detail_index_safe_tx < detail_total_index_safe_tx) {
        const DisplayItem *item = &display_ctx->items[detail_index_safe_tx];
        const char *name = item->name;
        const char *value = item->value;
        int name_intent = item->name_intent;

        if (name && value) {
          oledDrawStringAdapter(name_intent, y, name, FONT_STANDARD);
          oledDrawStringAdapter(0, y + 10, value, FONT_STANDARD);
        }
      }
      // scrollbar
      drawScrollbar(detail_total_index_safe_tx, detail_index_safe_tx);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);

      layout_index_count(detail_index_safe_tx + 1, detail_total_index_safe_tx);
      if (detail_total_index_safe_tx > 1) {
        if (detail_index_safe_tx == 0) {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
        } else if (detail_index_safe_tx == detail_total_index_safe_tx - 1) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        }
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        break;
      } else if (bubble_key == KEY_CONFIRM) {
        break;
      } else if (bubble_key == KEY_UP) {
        if (detail_index_safe_tx > 0) {
          detail_index_safe_tx--;
        }
      } else if (bubble_key == KEY_DOWN) {
        if (detail_index_safe_tx < detail_total_index_safe_tx - 1) {
          detail_index_safe_tx++;
        }
      }
    }
  } else if (index == 2) {  // to address
    layoutHeader(_(T_CONFIRM_SAFE_TX));
    oledDrawStringAdapter(0, y, _(I__SEND_TO_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, to_addr, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 3) {  // from address
    layoutHeader(_(T_CONFIRM_SAFE_TX));
    oledDrawStringAdapter(0, y, _(I__FROM_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, signer, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 4) {  // tx details
    detail_index = 0;
    const char *keys[] = {
        _(I__ETH_MAXIMUM_FEE_COLON),
        _(I__MAXIMUM_FEE_PER_GAS_COLON),
        _(I__PRIORITY_FEE_PER_GAS_COLON),
    };
    const char *values[] = {gas_fee, max_fee_per_gas, max_priority_fee_per_gas};
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(_(T__TRANSACTION_DETAILS));
      if (detail_index < detail_total_index) {
        if (keys[detail_index] && values[detail_index]) {
          oledDrawStringAdapter(0, y, keys[detail_index], FONT_STANDARD);
          oledDrawStringAdapter(0, y + 10, values[detail_index], FONT_STANDARD);
        }
      }
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);
      if (detail_total_index > 1) {
        // scrollbar
        drawScrollbar(detail_total_index, detail_index);
        layout_index_count(detail_index + 1, detail_total_index);
        if (detail_index == 0) {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
        } else if (detail_index == detail_total_index - 1) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        }
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        break;
      } else if (bubble_key == KEY_CONFIRM) {
        break;
      } else if (bubble_key == KEY_UP) {
        if (detail_index > 0) {
          detail_index--;
        }
      } else if (bubble_key == KEY_DOWN) {
        if (detail_index < detail_total_index - 1) {
          detail_index++;
        }
      }
    }
  } else if (index == 5) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, y, "Nonce:", FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, nonce, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 6) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, y, "ChainID:", FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, chain_id_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}
static bool layoutEthereumConfirmApproveHash(
    const struct signing_params *params, const char *signer, const uint8_t *to,
    const char *max_gas_fee, const char *approve_hash, const char *nonce,
    const char *max_fee_per_gas, const char *max_priority_fee_per_gas) {
  const char *chain_name = NULL;
  ASSIGN_ETHEREUM_NAME(chain_name, params->chain_id);

  char to_str[52] = "____________";
  bool rskip60 = false;
  // constants from trezor-common/defs/ethereum/networks.json
  switch (chain_id) {
    case 30:
    case 31:
      rskip60 = true;
      break;
  }
  ethereum_address_checksum(to, to_str, rskip60, chain_id);
  char chain_id_str[21] = {0};
  snprintf(chain_id_str, sizeof(chain_id_str), "%" PRIu32, (uint32_t)chain_id);
  return layoutTransactionSafeApproveHash(
      chain_name, to_str, signer, approve_hash, nonce, max_gas_fee,
      max_fee_per_gas, max_priority_fee_per_gas, chain_id_str);
}
static bool layoutEthereumConfirmExecTx(
    const struct signing_params *params, const char *signer, const uint8_t *to,
    bool is_delegate_call, const char *max_gas_fee,
    const DisplayInfo *display_ctx, const char *nonce,
    const char *max_fee_per_gas, const char *max_priority_fee_per_gas) {
  const char *chain_name = NULL;
  ASSIGN_ETHEREUM_NAME(chain_name, params->chain_id);

  char to_str[52] = "____________";
  bool rskip60 = false;
  // constants from trezor-common/defs/ethereum/networks.json
  switch (chain_id) {
    case 30:
    case 31:
      rskip60 = true;
      break;
  }
  ethereum_address_checksum(to, to_str, rskip60, chain_id);
  char chain_id_str[21] = {0};
  snprintf(chain_id_str, sizeof(chain_id_str), "%" PRIu32, (uint32_t)chain_id);
  return layoutTransactionSafeExecTx(
      chain_name, to_str, signer, is_delegate_call, display_ctx, nonce,
      max_gas_fee, max_fee_per_gas, max_priority_fee_per_gas, chain_id_str);
}

static bool layoutEthereumConfirmERC20Approve(
    const char *chain_name, const char *token_address, const char *signer,
    const char *spender, bool is_unlimited, bool is_revoke,
    const char *overview_text, const char *nonce, const char *gas_fee,
    const char *max_fee_per_gas, const char *max_priority_fee_per_gas,
    const char *chain_id_str) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t bubble_key;
  uint8_t max_index = 7, detail_total_index = 1, detail_index = 0;

  const char **tx_msg = format_tx_message(chain_name);

  if (max_fee_per_gas) detail_total_index++;
  if (max_priority_fee_per_gas) detail_total_index++;

  if (!button_request(ButtonRequestType_ButtonRequest_SignTx)) {
    return false;
  }
  if (is_unlimited) {
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                                NULL, NULL,
                                _(I_UNLIMITED_AUTHORIZATION_BANNER));
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      return false;
    }
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  bubble_key = KEY_NULL;
  y = 13;
  if (index == 0) {  // approve overview
    layoutHeader(_(T_CONFIRM_REQUEST));
    oledDrawStringAdapter(0, y, overview_text, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {  // spender address
    layoutHeader(_(T__TRANSACTION_DETAILS));
    oledDrawStringAdapter(0, y, is_revoke ? _(I_REVOKE_FROM) : _(I_APPROVE_TO),
                          FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, spender, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 2) {  // signer address
    layoutHeader(_(T__TRANSACTION_DETAILS));
    oledDrawStringAdapter(0, y, _(I__FROM_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, signer, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 3) {  // token address
    layoutHeader(_(T__TRANSACTION_DETAILS));
    oledDrawStringAdapter(0, y, _(I_TOKEN_ADDRESS), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, token_address, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 4) {  // gas details
    detail_index = 0;
    const char *keys[] = {
        _(I__ETH_MAXIMUM_FEE_COLON),
        _(I__MAXIMUM_FEE_PER_GAS_COLON),
        _(I__PRIORITY_FEE_PER_GAS_COLON),
    };
    const char *values[] = {gas_fee, max_fee_per_gas, max_priority_fee_per_gas};
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(_(T__TRANSACTION_DETAILS));
      if (detail_index < detail_total_index) {
        if (keys[detail_index] && values[detail_index]) {
          oledDrawStringAdapter(0, y, keys[detail_index], FONT_STANDARD);
          oledDrawStringAdapter(0, y + 10, values[detail_index], FONT_STANDARD);
        }
      }
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);
      if (detail_total_index > 1) {
        // scrollbar
        drawScrollbar(detail_total_index, detail_index);
        layout_index_count(detail_index + 1, detail_total_index);
        if (detail_index == 0) {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
        } else if (detail_index == detail_total_index - 1) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        }
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        break;
      } else if (bubble_key == KEY_CONFIRM) {
        break;
      } else if (bubble_key == KEY_UP) {
        if (detail_index > 0) {
          detail_index--;
        }
      } else if (bubble_key == KEY_DOWN) {
        if (detail_index < detail_total_index - 1) {
          detail_index++;
        }
      }
    }
  } else if (index == 5) {
    layoutHeader(_(T__TRANSACTION_DETAILS));
    oledDrawStringAdapter(0, y, "Nonce:", FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, nonce, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 6) {
    layoutHeader(_(T__TRANSACTION_DETAILS));
    oledDrawStringAdapter(0, y, "ChainID:", FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, chain_id_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}
static bool layoutEthereumConfirmTx(
    const struct signing_params *params, const char *signer, const uint8_t *to,
    uint32_t to_len, const uint8_t *value, uint32_t value_len,
    const TokenType *token, const uint8_t *gas_price, uint32_t gas_price_len,
    const uint8_t *gas_limit, uint32_t gas_limit_len, bool is_eip1559,
    bool is_nft_transfer, const uint8_t *recipient, char *token_id,
    char *token_amount, const char *key1, const char *value1, const char *key2,
    const char *value2, const char *key3, const char *value3) {
  bignum256 val = {0}, gas = {0}, total = {0};
  uint8_t pad_val[32] = {0};
  char tx_value[32] = {0};
  char gas_value[32] = {0};
  const char *chain_name = NULL;
  ASSIGN_ETHEREUM_NAME(chain_name, params->chain_id);
  // gas
  memzero(tx_value, sizeof(tx_value));
  memzero(gas_value, sizeof(gas_value));

  memzero(pad_val, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_price_len), gas_price, gas_price_len);
  bn_read_be(pad_val, &val);

  memzero(pad_val, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_limit_len), gas_limit, gas_limit_len);
  bn_read_be(pad_val, &gas);
  bn_multiply(&val, &gas, &secp256k1.prime);

  ethereumFormatAmount(&gas, NULL, gas_value, sizeof(gas_value));

  // amount
  memzero(pad_val, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, &val);

  char to_str[52] = "____________";
  char amount[64] = {0};
  char total_amount[64] = {0};
  if (to_len) {
    bool rskip60 = false;
    // constants from trezor-common/defs/ethereum/networks.json
    switch (chain_id) {
      case 30:
      case 31:
        rskip60 = true;
        break;
    }
    ethereum_address_checksum(to, to_str, rskip60, chain_id);
  } else {
    strlcpy(to_str, "to new contract?", sizeof(to_str));
  }
  if (is_nft_transfer) {
    char recip[64] = {0};
    bool rskip60 = false;
    switch (chain_id) {
      case 30:
      case 31:
        rskip60 = true;
        break;
    }
    ethereum_address_checksum(recipient, recip, rskip60, chain_id);
    if (!is_eip1559) {
      return layoutTransactionSignEVM(
          chain_name, params->chain_id, true, token_amount, to_str, signer,
          recip, token_id, NULL, 0, _(I__ETH_MAXIMUM_FEE_COLON), gas_value,
          NULL, NULL, NULL, NULL, NULL, NULL);
    } else {
      return layoutTransactionSignEVM(chain_name, params->chain_id, true,
                                      token_amount, to_str, signer, recip,
                                      token_id, NULL, 0, key1, value1, key2,
                                      value2, key3, value3, NULL, NULL);
    }
  } else if (token == NULL) {
    bn_add(&total, &val);
    bn_add(&total, &gas);
    ethereumFormatAmount(&val, NULL, amount, sizeof(amount));
    ethereumFormatAmount(&total, NULL, total_amount, sizeof(total_amount));
    if (!is_eip1559) {
      return layoutTransactionSignEVM(
          chain_name, params->chain_id, false, amount, to_str, signer, NULL,
          NULL, params->data_initial_chunk_bytes,
          data_total > 1024 ? 1024 : data_total, _(I__ETH_MAXIMUM_FEE_COLON),
          gas_value, _(I__TOTAL_AMOUNT_COLON), total_amount, NULL, NULL, NULL,
          NULL);
    } else {
      return layoutTransactionSignEVM(
          chain_name, params->chain_id, false, amount, to_str, signer, NULL,
          NULL, params->data_initial_chunk_bytes,
          data_total > 1024 ? 1024 : data_total, key1, value1, key2, value2,
          key3, value3, _(I__TOTAL_AMOUNT_COLON), total_amount);
    }
  } else {
    ethereumFormatAmount(&val, token, amount, sizeof(amount));
    strcat(total_amount, amount);
    strcat(total_amount, "\n");
    strcat(total_amount, gas_value);
    if (!is_eip1559) {
      return layoutTransactionSignEVM(
          chain_name, params->chain_id, true, amount, to_str, signer, NULL,
          NULL, NULL, 0, _(I__ETH_MAXIMUM_FEE_COLON), gas_value,
          _(I__TOTAL_AMOUNT_COLON), total_amount, NULL, NULL, NULL, NULL);
    } else {
      return layoutTransactionSignEVM(
          chain_name, params->chain_id, true, amount, to_str, signer, NULL,
          NULL, NULL, 0, key1, value1, key2, value2, key3, value3,
          _(I__TOTAL_AMOUNT_COLON), total_amount);
    }
  }

  return true;
}
static bool layoutEthereumConfirmEIP7702(
    const struct signing_params *params, const char *signer,
    const EthereumAuthorizationOneKey *authorization, const char *key1,
    const char *value1, const char *key2, const char *value2, const char *key3,
    const char *value3, const char *key4, const char *value4) {
  bignum256 temp = {0};
  uint8_t pad_val[32] = {0};
  const char *chain_name = NULL;
  ASSIGN_ETHEREUM_NAME(chain_name, params->chain_id);

  // amount
  char amount[64] = {0};
  memcpy(pad_val + (32 - params->value_size), params->value_bytes,
         params->value_size);
  bn_read_be(pad_val, &temp);
  ethereumFormatAmount(&temp, NULL, amount, sizeof(amount));
  // delegator name
  uint8_t delegator_address[20] = {0};
  ethereum_parse_onekey(authorization->address, delegator_address);
  bool is_revoke = is_revoke_delegator(delegator_address);
  const char *delegator_network = NULL;
  char chain_id_str[11] = {0};
  if (authorization->chain_id == 0) {
    delegator_network = "ALL";
  } else if (strcmp(chain_name, "EVM") == 0) {
    snprintf(chain_id_str, sizeof(chain_id_str), "%" PRIu32,
             (uint32_t)authorization->chain_id);
    delegator_network = chain_id_str;
  } else {
    delegator_network = chain_name;
  }
  const Delegator *delegator =
      get_delegator_by_address(authorization->chain_id, delegator_address);
  if (delegator == NULL) {
    fsm_sendFailure(FailureType_Failure_DataError, "Unregistered delegator");
    return false;
  }
  return layoutTransactionEIP7702(
      chain_name, authorization->address, delegator->name, delegator_network,
      is_revoke, signer, _(I__AMOUNT_COLON), amount, key1, value1, key2, value2,
      key3, value3, key4, value4);
}

static void fillEthereumFee(const uint8_t *amount_bytes, uint32_t amount_len,
                            const uint8_t *multiplier_bytes,
                            uint32_t multiplier_len, char *amount_str) {
  bignum256 amount_val = {0};
  uint8_t padded[32] = {0};

  memcpy(padded + (32 - amount_len), amount_bytes, amount_len);
  bn_read_be(padded, &amount_val);

  if (multiplier_len > 0) {
    bignum256 multiplier_val = {0};

    memzero(padded, sizeof(padded));
    memcpy(padded + (32 - multiplier_len), multiplier_bytes, multiplier_len);
    bn_read_be(padded, &multiplier_val);
    bn_multiply(&multiplier_val, &amount_val, &secp256k1.prime);
  }

  ethereumFormatAmount(&amount_val, NULL, amount_str, 32);
}

/*
 * RLP fields:
 * - nonce (0 .. 32)
 * - gas_price (0 .. 32)
 * - gas_limit (0 .. 32)
 * - to (0, 20)
 * - value (0 .. 32)
 * - data (0 ..)
 */

static bool ethereum_signing_init_common(struct signing_params *params) {
  ethereum_signing = true;
  sha3_256_Init(&keccak_ctx);

  data_total = data_left = 0;
  chain_id = 0;

  memzero(&msg_tx_request, sizeof(EthereumTxRequestOneKey));
  memzero(signing_access_list, sizeof(signing_access_list));
  signing_access_list_count = 0;
  memzero(signing_authorization_list, sizeof(signing_authorization_list));
  signing_authorization_list_count = 0;

  /* eip-155 chain id */
  if (params->chain_id < 1) {
    fsm_sendFailure(FailureType_Failure_DataError, "Chain ID out of bounds");
    return false;
  }
  chain_id = params->chain_id;

  if (params->data_length > 0) {
    if (params->data_initial_chunk_size == 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Data length provided, but no initial chunk");
      return false;
    }
    /* Our encoding only supports transactions up to 2^24 bytes.  To
     * prevent exceeding the limit we use a stricter limit on data length.
     */
    if (params->data_length > 16000000) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Data length exceeds limit");
      return false;
    }
    data_total = params->data_length;
  } else {
    data_total = 0;
  }
  if (params->data_initial_chunk_size > data_total) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid size of initial chunk");
    return false;
  }

  // safety checks

  size_t tolen = params->has_to ? strlen(params->to) : 0;
  /* Address has wrong length */
  bool wrong_length = (tolen != 42 && tolen != 40 && tolen != 0);

  // sending transaction to address 0 (contract creation) without a data field
  bool contract_without_data = (tolen == 0 && params->data_length == 0);

  if (wrong_length || contract_without_data) {
    fsm_sendFailure(FailureType_Failure_DataError, "Safety check failed");
    return false;
  }
  if (params->has_to && ethereum_parse_onekey(params->to, params->pubkeyhash)) {
    params->pubkeyhash_set = true;
  } else {
    params->pubkeyhash_set = false;
    memzero(params->pubkeyhash, sizeof(params->pubkeyhash));
  }
  return true;
}

static void ethereum_signing_handle_erc20(struct signing_params *params) {
  // detect ERC-20 token
  if (params->pubkeyhash_set && params->value_size == 0 && data_total == 68 &&
      params->data_initial_chunk_size == 68 &&
      memcmp(params->data_initial_chunk_bytes,
             "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    params->token = tokenByChainAddress(chain_id, params->pubkeyhash);
  }
}

static bool ethereum_signing_handle_nft(const struct signing_params *params,
                                        uint8_t *recipient, char *token_id,
                                        char *value) {
  // detect ERC-721/ERC1155 token
  if (params->pubkeyhash_set && params->value_size == 0 && data_total == 228 &&
      params->data_initial_chunk_size == 228 &&
      memcmp(params->data_initial_chunk_bytes,
             "\xf2\x42\x43\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    bignum256 val_token_id = {0}, val = {0};
    uint8_t pad_val[32] = {0};
    // recipient
    memcpy(recipient, params->data_initial_chunk_bytes + 48, 20);
    // toekn id
    memzero(pad_val, sizeof(pad_val));
    memcpy(pad_val, params->data_initial_chunk_bytes + 68, 32);
    bn_read_be(pad_val, &val_token_id);
    bn_format(&val_token_id, NULL, NULL, 0, 0, false, ',', token_id, 256);
    // toekn value
    memzero(pad_val, sizeof(pad_val));
    memcpy(pad_val, params->data_initial_chunk_bytes + 100, 32);
    bn_read_be(pad_val, &val);
    bn_format(&val, NULL, NULL, 0, 0, false, ',', value, 32);

    return true;
  }
  if (params->pubkeyhash_set && params->value_size == 0 && data_total == 100 &&
      params->data_initial_chunk_size == 100 &&
      memcmp(params->data_initial_chunk_bytes,
             "\x42\x84\x2e\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    bignum256 val_token_id = {0};
    uint8_t pad_val[32] = {0};
    // recipient
    memcpy(recipient, params->data_initial_chunk_bytes + 48, 20);
    // toekn id
    memzero(pad_val, sizeof(pad_val));
    memcpy(pad_val, params->data_initial_chunk_bytes + 68, 32);
    bn_read_be(pad_val, &val_token_id);
    bn_format(&val_token_id, NULL, NULL, 0, 0, false, 0, token_id, 256);
    // token value
    strcat(value, "1");

    return true;
  }

  return false;
}

static bool is_erc20_approve(const struct signing_params *params) {
  return params->pubkeyhash_set && params->value_size == 0 &&
         params->data_length == 68 &&
         ((memcmp(params->data_initial_chunk_bytes,
                  "\x09\x5e\xa7\xb3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00",  // approve
                  16) == 0) ||
          (memcmp(params->data_initial_chunk_bytes,
                  "\x39\x50\x93\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00",  // increaseAllowance
                  16) == 0));
}

static bool is_safe_approve_hash(const struct signing_params *params) {
  // detect approveHash(bytes32 hashToApprove) 0xd4d9bdcd
  if (params->pubkeyhash_set && params->value_size == 0 &&
      params->data_length == 36 &&
      memcmp(params->data_initial_chunk_bytes, "\xd4\xd9\xbd\xcd", 4) == 0) {
    return true;
  }
  return false;
}

static bool is_safe_exec_transaction(const struct signing_params *params) {
  // detect
  // execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)
  // 0x6a761202
  if (params->pubkeyhash_set && params->value_size == 0 &&
      params->data_length >= 437 &&
      memcmp(params->data_initial_chunk_bytes,
             "\x6a\x76\x12\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    return true;
  }
  return false;
}
static bool is_safe_tx(const struct signing_params *params) {
  return is_safe_approve_hash(params) || is_safe_exec_transaction(params);
}

static void detect_contract_action(const struct signing_params *params,
                                   bool *is_approve, bool *is_nft_transfer,
                                   bool *is_safe, uint8_t *recipient,
                                   char *token_id, char *token_value) {
  *is_approve = is_erc20_approve(params);
  if (*is_approve) {
    return;
  }
  *is_nft_transfer =
      ethereum_signing_handle_nft(params, recipient, token_id, token_value);
  if (*is_nft_transfer) {
    return;
  }
  *is_safe = is_safe_tx(params);
}
static bool ethereum_signing_handle_safe_tx(const struct signing_params *params,
                                            SafeTxContext *safe_tx_context,
                                            bool *is_delegate_call) {
  if (is_safe_approve_hash(params)) {
    // safe approve hash
    safe_tx_context->type = SafeTxContextType_APPROVE_HASH;
    char *data_str = malloc(67);
    if (data_str == NULL) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Failed to allocate memory");
      return false;
    }
    data_str[0] = '0';
    data_str[1] = 'x';
    data2hex(params->data_initial_chunk_bytes + 4, 32, data_str + 2);
    safe_tx_context->payload.approve_hash = data_str;
  } else {
    // safe exec transaction
    display_info_init(&display_info, 14);
    const uint8_t *data = params->data_initial_chunk_bytes + 16;
    display_info_add_item_name(&display_info, "to", 0);
    uint8_t to[20];
    memcpy(to, data, 20);
    char *to_str = decode_typed_data(to, 20, "address");
    display_info_set_value(&display_info, to_str);
    free(to_str);
    display_info_add_item_name(&display_info, "value", 0);
    char *value_str = decode_typed_data(data + 20, 32, "uint");
    display_info_set_value(&display_info, value_str);
    free(value_str);
    // display_info_add_item_name(&display_info, "operation", 0);
    uint8_t operation = data[105];
    char operation_str[16];
    if (operation == 0) {
      strcpy(operation_str, "0(Call)");
    } else if (operation == 1) {
      strcpy(operation_str, "1(DelegateCall)");
      *is_delegate_call = true;
    }
    char *safe_tx_gas_str = decode_typed_data(data + 116, 32, "uint");
    char *base_gas_str = decode_typed_data(data + 148, 32, "uint");
    char *gas_price_str = decode_typed_data(data + 180, 32, "uint");
    char *gas_token_str = decode_typed_data(data + 224, 20, "address");
    char *refund_receiver_str = decode_typed_data(data + 256, 20, "address");
    uint32_t signature_pos = 0;
    for (uint8_t i = 0; i < 32; i++) {
      signature_pos = (signature_pos << 8) | data[276 + i];
    }
    uint32_t data_len = 0;
    for (uint8_t i = 0; i < 32; i++) {
      data_len = (data_len << 8) | data[308 + i];
    }
    data_left = params->data_length - params->data_initial_chunk_size;
    if (data_left > 0) {
      data_left_bytes = (uint8_t *)malloc(data_left);
      if (data_left_bytes == NULL) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Failed to allocate memory");
        return false;
      }
      uint32_t data_left_pos = 0;
      while (data_left > 0) {
        msg_tx_request.has_data_length = true;
        msg_tx_request.data_length = data_left <= 1024 ? data_left : 1024;
        void *response_ptr =
            call(MessageType_MessageType_EthereumTxRequestOneKey,
                 &msg_tx_request, MessageType_MessageType_EthereumTxAckOneKey);
        if (response_ptr == NULL) {
          free(data_left_bytes);
          data_left_bytes = NULL;
          display_info_cleanup(&display_info);
          fsm_sendFailure(FailureType_Failure_DataError, "Invalid call data");
          return false;
        }
        EthereumTxAckOneKey resp = *(EthereumTxAckOneKey *)response_ptr;
        memcpy(data_left_bytes + data_left_pos, resp.data_chunk.bytes,
               resp.data_chunk.size);
        data_left_pos += resp.data_chunk.size;
        data_left -= resp.data_chunk.size;
      }
    }
    if (data_len > 0 && data_left == 0) {
      const uint8_t *nest_data = data + 340;
      display_info_add_item_name(&display_info, "data", 0);
      if (data_len == 68 && memcmp(nest_data,
                                   "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00\x00\x00",
                                   16) == 0) {
        // erc20 transfer
        const TokenType *token = tokenByChainAddress(params->chain_id, to);
        display_info_set_value(&display_info, "Transfer");
        display_info_add_item_name(&display_info, "[Recipient]", 4);
        char *recipient_str = decode_typed_data(nest_data + 16, 20, "address");
        display_info_set_value(&display_info, recipient_str);
        free(recipient_str);
        display_info_add_item_name(&display_info, "[Amount]", 4);
        bignum256 amount = {0};
        bn_read_be(nest_data + 36, &amount);
        char amount_str[64] = {0};
        ethereumFormatAmount(&amount, token, amount_str, sizeof(amount_str));
        display_info_set_value(&display_info, amount_str);
      } else if ((data_len == 196 || data_len == 228) &&
                 memcmp(nest_data,
                        "\xf2\x42\x43\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00",
                        16) == 0) {
        // erc1155 safeTransferFrom
        display_info_set_value(&display_info, "Transfer");
        display_info_add_item_name(&display_info, "[From]", 4);
        char *from_str = decode_typed_data(nest_data + 16, 20, "address");
        display_info_set_value(&display_info, from_str);
        free(from_str);
        display_info_add_item_name(&display_info, "[Recipient]", 4);
        char *recipient_str = decode_typed_data(nest_data + 48, 20, "address");
        display_info_set_value(&display_info, recipient_str);
        free(recipient_str);
        display_info_add_item_name(&display_info, "[Token ID]", 4);
        char *token_id_str = decode_typed_data(nest_data + 68, 32, "uint");
        display_info_set_value(&display_info, token_id_str);
        free(token_id_str);
        display_info_add_item_name(&display_info, "[Amount]", 4);
        char *amount_str = decode_typed_data(nest_data + 100, 32, "uint");
        display_info_set_value(&display_info, amount_str);
        free(amount_str);
      } else if (data_len >= 100 && memcmp(nest_data,
                                           "\x42\x84\x2e\x0e\x00\x00\x00\x00"
                                           "\x00\x00\x00\x00\x00\x00\x00\x00",
                                           16) == 0) {
        // erc721 safeTransferFrom
        display_info_set_value(&display_info, "Transfer");
        display_info_add_item_name(&display_info, "[From]", 4);
        char *from_str = decode_typed_data(nest_data + 16, 20, "address");
        display_info_set_value(&display_info, from_str);
        free(from_str);
        display_info_add_item_name(&display_info, "[Recipient]", 4);
        char *recipient_str = decode_typed_data(nest_data + 48, 20, "address");
        display_info_set_value(&display_info, recipient_str);
        free(recipient_str);
        display_info_add_item_name(&display_info, "[Token ID]", 4);
        char *token_id_str = decode_typed_data(nest_data + 68, 32, "uint");
        display_info_set_value(&display_info, token_id_str);
        free(token_id_str);
      } else if (data_len == 68 && memcmp(nest_data,
                                          "\x09\x5e\xa7\xb3\x00\x00\x00\x00\x00"
                                          "\x00\x00\x00\x00\x00\x00\x00",
                                          16) == 0) {
        // erc20/erc721 approve
        display_info_set_value(&display_info, "Approve");
        display_info_add_item_name(&display_info, "[Spender]", 4);
        char *spender_str = decode_typed_data(nest_data + 16, 20, "address");
        display_info_set_value(&display_info, spender_str);
        free(spender_str);
        display_info_add_item_name(&display_info, "[Amount/ID]", 4);
        char *amount_id_str = decode_typed_data(nest_data + 36, 32, "uint");
        display_info_set_value(&display_info, amount_id_str);
        free(amount_id_str);
      } else {
        char *data_str = decode_typed_data(nest_data, data_len, "bytes");
        display_info_set_value(&display_info, data_str);
        free(data_str);
      }
    }
    if (signature_pos < 340 + data_len) {
      if (data_left_bytes != NULL) {
        free(data_left_bytes);
        free(safe_tx_gas_str);
        free(base_gas_str);
        free(gas_price_str);
        free(gas_token_str);
        free(refund_receiver_str);
        data_left_bytes = NULL;
      }
      display_info_cleanup(&display_info);
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid call data");
      return false;
    }
    display_info_add_item_name(&display_info, "operation", 0);
    display_info_set_value(&display_info, operation_str);
    display_info_add_item_name(&display_info, "safeTxGas", 0);
    display_info_set_value(&display_info, safe_tx_gas_str);
    free(safe_tx_gas_str);
    display_info_add_item_name(&display_info, "baseGas", 0);
    display_info_set_value(&display_info, base_gas_str);
    free(base_gas_str);
    display_info_add_item_name(&display_info, "gasPrice", 0);
    display_info_set_value(&display_info, gas_price_str);
    free(gas_price_str);
    display_info_add_item_name(&display_info, "gasToken", 0);
    display_info_set_value(&display_info, gas_token_str);
    free(gas_token_str);
    display_info_add_item_name(&display_info, "refundReceiver", 0);
    display_info_set_value(&display_info, refund_receiver_str);
    free(refund_receiver_str);
    uint8_t *signature_data = NULL;
    uint8_t *remaining_data = NULL;
    if (data_left_bytes != NULL) {
      remaining_data = (uint8_t *)malloc(params->data_length - 340);
      if (remaining_data == NULL) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Failed to allocate memory");
        return false;
      }
      memcpy(remaining_data, data + 340, 1024 - 340);
      memcpy(remaining_data + 1024 - 340, data_left_bytes, data_left);
      signature_data = remaining_data + (signature_pos - 340);
    } else {
      signature_data = (uint8_t *)(data + signature_pos);
    }
    uint32_t signatures_len = 0;
    for (uint8_t i = 0; i < 20; i++) {
      signatures_len = (signatures_len << 8) | signature_data[i];
    }
    display_info_add_item_name(&display_info, "signatures", 0);
    char *signatures_str =
        decode_typed_data(signature_data + 20, signatures_len, "bytes");
    display_info_set_value(&display_info, signatures_str);
    free(signatures_str);
    if (data_left_bytes != NULL) {
      free(remaining_data);
    }
    safe_tx_context->type = SafeTxContextType_EXEC;
    safe_tx_context->payload.display_info = &display_info;
  }
  return true;
}

static bool ethereum_signing_safe_tx(
    const struct signing_params *params, const char *signer,
    const uint8_t *gas_price, uint32_t gas_price_len, const uint8_t *gas_limit,
    uint32_t gas_limit_len, const uint8_t *nonce, uint32_t nonce_len,
    const uint8_t *max_fee_per_gas, uint32_t max_fee_per_gas_len,
    const uint8_t *max_priority_fee_per_gas,
    uint32_t max_priority_fee_per_gas_len) {
  SafeTxContext safe_tx_context = {0};
  bool is_delegate_call = false;
  if (!ethereum_signing_handle_safe_tx(params, &safe_tx_context,
                                       &is_delegate_call)) {
    if (safe_tx_context.payload.approve_hash != NULL) {
      free(safe_tx_context.payload.approve_hash);
      safe_tx_context.payload.approve_hash = NULL;
    }
    return false;
  }
  char max_fee_per_gas_str[32] = {0};
  char priority_fee_per_gas_str[32] = {0};
  char max_fee_str[32] = {0};
  char nonce_str[32] = {0};
  if (max_fee_per_gas != NULL) {
    fillEthereumFee(max_fee_per_gas, max_fee_per_gas_len, NULL, 0,
                    max_fee_per_gas_str);
    fillEthereumFee(max_priority_fee_per_gas, max_priority_fee_per_gas_len,
                    NULL, 0, priority_fee_per_gas_str);
    fillEthereumFee(gas_limit, gas_limit_len, max_fee_per_gas,
                    max_fee_per_gas_len, max_fee_str);
  } else {
    fillEthereumFee(gas_limit, gas_limit_len, gas_price, gas_price_len,
                    max_fee_str);
  }
  char *nonce_ptr = decode_typed_data(nonce, nonce_len, "uint");
  memcpy(nonce_str, nonce_ptr, strlen(nonce_ptr));
  free(nonce_ptr);
  bool result = false;
  if (safe_tx_context.type == SafeTxContextType_APPROVE_HASH) {
    result = layoutEthereumConfirmApproveHash(
        params, signer, params->pubkeyhash, max_fee_str,
        safe_tx_context.payload.approve_hash, nonce_str,
        max_fee_per_gas != NULL ? max_fee_per_gas_str : NULL,
        max_priority_fee_per_gas != NULL ? priority_fee_per_gas_str : NULL);
    free(safe_tx_context.payload.approve_hash);
    safe_tx_context.payload.approve_hash = NULL;
  } else if (safe_tx_context.type == SafeTxContextType_EXEC) {
    result = layoutEthereumConfirmExecTx(
        params, signer, params->pubkeyhash, is_delegate_call, max_fee_str,
        safe_tx_context.payload.display_info, nonce_str,
        max_fee_per_gas != NULL ? max_fee_per_gas_str : NULL,
        max_priority_fee_per_gas != NULL ? priority_fee_per_gas_str : NULL);
    safe_tx_context.payload.display_info = NULL;
  }
  return result;
}

static bool ethereum_signing_confirm_approve(
    const struct signing_params *params, const char *signer,
    const uint8_t *gas_price, uint32_t gas_price_len, const uint8_t *gas_limit,
    uint32_t gas_limit_len, const uint8_t *nonce, uint32_t nonce_len,
    const uint8_t *max_fee_per_gas, uint32_t max_fee_per_gas_len,
    const uint8_t *max_priority_fee_per_gas,
    uint32_t max_priority_fee_per_gas_len) {
  const TokenType *token =
      tokenByChainAddress(params->chain_id, params->pubkeyhash);
  const EthereumApprover *approver = ethereum_approver_by_chain_address(
      params->chain_id, params->data_initial_chunk_bytes + 16);
  const char *provider_name = approver ? approver->name : NULL;
  char spender_str[52] = "____________";
  char token_address_str[52] = "____________";
  bool rskip60 = false;
  switch (params->chain_id) {
    case 30:
    case 31:
      rskip60 = true;
      break;
  }
  ethereum_address_checksum(params->data_initial_chunk_bytes + 16, spender_str,
                            rskip60, params->chain_id);
  ethereum_address_checksum(params->pubkeyhash, token_address_str, rskip60,
                            params->chain_id);
  bignum256 amount = {0};
  bn_read_be(params->data_initial_chunk_bytes + 36, &amount);
  bignum256 bn_max_value = {0};
  bignum256 one = {0};
  bn_one(&one);
  bn_setbit(&bn_max_value, 256);
  bn_subtract(&bn_max_value, &one, &bn_max_value);
  bool is_unlimited = false;
  bool is_revoke = false;
  char overview_text[256] = {0};
  const char *token_name = token == UnknownToken ? "UNKN" : token->ticker;
  if (bn_is_zero(&amount)) {
    is_revoke = true;
    strcat(overview_text, _(I_REVOKE_TOKEN));
    bracket_replace(overview_text, token_name);
    if (provider_name != NULL) {
      strcat(overview_text, " ");
      strcat(overview_text, _(I_AUTHORIZATION_PROVIDER));
      bracket_replace(overview_text, provider_name);
    }
  } else if (bn_is_equal(&amount, &bn_max_value)) {
    is_unlimited = true;
    strcat(overview_text, _(I_APPROVE_UNLIMITED_TOKEN));
    bracket_replace(overview_text, token_name);
    if (provider_name != NULL) {
      strcat(overview_text, " ");
      strcat(overview_text, _(I_AUTHORIZATION_PROVIDER));
      bracket_replace(overview_text, provider_name);
    }
  } else {
    char amount_str[64] = {0};
    ethereumFormatAmount(&amount, token, amount_str, sizeof(amount_str));
    strcat(overview_text, _(I_APPROVE_TOKEN));
    bracket_replace(overview_text, amount_str);
    if (provider_name != NULL) {
      strcat(overview_text, " ");
      strcat(overview_text, _(I_AUTHORIZATION_PROVIDER));
      bracket_replace(overview_text, provider_name);
    }
  }
  char max_fee_per_gas_str[32] = {0};
  char priority_fee_per_gas_str[32] = {0};
  char max_fee_str[32] = {0};
  char nonce_str[32] = {0};
  if (max_fee_per_gas != NULL) {
    fillEthereumFee(max_fee_per_gas, max_fee_per_gas_len, NULL, 0,
                    max_fee_per_gas_str);
    fillEthereumFee(max_priority_fee_per_gas, max_priority_fee_per_gas_len,
                    NULL, 0, priority_fee_per_gas_str);
    fillEthereumFee(gas_limit, gas_limit_len, max_fee_per_gas,
                    max_fee_per_gas_len, max_fee_str);
  } else {
    fillEthereumFee(gas_limit, gas_limit_len, gas_price, gas_price_len,
                    max_fee_str);
  }
  char *nonce_ptr = decode_typed_data(nonce, nonce_len, "uint");
  memcpy(nonce_str, nonce_ptr, strlen(nonce_ptr));
  free(nonce_ptr);
  char chain_id_str[21] = {0};
  snprintf(chain_id_str, sizeof(chain_id_str), "%" PRIu32,
           (uint32_t)params->chain_id);
  const char *chain_name = NULL;
  ASSIGN_ETHEREUM_NAME(chain_name, params->chain_id);
  return layoutEthereumConfirmERC20Approve(
      chain_name, token_address_str, signer, spender_str, is_unlimited,
      is_revoke, overview_text, nonce_str, max_fee_str,
      max_fee_per_gas != NULL ? max_fee_per_gas_str : NULL,
      max_priority_fee_per_gas != NULL ? priority_fee_per_gas_str : NULL,
      chain_id_str);
}
static bool ethereum_signing_confirm_common(
    const struct signing_params *params, const char *signer,
    const uint8_t *gas_price, uint32_t gas_price_len, const uint8_t *gas_limit,
    uint32_t gas_limit_len, bool is_eip1559, bool is_nft_transfer,
    const uint8_t *recipient, char *token_id, char *token_amount,
    const char *key1, const char *value1, const char *key2, const char *value2,
    const char *key3, const char *value3) {
  const uint8_t *to_addr = params->token
                               ? (params->data_initial_chunk_bytes + 16)
                               : params->pubkeyhash;
  const uint8_t *amount_data = params->token
                                   ? (params->data_initial_chunk_bytes + 36)
                                   : params->value_bytes;
  uint32_t to_size = 20;
  uint32_t amount_size = params->token ? 32 : params->value_size;

  return layoutEthereumConfirmTx(
      params, signer, to_addr, to_size, amount_data, amount_size, params->token,
      gas_price, gas_price_len, gas_limit, gas_limit_len, is_eip1559,
      is_nft_transfer, recipient, token_id, token_amount, key1, value1, key2,
      value2, key3, value3);
}

void ethereum_signing_init_onekey(const EthereumSignTxOneKey *msg,
                                  const HDNode *node) {
  struct signing_params params = {
      .chain_id = msg->chain_id,

      .data_length = msg->data_length,
      .data_initial_chunk_size = msg->data_initial_chunk.size,
      .data_initial_chunk_bytes = msg->data_initial_chunk.bytes,

      .has_to = msg->has_to,
      .to = msg->to,

      .value_size = msg->value.size,
      .value_bytes = msg->value.bytes,
  };

  eip1559 = false;
  eip7702 = false;
  if (!ethereum_signing_init_common(&params)) {
    ethereum_signing_abort_onekey();
    return;
  }

  // sanity check that fee doesn't overflow
  if (msg->gas_price.size + msg->gas_limit.size > 30) {
    fsm_sendFailure(FailureType_Failure_DataError, "Safety check failed");
    ethereum_signing_abort_onekey();
    return;
  }

  uint32_t tx_type = 0;
  /* Wanchain txtype */
  if (msg->has_tx_type) {
    if (msg->tx_type == 1 || msg->tx_type == 6) {
      tx_type = msg->tx_type;
    } else {
      fsm_sendFailure(FailureType_Failure_DataError, "Txtype out of bounds");
      ethereum_signing_abort_onekey();
      return;
    }
  }

  bool is_nft_transfer = false;
  bool is_safe = false;
  bool is_approve = false;
  char token_id[256] = {0}, token_value[32] = {0};
  uint8_t recipient[20];
  ethereum_signing_handle_erc20(&params);
  if (params.token == NULL) {
    detect_contract_action(&params, &is_approve, &is_nft_transfer, &is_safe,
                           recipient, token_id, token_value);
  }
  // signer address
  uint8_t signerhash[20];
  char signer[52] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, signerhash)) {
    fsm_sendFailure(FailureType_Failure_DataError, NULL);
    ethereum_signing_abort_onekey();
    return;
  }
  uint32_t slip44 =
      (msg->address_n_count > 1) ? (msg->address_n[1] & 0x7fffffff) : 0;
  bool rskip60 = false;
  uint64_t chainid = 0;
  // constants from trezor-common/defs/ethereum/networks.json
  switch (slip44) {
    case 137:
      rskip60 = true;
      chainid = 30;
      break;
    case 37310:
      rskip60 = true;
      chainid = 31;
      break;
  }

  ethereum_address_checksum(signerhash, signer, rskip60, chainid);
  if (!is_safe) {
    if (is_approve) {
      if (!ethereum_signing_confirm_approve(
              &params, signer, msg->gas_price.bytes, msg->gas_price.size,
              msg->gas_limit.bytes, msg->gas_limit.size, msg->nonce.bytes,
              msg->nonce.size, NULL, 0, NULL, 0)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        ethereum_signing_abort_onekey();
        return;
      }
    } else {
      if (!ethereum_signing_confirm_common(
              &params, signer, msg->gas_price.bytes, msg->gas_price.size,
              msg->gas_limit.bytes, msg->gas_limit.size, false, is_nft_transfer,
              recipient, token_id, token_value, NULL, NULL, NULL, NULL, NULL,
              NULL)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        ethereum_signing_abort_onekey();
        return;
      }
    }
  }

  /* Stage 1: Calculate total RLP length */
  uint32_t rlp_length = 0;

  layoutProgressAdapter(_(C__SIGNING), 0);

  rlp_length += rlp_calculate_length(msg->nonce.size, msg->nonce.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->gas_price.size, msg->gas_price.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->gas_limit.size, msg->gas_limit.bytes[0]);
  rlp_length += rlp_calculate_length(params.pubkeyhash_set ? 20 : 0,
                                     params.pubkeyhash[0]);
  rlp_length += rlp_calculate_length(params.value_size, params.value_bytes[0]);
  rlp_length +=
      rlp_calculate_length(data_total, params.data_initial_chunk_bytes[0]);
  if (tx_type) {
    rlp_length += rlp_calculate_number_length(tx_type);
  }
  rlp_length += rlp_calculate_number_length(chain_id);
  rlp_length += rlp_calculate_length(0, 0);
  rlp_length += rlp_calculate_length(0, 0);

  /* Stage 2: Store header fields */
  hash_rlp_list_length(rlp_length);

  layoutProgressAdapter(_(C__SIGNING), 100);

  if (tx_type) {
    hash_rlp_number(tx_type);
  }
  hash_rlp_field(msg->nonce.bytes, msg->nonce.size);
  hash_rlp_field(msg->gas_price.bytes, msg->gas_price.size);
  hash_rlp_field(msg->gas_limit.bytes, msg->gas_limit.size);
  hash_rlp_field(params.pubkeyhash, params.pubkeyhash_set ? 20 : 0);
  hash_rlp_field(params.value_bytes, params.value_size);
  hash_rlp_length(data_total, params.data_initial_chunk_bytes[0]);
  hash_data(params.data_initial_chunk_bytes, params.data_initial_chunk_size);
  data_left = data_total - params.data_initial_chunk_size;

  _node = (HDNode *)node;
#if EMULATOR
  memcpy(privkey, node->private_key, 32);
#endif
  if (is_safe) {
    bool result = ethereum_signing_safe_tx(
        &params, signer, msg->gas_price.bytes, msg->gas_price.size,
        msg->gas_limit.bytes, msg->gas_limit.size, msg->nonce.bytes,
        msg->nonce.size, NULL, 0, NULL, 0);
    display_info_cleanup(&display_info);
    if (!result) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      ethereum_signing_abort_onekey();
      return;
    }
  }
  if (data_left > 0 && data_left_bytes == NULL) {
    send_request_chunk();
  } else {
    if (data_left_bytes != NULL) {
      hash_data(data_left_bytes, data_left);
      free(data_left_bytes);
      data_left_bytes = NULL;
    }
    send_signature();
  }
}

void ethereum_signing_init_eip1559_onekey(
    const EthereumSignTxEIP1559OneKey *msg, const HDNode *node) {
  struct signing_params params = {
      .chain_id = msg->chain_id,

      .data_length = msg->data_length,
      .data_initial_chunk_size = msg->data_initial_chunk.size,
      .data_initial_chunk_bytes = msg->data_initial_chunk.bytes,

      .has_to = msg->has_to,
      .to = msg->to,

      .value_size = msg->value.size,
      .value_bytes = msg->value.bytes,
  };

  eip1559 = true;
  eip7702 = false;
  if (!ethereum_signing_init_common(&params)) {
    ethereum_signing_abort_onekey();
    return;
  }

  // sanity check that fee doesn't overflow
  if (msg->max_gas_fee.size + msg->gas_limit.size > 30 ||
      msg->max_priority_fee.size + msg->gas_limit.size > 30) {
    fsm_sendFailure(FailureType_Failure_DataError, "Safety check failed");
    ethereum_signing_abort_onekey();
    return;
  }

  bool is_nft_transfer = false;
  bool is_safe = false;
  bool is_approve = false;
  char token_id[256] = {0}, token_value[32] = {0};
  uint8_t recipient[20];
  ethereum_signing_handle_erc20(&params);
  if (params.token == NULL) {
    detect_contract_action(&params, &is_approve, &is_nft_transfer, &is_safe,
                           recipient, token_id, token_value);
  }

  // signer address
  uint8_t signerhash[20];
  char signer[52] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, signerhash)) {
    fsm_sendFailure(FailureType_Failure_DataError, NULL);
    ethereum_signing_abort_onekey();
    return;
  }
  uint32_t slip44 =
      (msg->address_n_count > 1) ? (msg->address_n[1] & 0x7fffffff) : 0;
  bool rskip60 = false;
  uint64_t chainid = 0;
  // constants from trezor-common/defs/ethereum/networks.json
  switch (slip44) {
    case 137:
      rskip60 = true;
      chainid = 30;
      break;
    case 37310:
      rskip60 = true;
      chainid = 31;
      break;
  }

  ethereum_address_checksum(signerhash, signer, rskip60, chainid);

  if (!is_safe) {
    if (is_approve) {
      if (!ethereum_signing_confirm_approve(
              &params, signer, NULL, 0, msg->gas_limit.bytes,
              msg->gas_limit.size, msg->nonce.bytes, msg->nonce.size,
              msg->max_gas_fee.bytes, msg->max_gas_fee.size,
              msg->max_priority_fee.bytes, msg->max_priority_fee.size)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        ethereum_signing_abort_onekey();
        return;
      }
    } else {
      char max_fee_per_gas_str[32] = {0};
      char priority_fee_per_gas_str[32] = {0};
      char max_fee_str[32] = {0};
      fillEthereumFee(msg->max_gas_fee.bytes, msg->max_gas_fee.size, NULL, 0,
                      max_fee_per_gas_str);
      fillEthereumFee(msg->max_priority_fee.bytes, msg->max_priority_fee.size,
                      NULL, 0, priority_fee_per_gas_str);
      fillEthereumFee(msg->gas_limit.bytes, msg->gas_limit.size,
                      msg->max_gas_fee.bytes, msg->max_gas_fee.size,
                      max_fee_str);
      if (!ethereum_signing_confirm_common(
              &params, signer, msg->max_gas_fee.bytes, msg->max_gas_fee.size,
              msg->gas_limit.bytes, msg->gas_limit.size, true, is_nft_transfer,
              recipient, token_id, token_value, _(I__ETH_MAXIMUM_FEE_COLON),
              max_fee_str, _(I__MAXIMUM_FEE_PER_GAS_COLON), max_fee_per_gas_str,
              _(I__PRIORITY_FEE_PER_GAS_COLON), priority_fee_per_gas_str)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        ethereum_signing_abort_onekey();
        return;
      }
    }
  }

  /* Stage 1: Calculate total RLP length */
  uint32_t rlp_length = 0;

  layoutProgressAdapter(_(C__SIGNING), 0);

  rlp_length += rlp_calculate_number_length(chain_id);
  rlp_length += rlp_calculate_length(msg->nonce.size, msg->nonce.bytes[0]);
  rlp_length += rlp_calculate_length(msg->max_priority_fee.size,
                                     msg->max_priority_fee.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->max_gas_fee.size, msg->max_gas_fee.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->gas_limit.size, msg->gas_limit.bytes[0]);
  rlp_length += rlp_calculate_length(params.pubkeyhash_set ? 20 : 0,
                                     params.pubkeyhash[0]);
  rlp_length += rlp_calculate_length(params.value_size, params.value_bytes[0]);
  rlp_length +=
      rlp_calculate_length(data_total, params.data_initial_chunk_bytes[0]);

  rlp_length +=
      rlp_calculate_length(rlp_calculate_access_list_length(
                               msg->access_list, msg->access_list_count),
                           0xff);

  /* Stage 2: Store header fields */
  hash_rlp_number(EIP1559_TX_TYPE);
  hash_rlp_list_length(rlp_length);

  layoutProgressAdapter(_(C__SIGNING), 100);

  hash_rlp_number(chain_id);
  hash_rlp_field(msg->nonce.bytes, msg->nonce.size);
  hash_rlp_field(msg->max_priority_fee.bytes, msg->max_priority_fee.size);
  hash_rlp_field(msg->max_gas_fee.bytes, msg->max_gas_fee.size);
  hash_rlp_field(msg->gas_limit.bytes, msg->gas_limit.size);
  hash_rlp_field(params.pubkeyhash, params.pubkeyhash_set ? 20 : 0);
  hash_rlp_field(params.value_bytes, params.value_size);
  hash_rlp_length(data_total, params.data_initial_chunk_bytes[0]);
  hash_data(params.data_initial_chunk_bytes, params.data_initial_chunk_size);
  data_left = data_total - params.data_initial_chunk_size;

  /* make a copy of access_list, hash it after data is processed */
  memcpy(signing_access_list, msg->access_list, sizeof(signing_access_list));
  signing_access_list_count = msg->access_list_count;

  _node = (HDNode *)node;
#if EMULATOR
  memcpy(privkey, node->private_key, 32);
#endif
  if (is_safe) {
    bool result = ethereum_signing_safe_tx(
        &params, signer, NULL, 0, msg->gas_limit.bytes, msg->gas_limit.size,
        msg->nonce.bytes, msg->nonce.size, msg->max_gas_fee.bytes,
        msg->max_gas_fee.size, msg->max_priority_fee.bytes,
        msg->max_priority_fee.size);
    display_info_cleanup(&display_info);
    if (!result) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      ethereum_signing_abort_onekey();
      return;
    }
  }
  if (data_left > 0 && data_left_bytes == NULL) {
    send_request_chunk();
  } else {
    if (data_left_bytes != NULL) {
      hash_data(data_left_bytes, data_left);
      free(data_left_bytes);
      data_left_bytes = NULL;
    }
    send_signature();
  }
}

static uint64_t ethereum_bytes_to_uint64(const uint8_t *bytes, size_t size) {
  uint64_t result = 0;
  for (size_t i = 0; i < size; i++) {
    result = (result << 8) | bytes[i];
  }
  return result;
}

static bool ethereum_check_authorization_list(
    const struct signing_params *params,
    const EthereumAuthorizationOneKey *authorization_list,
    uint32_t authorization_list_count, uint64_t nonce) {
  for (size_t i = 0; i < authorization_list_count; i++) {
    const EthereumAuthorizationOneKey *cur_authorization =
        &authorization_list[i];
    if (cur_authorization->chain_id != 0 &&
        cur_authorization->chain_id != chain_id) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Authorization chain ID invalid");
      return false;
    }
    if (strlen(cur_authorization->address) != 42) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Authorization address invalid, should start with 0x");
      return false;
    }
    // check if the delegator is registered
    uint8_t delegator_address[20] = {0};
    if (ethereum_parse_onekey(cur_authorization->address, delegator_address)) {
      if (!is_registered_delegator(chain_id, delegator_address)) {
        layoutDialogCenterAdapterV2(
            NULL, &bmp_icon_warning, &bmp_bottom_left_close,
            &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
            _(I_NOT_IN_SMART_ACCOUNT_WHITELIST));
        protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false);
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Unregistered delegator address");
        return false;
      }
      const Delegator *delegator =
          get_delegator_by_address(chain_id, delegator_address);
      if (delegator->initial_data_size != params->data_initial_chunk_size) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Invalid initial calldata size");
        return false;
      }
      if (memcmp(delegator->initial_data, params->data_initial_chunk_bytes,
                 params->data_initial_chunk_size) != 0) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Invalid initial calldata");
        return false;
      }
    } else {
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid address format");
      return false;
    }
    if (cur_authorization->nonce.size > 8) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Authorization nonce invalid");
      return false;
    }
    if (cur_authorization->has_signature &&
        cur_authorization->address_n_count > 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Authorization list item has both signature and address");
      return false;
    } else if (cur_authorization->has_signature) {
      if (cur_authorization->signature.y_parity >= 256) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Authorization signature v invalid");
        return false;
      }
      if (cur_authorization->signature.r.size != 32) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Authorization signature r invalid");
        return false;
      }
      if (cur_authorization->signature.s.size != 32) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Authorization signature s invalid");
        return false;
      }
    } else {
      if (cur_authorization->address_n_count == 0) {
        uint64_t authority_nonce = ethereum_bytes_to_uint64(
            cur_authorization->nonce.bytes, cur_authorization->nonce.size);
        if (authority_nonce != nonce + 1) {
          fsm_sendFailure(FailureType_Failure_DataError,
                          "Authorization nonce invalid");
          return false;
        }
      }
    }
  }
  return true;
}

void ethereum_signing_init_eip7702_onekey(
    const EthereumSignTxEIP7702OneKey *msg, const HDNode *node) {
  struct signing_params params = {
      .chain_id = msg->chain_id,
      .data_length = msg->data_length,
      .data_initial_chunk_size = msg->data_initial_chunk.size,
      .data_initial_chunk_bytes = msg->data_initial_chunk.bytes,
      .has_to = true,
      .to = msg->to,
      .value_size = msg->value.size,
      .value_bytes = msg->value.bytes,
  };

  eip7702 = true;
  eip1559 = false;
  if (!ethereum_signing_init_common(&params)) {
    ethereum_signing_abort_onekey();
    return;
  }

  // sanity check that fee doesn't overflow
  if (msg->max_gas_fee.size + msg->gas_limit.size > 30 ||
      msg->max_priority_fee.size + msg->gas_limit.size > 30) {
    fsm_sendFailure(FailureType_Failure_DataError, "Safety check failed");
    ethereum_signing_abort_onekey();
    return;
  }
  // eip7702 recipient address can not be empty
  if (strlen(msg->to) == 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "Address can not be empty");
    ethereum_signing_abort_onekey();
    return;
  }
  params.pubkeyhash_set = true;
  if (!ethereum_parse_onekey(msg->to, params.pubkeyhash)) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid recipient address format");
    ethereum_signing_abort_onekey();
    return;
  }
  if (msg->authorization_list_count == 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Authorization list is empty");
    ethereum_signing_abort_onekey();
    return;
  }
  // eip7702 only support self-sponsoring transaction now temporarily
  if (msg->authorization_list_count > 1) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Only support Self-sponsoring transaction now");
    ethereum_signing_abort_onekey();
    return;
  }
  // authorization list check
  uint64_t nonce = ethereum_bytes_to_uint64(msg->nonce.bytes, msg->nonce.size);
  if (!ethereum_check_authorization_list(&params, msg->authorization_list,
                                         msg->authorization_list_count,
                                         nonce)) {
    ethereum_signing_abort_onekey();
    return;
  }
  // signer address
  uint8_t signerhash[20];
  char signer[52] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, signerhash)) {
    fsm_sendFailure(FailureType_Failure_DataError, NULL);
    ethereum_signing_abort_onekey();
    return;
  }
  uint32_t slip44 =
      (msg->address_n_count > 1) ? (msg->address_n[1] & 0x7fffffff) : 0;
  bool rskip60 = false;
  uint64_t chainid = 0;
  // constants from trezor-common/defs/ethereum/networks.json
  switch (slip44) {
    case 137:
      rskip60 = true;
      chainid = 30;
      break;
    case 37310:
      rskip60 = true;
      chainid = 31;
      break;
  }

  ethereum_address_checksum(signerhash, signer, rskip60, chainid);

  char max_fee_per_gas_str[32] = {0};
  char priority_fee_per_gas_str[32] = {0};
  char max_fee_str[32] = {0};
  fillEthereumFee(msg->max_gas_fee.bytes, msg->max_gas_fee.size, NULL, 0,
                  max_fee_per_gas_str);
  fillEthereumFee(msg->max_priority_fee.bytes, msg->max_priority_fee.size, NULL,
                  0, priority_fee_per_gas_str);
  fillEthereumFee(msg->gas_limit.bytes, msg->gas_limit.size,
                  msg->max_gas_fee.bytes, msg->max_gas_fee.size, max_fee_str);
  char nonce_str[11] = {0};
  snprintf(nonce_str, sizeof(nonce_str), "%" PRIu32, (uint32_t)nonce);
  if (!layoutEthereumConfirmEIP7702(
          &params, signer, &msg->authorization_list[0], "Nonce:", nonce_str,
          _(I__ETH_MAXIMUM_FEE_COLON), max_fee_str,
          _(I__MAXIMUM_FEE_PER_GAS_COLON), max_fee_per_gas_str,
          _(I__PRIORITY_FEE_PER_GAS_COLON), priority_fee_per_gas_str)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action cancelled");
    ethereum_signing_abort_onekey();
    return;
  }
  // sign authorization list
  if (!sign_authorization_list(msg, node)) {
    ethereum_signing_abort_onekey();
    return;
  }

  /* Stage 1: Calculate total RLP length */
  uint32_t rlp_length = 0;

  layoutProgressAdapter(_(C__SIGNING), 0);

  rlp_length += rlp_calculate_number_length(msg->chain_id);
  rlp_length += rlp_calculate_length(msg->nonce.size, msg->nonce.bytes[0]);
  rlp_length += rlp_calculate_length(msg->max_priority_fee.size,
                                     msg->max_priority_fee.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->max_gas_fee.size, msg->max_gas_fee.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->gas_limit.size, msg->gas_limit.bytes[0]);
  rlp_length += rlp_calculate_length(20, 0xff);
  rlp_length += rlp_calculate_length(params.value_size, params.value_bytes[0]);
  rlp_length +=
      rlp_calculate_length(data_total, params.data_initial_chunk_bytes[0]);

  rlp_length +=
      rlp_calculate_length(rlp_calculate_access_list_length(
                               msg->access_list, msg->access_list_count),
                           0xff);

  rlp_length += rlp_calculate_length(
      rlp_calculate_authorization_list_length(signing_authorization_list,
                                              signing_authorization_list_count),
      0xff);

  /* Stage 2: Store header fields */
  hash_rlp_number(EIP7702_TX_TYPE);
  hash_rlp_list_length(rlp_length);

  layoutProgressAdapter(_(C__SIGNING), 100);

  hash_rlp_number(msg->chain_id);
  hash_rlp_field(msg->nonce.bytes, msg->nonce.size);
  hash_rlp_field(msg->max_priority_fee.bytes, msg->max_priority_fee.size);
  hash_rlp_field(msg->max_gas_fee.bytes, msg->max_gas_fee.size);
  hash_rlp_field(msg->gas_limit.bytes, msg->gas_limit.size);
  hash_rlp_field(params.pubkeyhash, 20);
  hash_rlp_field(params.value_bytes, params.value_size);
  hash_rlp_length(msg->data_length, params.data_initial_chunk_bytes[0]);
  hash_data(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size);
  data_left = msg->data_length - msg->data_initial_chunk.size;

  /* make a copy of access_list, hash it after data is processed */
  memcpy(signing_access_list, msg->access_list, sizeof(signing_access_list));
  signing_access_list_count = msg->access_list_count;

  _node = (HDNode *)node;
#if EMULATOR
  memcpy(privkey, node->private_key, 32);
#endif

  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void ethereum_signing_txack_onekey(const EthereumTxAckOneKey *tx) {
  if (!ethereum_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Ethereum signing mode");
    layoutHome();
    return;
  }

  if (tx->data_chunk.size > data_left) {
    fsm_sendFailure(FailureType_Failure_DataError, "Too much data");
    ethereum_signing_abort_onekey();
    return;
  }

  if (data_left > 0 && tx->data_chunk.size == 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "Empty data chunk received");
    ethereum_signing_abort_onekey();
    return;
  }

  hash_data(tx->data_chunk.bytes, tx->data_chunk.size);

  data_left -= tx->data_chunk.size;

  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void ethereum_signing_abort_onekey(void) {
  if (ethereum_signing) {
    _node = NULL;
#if EMULATOR
    memzero(privkey, sizeof(privkey));
#endif
    layoutHome();
    ethereum_signing = false;
  }
}

void ethereum_message_hash(const uint8_t *message, size_t message_len,
                           uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)"\x19" "Ethereum Signed Message:\n", 26);
  uint8_t c = 0;
  if (message_len >= 1000000000) {
    c = '0' + message_len / 1000000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000000) {
    c = '0' + message_len / 100000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000000) {
    c = '0' + message_len / 10000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000000) {
    c = '0' + message_len / 1000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000) {
    c = '0' + message_len / 100000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000) {
    c = '0' + message_len / 10000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000) {
    c = '0' + message_len / 1000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100) {
    c = '0' + message_len / 100 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10) {
    c = '0' + message_len / 10 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  c = '0' + message_len % 10;
  sha3_Update(&ctx, &c, 1);
  sha3_Update(&ctx, message, message_len);
  keccak_Final(&ctx, hash);
}

void ethereum_message_sign_onekey(const EthereumSignMessageOneKey *msg,
                                  const HDNode *node,
                                  EthereumMessageSignatureOneKey *resp) {
  uint8_t hash[32] = {0};
  ethereum_message_hash(msg->message.bytes, msg->message.size, hash);

  uint8_t v = 0;
#if EMULATOR
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
#else
  if (hdnode_sign_digest(node, hash, resp->signature.bytes, &v,
                         ethereum_is_canonic) != 0) {
#endif
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return;
  }
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumMessageSignatureOneKey, resp);
}

int ethereum_message_verify_onekey(const EthereumVerifyMessageOneKey *msg) {
  if (msg->signature.size != 65) {
    fsm_sendFailure(FailureType_Failure_DataError, "Malformed signature");
    return 1;
  }

  uint8_t pubkeyhash[20] = {0};
  if (!ethereum_parse_onekey(msg->address, pubkeyhash)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Malformed address");
    return 1;
  }

  uint8_t pubkey[65] = {0};
  uint8_t hash[32] = {0};

  ethereum_message_hash(msg->message.bytes, msg->message.size, hash);

  /* v should be 27, 28 but some implementations use 0,1.  We are
   * compatible with both.
   */
  uint8_t v = msg->signature.bytes[64];
  if (v >= 27) {
    v -= 27;
  }

  if (v >= 2) {
    return 2;
  }

  int ret = 0;
  ret = ecdsa_recover_pub_from_sig(&secp256k1, pubkey, msg->signature.bytes,
                                   hash, v);
  if (ret != 0) {
    return 2;
  }

  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, pubkey + 1, 64);
  keccak_Final(&ctx, hash);

  /* result are the least significant 160 bits */
  if (memcmp(pubkeyhash, hash + 12, 20) != 0) {
    return 2;
  }
  return 0;
}

/*
 * EIP-712 hashes might have no message_hash if primaryType="EIP712Domain".
 * In this case, set has_message_hash=false.
 */
static void ethereum_typed_hash(const uint8_t domain_separator_hash[32],
                                const uint8_t message_hash[32],
                                bool has_message_hash, uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)"\x19\x01", 2);
  sha3_Update(&ctx, domain_separator_hash, 32);
  if (has_message_hash) {
    sha3_Update(&ctx, message_hash, 32);
  }
  keccak_Final(&ctx, hash);
}

void ethereum_typed_hash_sign_onekey(const EthereumSignTypedHashOneKey *msg,
                                     const HDNode *node,
                                     EthereumTypedDataSignatureOneKey *resp) {
  uint8_t hash[32] = {0};

  ethereum_typed_hash(msg->domain_separator_hash.bytes, msg->message_hash.bytes,
                      msg->has_message_hash, hash);

  uint8_t v = 0;
#if EMULATOR
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
#else
  if (hdnode_sign_digest(node, hash, resp->signature.bytes, &v,
                         ethereum_is_canonic) != 0) {
#endif
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return;
  }
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumTypedDataSignatureOneKey, resp);
}

static bool is_string_in_list(const char *str, const char *const *list,
                              size_t list_size) {
  for (size_t i = 0; i < list_size; i++) {
    if (strcmp(str, list[i]) == 0) {
      return true;
    }
  }
  return false;
}
static bool typed_data_confirm_final(void) {
  oledClear();
  layoutHeader(_(T_CONFIRM_TYPED_DATA));
  char confirm_text[128] = {0};
  snprintf(confirm_text, 128, "%s",
           _(C__DO_YOU_WANT_TO_SIGN_THIS_CHAIN_STR_MESSAGE_QUES));
  bracket_replace(confirm_text, "EIP712");
  oledDrawStringAdapter(0, 13, confirm_text, FONT_STANDARD);
  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  oledRefresh();
  return protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false);
}
static void get_domain_separator_hash(uint64_t id,
                                      const char *verifying_contract,
                                      uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)DOMAIN_SEPARATOR_TYPEHASH,
              sizeof(DOMAIN_SEPARATOR_TYPEHASH));
  uint8_t chain_id_bytes[32] = {0};
  for (int i = 0; i < 8; i++) {
    chain_id_bytes[31 - i] = (id >> (i * 8)) & 0xFF;
  }
  sha3_Update(&ctx, (const uint8_t *)chain_id_bytes, 32);
  uint8_t pad_vc_bytes[32] = {0};
  ethereum_parse_onekey(verifying_contract, pad_vc_bytes + 12);
  sha3_Update(&ctx, (const uint8_t *)pad_vc_bytes, 32);
  keccak_Final(&ctx, hash);
}
static void get_safe_message_hash(const EthereumGnosisSafeTxAck *ack,
                                  uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)SAFE_TX_TYPEHASH,
              sizeof(SAFE_TX_TYPEHASH));

  uint8_t pad_bytes[32] = {0};

  ethereum_parse_onekey(ack->to, pad_bytes + 12);
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 32);
  memcpy(pad_bytes + (32 - ack->value.size), ack->value.bytes, ack->value.size);
  sha3_Update(&ctx, pad_bytes, 32);

  keccak_256(ack->data.bytes, ack->data.size, pad_bytes);
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 32);
  pad_bytes[31] = (uint8_t)ack->operation;
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 32);
  memcpy(pad_bytes + (32 - ack->safeTxGas.size), ack->safeTxGas.bytes,
         ack->safeTxGas.size);
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 32);
  memcpy(pad_bytes + (32 - ack->baseGas.size), ack->baseGas.bytes,
         ack->baseGas.size);
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 32);
  memcpy(pad_bytes + (32 - ack->gasPrice.size), ack->gasPrice.bytes,
         ack->gasPrice.size);
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 12);
  ethereum_parse_onekey(ack->gasToken, pad_bytes + 12);
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 12);
  ethereum_parse_onekey(ack->refundReceiver, pad_bytes + 12);
  sha3_Update(&ctx, pad_bytes, 32);

  memset(pad_bytes, 0, 32);
  memcpy(pad_bytes + (32 - ack->nonce.size), ack->nonce.bytes, ack->nonce.size);
  sha3_Update(&ctx, pad_bytes, 32);

  keccak_Final(&ctx, hash);
}
static void ethereum_gnosis_safe_tx_sign(
    const EthereumGnosisSafeTxAck *ack, const HDNode *node,
    EthereumTypedDataSignatureOneKey *resp) {
  uint8_t domian_hash[32] = {0};
  get_domain_separator_hash(ack->chain_id, ack->verifyingContract, domian_hash);
  uint8_t message_hash[32] = {0};
  get_safe_message_hash(ack, message_hash);
  uint8_t hash[32] = {0};
  ethereum_typed_hash(domian_hash, message_hash, true, hash);
  bool is_delegate_call =
      ack->operation == EthereumGnosisSafeTxOperation_DELEGATE_CALL;
  if (!layoutSafeTx(is_delegate_call, domian_hash, message_hash, hash)) {
    display_info_cleanup(&display_info);
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
  display_info_init(&display_info, 2);
  prepare_domain_items(&display_info, ack);
  if (!layoutTypedData(&display_info, TYPE_NAME_DOMAIN)) {
    display_info_cleanup(&display_info);
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
  display_info_cleanup(&display_info);
  display_info_init(&display_info, 10);
  prepare_safe_items(&display_info, ack);
  if (!layoutTypedData(&display_info, "SafeTx")) {
    display_info_cleanup(&display_info);
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
  display_info_cleanup(&display_info);
  if (!typed_data_confirm_final()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
  uint8_t v = 0;
#if EMULATOR
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
#else
  if (hdnode_sign_digest(node, hash, resp->signature.bytes, &v,
                         ethereum_is_canonic) != 0) {
#endif
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return;
  }
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumTypedDataSignatureOneKey, resp);
}
void ethereum_typed_data_sign_onekey(const EthereumSignTypedDataOneKey *msg,
                                     const HDNode *node,
                                     EthereumTypedDataSignatureOneKey *resp) {
  if (strncmp(msg->primary_type, "SafeTx", strlen("SafeTx")) == 0) {
    EthereumGnosisSafeTxRequest request = {0};
    const EthereumGnosisSafeTxAck *ack =
        call(MessageType_MessageType_EthereumGnosisSafeTxRequest, &request,
             MessageType_MessageType_EthereumGnosisSafeTxAck);
    if (ack == NULL) {
      return;
    }
    ethereum_gnosis_safe_tx_sign(ack, node, resp);
    return;
  }
  TypedDataEnvelope envelope = {0};
  TypedDataEnvelope_init(&envelope, msg->primary_type,
                         strlen(msg->primary_type), msg->metamask_v4_compat);
  if (!collect_types(&envelope)) {
    return;
  }
  bool is_permit =
      is_string_in_list(envelope.primary_type, HIGH_RISK_PRIMARY_TYPES_PERMIT,
                        sizeof(HIGH_RISK_PRIMARY_TYPES_PERMIT) /
                            sizeof(HIGH_RISK_PRIMARY_TYPES_PERMIT[0]));
  bool is_order =
      is_string_in_list(envelope.primary_type, HIGH_RISK_PRIMARY_TYPES_ORDER,
                        sizeof(HIGH_RISK_PRIMARY_TYPES_ORDER) /
                            sizeof(HIGH_RISK_PRIMARY_TYPES_ORDER[0]));
  char warning_text[128] = {0};
  snprintf(warning_text, 128, "%s", _(I_TYPED_DATA_AUTHORIZATION_WARNING));
  char *warning_type = NULL;
  if (is_permit) {
    warning_type = "Permit";
  } else if (is_order) {
    warning_type = "Order";
  } else {
    warning_type = "signTypedData";
  }
  bracket_replace(warning_text, warning_type);
  // show warning
  layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                              &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                              NULL, NULL, warning_text);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
  uint32_t member_path[] = {0};
  uint8_t member_path_len = 1;
  char parent_objects[1][64] = {TYPE_NAME_DOMAIN};
  uint8_t parent_objects_len = 1;
  uint8_t domain_separator[32] = {0};
  display_info_init(&display_info, 16);

  if (!hash_struct(&envelope, TYPE_NAME_DOMAIN, strlen(TYPE_NAME_DOMAIN),
                   member_path, member_path_len, 0, parent_objects,
                   parent_objects_len, domain_separator)) {
    display_info_cleanup(&display_info);
    return;
  }
  if (!layoutTypedData(&display_info, TYPE_NAME_DOMAIN)) {
    display_info_cleanup(&display_info);
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
  display_info_cleanup(&display_info);
  bool has_message_hash = true;
  if (strncmp(envelope.primary_type, TYPE_NAME_DOMAIN,
              strlen(TYPE_NAME_DOMAIN)) == 0) {
    has_message_hash = false;
  }
  uint8_t message_hash[32] = {0};

  if (has_message_hash) {
    member_path[0] = 1;
    memzero(parent_objects, sizeof(parent_objects));
    strncpy(parent_objects[0], envelope.primary_type,
            strlen(envelope.primary_type));
    display_info_init(&display_info, 16);
    if (!hash_struct(&envelope, envelope.primary_type,
                     strlen(envelope.primary_type), member_path,
                     member_path_len, 0, parent_objects, parent_objects_len,
                     message_hash)) {
      display_info_cleanup(&display_info);
      return;
    }
    if (!layoutTypedData(&display_info, envelope.primary_type)) {
      display_info_cleanup(&display_info);
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return;
    }
    display_info_cleanup(&display_info);
  }

  // confirm final
  if (!typed_data_confirm_final()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
  uint8_t hash[32] = {0};
  SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)"\x19\x01", 2);
  sha3_Update(&ctx, domain_separator, 32);
  if (has_message_hash) {
    sha3_Update(&ctx, message_hash, 32);
  }
  keccak_Final(&ctx, hash);
  uint8_t v = 0;
#if EMULATOR
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
#else
  if (hdnode_sign_digest(node, hash, resp->signature.bytes, &v,
                         ethereum_is_canonic) != 0) {
#endif
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return;
  }
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumTypedDataSignatureOneKey, resp);
}

bool ethereum_parse_onekey(const char *address, uint8_t pubkeyhash[20]) {
  memzero(pubkeyhash, 20);
  size_t len = strlen(address);
  if (len == 40) {
    // do nothing
  } else if (len == 42) {
    // check for "0x" prefix and strip it when required
    if (address[0] != '0') return false;
    if (address[1] != 'x' && address[1] != 'X') return false;
    address += 2;
    len -= 2;
  } else {
    return false;
  }
  for (size_t i = 0; i < len; i++) {
    if (address[i] >= '0' && address[i] <= '9') {
      pubkeyhash[i / 2] |= (address[i] - '0') << ((1 - (i % 2)) * 4);
    } else if (address[i] >= 'a' && address[i] <= 'f') {
      pubkeyhash[i / 2] |= ((address[i] - 'a') + 10) << ((1 - (i % 2)) * 4);
    } else if (address[i] >= 'A' && address[i] <= 'F') {
      pubkeyhash[i / 2] |= ((address[i] - 'A') + 10) << ((1 - (i % 2)) * 4);
    } else {
      return false;
    }
  }
  return true;
}

static bool ethereum_path_check_bip44(uint32_t address_n_count,
                                      const uint32_t *address_n,
                                      bool pubkey_export, uint64_t chain) {
  bool valid = (address_n_count >= 3);
  valid = valid && (address_n[0] == (PATH_HARDENED | 44));
  valid = valid && (address_n[1] & PATH_HARDENED);
  valid = valid && (address_n[2] & PATH_HARDENED);
  valid = valid && ((address_n[2] & PATH_UNHARDEN_MASK) <= PATH_MAX_ACCOUNT);

  uint32_t path_slip44 = address_n[1] & PATH_UNHARDEN_MASK;
  if (chain == CHAIN_ID_UNKNOWN) {
    valid = valid && (is_ethereum_slip44(path_slip44));
  } else {
    uint32_t chain_slip44 = ethereum_slip44_by_chain_id(chain);
    if (chain_slip44 == SLIP44_UNKNOWN) {
      // Allow Ethereum or testnet paths for unknown networks.
      valid = valid && (path_slip44 == 60 || path_slip44 == 1);
    } else if (chain_slip44 != 60 && chain_slip44 != 1) {
      // Allow cross-signing with Ethereum unless it's testnet.
      valid = valid && (path_slip44 == chain_slip44 || path_slip44 == 60);
    } else {
      valid = valid && (path_slip44 == chain_slip44);
    }
  }

  if (pubkey_export) {
    // m/44'/coin_type'/account'/*
    return valid;
  }

  if (address_n_count == 3) {
    // SEP-0005 for non-UTXO-based currencies, defined by Stellar:
    // https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
    // m/44'/coin_type'/account'
    return valid;
  }

  if (address_n_count == 4) {
    // Also to support "Ledger Live" legacy paths
    // https://github.com/trezor/trezor-firmware/issues/1749
    // m/44'/coin_type'/0'/account
    valid = valid && (address_n[2] == (PATH_HARDENED | 0));
    valid = valid && (address_n[3] <= PATH_MAX_ACCOUNT);
    return valid;
  }

  // We believe Ethereum should use the SEP-0005 scheme for everything,
  // because it is account-based, rather than UTXO-based. Unfortunately, a
  // lot of Ethereum tools (MEW, Metamask) do not use such scheme and set
  // account = 0 and then iterate the address index. For compatibility, we
  // allow this scheme as well.
  // m/44'/coin_type'/account'/change/address_index
  valid = valid && (address_n_count == 5);
  valid = valid && (address_n[3] <= PATH_MAX_CHANGE);
  valid = valid && (address_n[4] <= PATH_MAX_ADDRESS_INDEX);

  return valid;
}

static bool ethereum_path_check_casa45(uint32_t address_n_count,
                                       const uint32_t *address_n,
                                       uint64_t chain) {
  bool valid = (address_n_count == 5);
  valid = valid && (address_n[0] == (PATH_HARDENED | 45));
  valid = valid && (address_n[1] < PATH_HARDENED);
  valid = valid && (address_n[2] <= PATH_MAX_ACCOUNT);
  valid = valid && (address_n[3] <= PATH_MAX_CHANGE);
  valid = valid && (address_n[4] <= PATH_MAX_ADDRESS_INDEX);

  uint32_t path_slip44 = address_n[1];
  if (chain == CHAIN_ID_UNKNOWN) {
    valid = valid && (is_ethereum_slip44(path_slip44));
  } else {
    uint32_t chain_slip44 = ethereum_slip44_by_chain_id(chain);
    if (chain_slip44 == SLIP44_UNKNOWN) {
      // Allow Ethereum or testnet paths for unknown networks.
      valid = valid && (path_slip44 == 60 || path_slip44 == 1);
    } else if (chain_slip44 != 60 && chain_slip44 != 1) {
      // Allow cross-signing with Ethereum unless it's testnet.
      valid = valid && (path_slip44 == chain_slip44 || path_slip44 == 60);
    } else {
      valid = valid && (path_slip44 == chain_slip44);
    }
  }

  return valid;
}

bool ethereum_path_check_onekey(uint32_t address_n_count,
                                const uint32_t *address_n, bool pubkey_export,
                                uint64_t chain) {
  if (address_n_count == 0) {
    return false;
  }
  if (address_n[0] == (PATH_HARDENED | 44)) {
    return ethereum_path_check_bip44(address_n_count, address_n, pubkey_export,
                                     chain);
  }
  if (address_n[0] == (PATH_HARDENED | 45)) {
    return ethereum_path_check_casa45(address_n_count, address_n, chain);
  }
  return false;
}
