#include "scdo.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../legacy/util.h"
#include "address.h"
#include "bignum.h"
#include "crypto.h"
#include "ecdsa.h"
#include "ethereum.h"
#include "ethereum_networks.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "scdo_tokens.h"
#include "secp256k1.h"
#include "sha3.h"
#include "transaction.h"
#include "util.h"

#define SCDO_CHAIN_ID 541

static bool scdo_signing = false;
static uint32_t data_total, data_left;
static ScdoSignedTx msg_tx_request;
static CONFIDENTIAL HDNode *_node = NULL;
struct SHA3_CTX keccak_ctx_scdo = {0};

void scdo_eth_2_address(const uint8_t *pubkey, char *scdo_address,
                        size_t scdo_address_size) {
  if (!pubkey || !scdo_address || scdo_address_size < 43) {
    return;
  }

  uint8_t hash[32];
  struct SHA3_CTX ctx;
  sha3_256_Init(&ctx);

  // RLP encode the pubkey
  uint8_t rlp_encoded[66];  // 64 bytes for pubkey + 2 bytes for RLP header
  rlp_encoded[0] = 0xb8;    // RLP header for a string longer than 55 bytes
  rlp_encoded[1] = 64;      // Length of the pubkey
  memcpy(rlp_encoded + 2, pubkey, 64);

  sha3_Update(&ctx, rlp_encoded, sizeof(rlp_encoded));
  keccak_Final(&ctx, hash);

  uint8_t address[20];
  memcpy(address, hash + 12, 20);

  address[0] = 1;
  address[19] = (address[19] & 0xF0) | 0x01;

  char hex_address[41];
  data2hexaddr(address, 20, hex_address);

  snprintf(scdo_address, scdo_address_size, "1S%s", hex_address);
}

static inline void hash_data(const uint8_t *buf, size_t size) {
  sha3_Update(&keccak_ctx_scdo, buf, size);
}

static void hash_rlp_list_length(uint32_t length) {
  uint8_t buf[4] = {0};
  if (length <= 55) {
    buf[0] = 0xc0 + length;
    hash_data(buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xf7 + 1;
    buf[1] = length;
    hash_data(buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xf7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data(buf, 3);
  } else {
    buf[0] = 0xf7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data(buf, 4);
  }
}

static void hash_rlp_length(uint32_t length, uint8_t firstbyte) {
  uint8_t buf[4] = {0};

  if (length == 1 && firstbyte <= 0x7f) {
    /* empty length header */
  } else if (length <= 55) {
    buf[0] = 0x80 + length;
    hash_data(buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xb7 + 1;
    buf[1] = length;
    hash_data(buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xb7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data(buf, 3);
  } else {
    buf[0] = 0xb7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data(buf, 4);
  }
}

static void hash_rlp_field(const uint8_t *buf, size_t size) {
  hash_rlp_length(size, buf[0]);
  hash_data(buf, size);
}

static void hash_rlp_number(uint32_t number) {
  uint8_t data[4] = {0};
  data[0] = (number >> 24) & 0xff;
  data[1] = (number >> 16) & 0xff;
  data[2] = (number >> 8) & 0xff;
  data[3] = (number)&0xff;
  int offset = 0;
  while (!data[offset]) {
    offset++;
  }
  hash_rlp_field(data + offset, 4 - offset);
}

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

static int rlp_calculate_number_length(uint32_t number) {
  if (number <= 0x7f) {
    return 1;
  } else if (number <= 0xff) {
    return 2;
  } else if (number <= 0xffff) {
    return 3;
  } else if (number <= 0xffffff) {
    return 4;
  } else {
    return 5;
  }
}

static void send_request_chunk(void) {
  int progress = 1000 - (data_total > 1000000 ? data_left / (data_total / 800)
                                              : data_left * 800 / data_total);
  layoutProgressAdapter(_(C__SIGNING), progress);
  msg_tx_request.has_data_length = true;
  msg_tx_request.has_signature = false;
  msg_tx_request.data_length = data_left <= 1024 ? data_left : 1024;
  msg_write(MessageType_MessageType_ScdoSignedTx, &msg_tx_request);
}

static int scdo_is_canonic(uint8_t v, uint8_t signature[64]) {
  (void)signature;
  return (v & 2) == 0;
}

static void send_signature(void) {
  uint8_t hash[32] = {0}, sig[64] = {0};
  uint8_t v = 0;
  layoutProgressAdapter(_(C__SIGNING), 1000);

  keccak_Final(&keccak_ctx_scdo, hash);

  if (hdnode_sign_digest(_node, hash, sig, &v, scdo_is_canonic) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    scdo_signing_abort();
    return;
  }

  /* Send back the result */
  msg_tx_request.has_data_length = false;

  msg_tx_request.has_signature = true;
  msg_tx_request.signature.size = 65;
  memcpy(msg_tx_request.signature.bytes, sig, 64);
  memcpy(msg_tx_request.signature.bytes + 64, &v, 1);
  msg_write(MessageType_MessageType_ScdoSignedTx, &msg_tx_request);

  scdo_signing_abort();
}

static void scdoFormatAmount(const bignum256 *amnt, char *buf, int buflen,
                             const ScdoTokenType *token) {
  const char *suffix = NULL;
  int decimals = 8;

  if (token != NULL) {
    suffix = token->symbol;
    decimals = token->decimals;
  } else {
    suffix = " SCDO";
  }
  bn_format(amnt, NULL, suffix, decimals, 0, false, 0, buf, buflen);
  return;
}

static bool layoutScdoConfirmTx(char *to_str, const char *signer,
                                const uint8_t *value, uint32_t value_len,
                                const uint8_t *gas_price,
                                uint32_t gas_price_len,
                                const uint8_t *gas_limit,
                                uint32_t gas_limit_len, const uint8_t *data,
                                uint32_t data_len, const ScdoTokenType *token) {
  bignum256 val = {0}, gas = {0};
  uint8_t pad_val[32] = {0};
  char gas_value[32] = {0};

  memzero(pad_val, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_price_len), gas_price, gas_price_len);
  bn_read_be(pad_val, &val);

  memzero(pad_val, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_limit_len), gas_limit, gas_limit_len);
  bn_read_be(pad_val, &gas);
  bn_multiply(&val, &gas, &secp256k1.prime);

  scdoFormatAmount(&gas, gas_value, sizeof(gas_value), NULL);

  memzero(pad_val, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, &val);

  char amount[36] = {0};
  scdoFormatAmount(&val, amount, sizeof(amount), token);

  if (token == NULL) {
    return layoutTransactionSign("SCDO", 0, false, amount, to_str, signer, NULL,
                                 NULL, data, data_len,
                                 _(I__ETH_MAXIMUM_FEE_COLON), gas_value, NULL,
                                 NULL, NULL, NULL, NULL, NULL);
  } else {
    return layoutTransactionSign("SCDO", 0, true, amount, to_str, signer, NULL,
                                 NULL, NULL, 0, _(I__ETH_MAXIMUM_FEE_COLON),
                                 gas_value, NULL, NULL, NULL, NULL, NULL, NULL);
  }
}

void scdo_sign_tx(ScdoSignTx *msg, const HDNode *node, char *from_str) {
  scdo_signing = true;
  sha3_256_Init(&keccak_ctx_scdo);

  memzero(&msg_tx_request, sizeof(ScdoSignedTx));

  if (!msg->has_data_initial_chunk) msg->data_initial_chunk.size = 0;

  if (msg->has_data_length && msg->data_length > 0) {
    if (!msg->has_data_initial_chunk || msg->data_initial_chunk.size == 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Data length provided, but no initial chunk");
      scdo_signing_abort();
      return;
    }

    /* Our encoding only supports transactions up to 2^24 bytes.  To
     * prevent exceeding the limit we use a stricter limit on data length.
     */
    if (msg->data_length > 16000000) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Data length exceeds limit");
      scdo_signing_abort();
      return;
    }
    data_total = msg->data_length;
  } else {
    data_total = 0;
  }
  if (msg->data_initial_chunk.size > data_total) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid size of initial chunk");
    scdo_signing_abort();
    return;
  }

  /* detect SRC-20 like token */
  const ScdoTokenType *token = NULL;
  char to_str[43] = {0};

  if (msg->value.size == 0 && data_total == 68 &&
      msg->data_initial_chunk.size == 68 &&
      memcmp(msg->data_initial_chunk.bytes,
             "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    to_str[0] = '1';
    to_str[1] = 'S';
    data2hexaddr(msg->data_initial_chunk.bytes + 16, 20, to_str + 2);

    token = getTokenByAddress(to_str);
  }

  if (token != NULL) {
    /* token transfer*/
    if (!layoutScdoConfirmTx(
            to_str, from_str, msg->data_initial_chunk.bytes + 36, 32,
            msg->gas_price.bytes, msg->gas_price.size, msg->gas_limit.bytes,
            msg->gas_limit.size, msg->data_initial_chunk.bytes,
            msg->data_initial_chunk.size, token)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      scdo_signing_abort();
      return;
    }
  } else {
    if (!layoutScdoConfirmTx(msg->to, from_str, msg->value.bytes,
                             msg->value.size, msg->gas_price.bytes,
                             msg->gas_price.size, msg->gas_limit.bytes,
                             msg->gas_limit.size, msg->data_initial_chunk.bytes,
                             msg->data_initial_chunk.size, token)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      scdo_signing_abort();
      return;
    }
  }

  uint8_t from[20];
  unsigned int from_len = 0;
  hex2data(from_str + 2, from, &from_len);

  uint8_t to[20];
  unsigned int to_len = 0;
  hex2data(msg->to + 2, to, &to_len);

  /* Stage 1: Calculate total RLP length */
  uint32_t rlp_length = 0;

  layoutProgressAdapter(_(C__SIGNING), 0);

  rlp_length += rlp_calculate_number_length(msg->tx_type);
  rlp_length += rlp_calculate_length(20, from[0]);
  rlp_length += rlp_calculate_length(20, msg->to[0]);
  rlp_length += rlp_calculate_length(msg->value.size, msg->value.bytes[0]);
  rlp_length += rlp_calculate_length(msg->nonce.size, msg->nonce.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->gas_price.size, msg->gas_price.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->gas_limit.size, msg->gas_limit.bytes[0]);
  rlp_length +=
      rlp_calculate_length(msg->timestamp.size, msg->timestamp.bytes[0]);
  rlp_length +=
      rlp_calculate_length(data_total, msg->data_initial_chunk.bytes[0]);

  /* Stage 2: Store header fields */
  hash_rlp_list_length(rlp_length);

  layoutProgressAdapter(_(C__SIGNING), 100);

  hash_rlp_number(msg->tx_type);
  hash_rlp_field(from, 20);
  hash_rlp_field(to, 20);
  hash_rlp_field(msg->value.bytes, msg->value.size);
  hash_rlp_field(msg->nonce.bytes, msg->nonce.size);
  hash_rlp_field(msg->gas_price.bytes, msg->gas_price.size);
  hash_rlp_field(msg->gas_limit.bytes, msg->gas_limit.size);
  hash_rlp_field(msg->timestamp.bytes, msg->timestamp.size);
  hash_rlp_length(data_total, msg->data_initial_chunk.bytes[0]);
  hash_data(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size);
  data_left = data_total - msg->data_initial_chunk.size;
  _node = (HDNode *)node;
  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void scdo_signing_txack(const ScdoTxAck *tx) {
  if (!scdo_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in SCDO signing mode");
    layoutHome();
    return;
  }

  if (tx->data_chunk.size > data_left) {
    fsm_sendFailure(FailureType_Failure_DataError, "Too much data");
    scdo_signing_abort();
    return;
  }

  if (data_left > 0 && (!tx->has_data_chunk || tx->data_chunk.size == 0)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Empty data chunk received");
    scdo_signing_abort();
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

void scdo_signing_abort(void) {
  if (scdo_signing) {
    _node = NULL;
    layoutHome();
    scdo_signing = false;
  }
}

static void scdo_message_hash(const uint8_t *message, size_t message_len,
                              uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)"\x19" "SCDO Signed Message:\n", 22);
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

void scdo_sign_message(const ScdoSignMessage *msg, const HDNode *node,
                       ScdoSignedMessage *resp) {
  uint8_t hash[32] = {0};
  scdo_message_hash(msg->message.bytes, msg->message.size, hash);

  uint8_t v = 0;
  if (hdnode_sign_digest((HDNode *)node, hash, resp->signature.bytes, &v,
                         scdo_is_canonic)) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return;
  }

  resp->has_signature = true;
  resp->signature.bytes[64] = v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_ScdoSignedMessage, resp);
}
