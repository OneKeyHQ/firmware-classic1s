#include "benfen.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "stdint.h"
#include "util.h"

static bool benfen_signing = false;
static uint32_t data_total, data_left;
static uint8_t pubkey[32];
static BLAKE2B_CTX hash_ctx = {0};
static BenfenTxRequest msg_tx_request;
static CONFIDENTIAL HDNode node_cache;

void benfen_get_address_from_public_key(const uint8_t *public_key,
                                        char *address) {
  static char hex_addr[67];
  static uint8_t hash_buf[32];
  static BLAKE2B_CTX blake_ctx;
  static SHA256_CTX sha_ctx;
  static char padded_hex[BFC_HEX_LEN + 1];
  static uint8_t sha_hash[SHA256_DIGEST_LENGTH];
  static char checksum[5];
  memset(hex_addr, 0, sizeof(hex_addr));
  memset(hash_buf, 0, sizeof(hash_buf));
  memset(padded_hex, 0, sizeof(padded_hex));
  memset(checksum, 0, sizeof(checksum));
  blake2b_Init(&blake_ctx, 32);
  blake2b_Update(&blake_ctx, (const uint8_t *)"\x00", 1);
  blake2b_Update(&blake_ctx, public_key, 32);
  blake2b_Final(&blake_ctx, hash_buf, 32);
  hex_addr[0] = '0';
  hex_addr[1] = 'x';
  data2hexaddr((const uint8_t *)hash_buf, 32, hex_addr + 2);
  const char *hex_part = hex_addr + 2;
  size_t hex_len = strlen(hex_part);

  if (hex_len == 0 || hex_len > BFC_HEX_LEN) {
    return;
  }

  size_t padding = BFC_HEX_LEN - hex_len;
  if (padding > 0) {
    memset(padded_hex, '0', padding);
    memcpy(padded_hex + padding, hex_part, hex_len);
  } else {
    memcpy(padded_hex, hex_part, BFC_HEX_LEN);
  }

  sha256_Init(&sha_ctx);
  sha256_Update(&sha_ctx, (const uint8_t *)padded_hex, BFC_HEX_LEN);
  sha256_Final(&sha_ctx, sha_hash);

  memcpy(address, BFC_PREFIX, BFC_PREFIX_LEN);
  memcpy(address + BFC_PREFIX_LEN, padded_hex, BFC_HEX_LEN);

  sprintf(checksum, "%02x%02x", sha_hash[0], sha_hash[1]);
  memcpy(address + BFC_PREFIX_LEN + BFC_HEX_LEN, checksum, BFC_CHECKSUM_LEN);
  address[BFC_ADDR_LENGTH] = '\0';
}

void benfen_sign_tx(const BenfenSignTx *msg, const HDNode *node,
                    BenfenSignedTx *resp) {
  char address[67] = {0};
  uint8_t digest[32] = {0};
  benfen_get_address_from_public_key(node->public_key + 1, address);
  if ((msg->raw_tx.bytes[0] != 0x00) && ((msg->raw_tx.bytes[1] != 0x00)) &&
      ((msg->raw_tx.bytes[2] != 0x00))) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid raw tx");
    layoutHome();
  }

  BLAKE2B_CTX ctx;
  blake2b_Init(&ctx, 32);
  blake2b_Update(&ctx, msg->raw_tx.bytes, msg->raw_tx.size);
  blake2b_Final(&ctx, digest, 32);

  if (!layoutBlindSign("Benfen", false, NULL, address, msg->raw_tx.bytes,
                       msg->raw_tx.size, NULL, NULL, NULL, NULL, NULL, NULL)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    layoutHome();
    return;
  }

#if EMULATOR
  ed25519_sign(digest, 32, node->private_key, resp->signature.bytes);
#else
  hdnode_sign(node, digest, 32, 0, resp->signature.bytes, NULL, NULL);
#endif
  memcpy(resp->public_key.bytes, node->public_key + 1, 32);
  resp->signature.size = 64;
  resp->public_key.size = 32;
  msg_write(MessageType_MessageType_BenfenSignedTx, resp);
}

static void uleb_encode(int num, uint8_t *num_bytes, int *len) {
  while (num > 0) {
    num_bytes[*len] = num & 127;
    if (num >>= 7) {
      num_bytes[*len] |= 128;
    }
    *len += 1;
  }
}

void benfen_message_sign(const BenfenSignMessage *msg, const HDNode *node,
                         BenfenMessageSignature *resp) {
  uint8_t digest[32] = {0};
  uint8_t num_bytes[32] = {0x3, 0x0, 0x0};
  int num_bytes_len = 3;

  uleb_encode(msg->message.size, num_bytes, &num_bytes_len);

  BLAKE2B_CTX ctx;
  blake2b_Init(&ctx, 32);
  blake2b_Update(&ctx, num_bytes, num_bytes_len);
  blake2b_Update(&ctx, msg->message.bytes, msg->message.size);
  blake2b_Final(&ctx, digest, 32);

#if EMULATOR
  ed25519_sign(digest, 32, node->private_key, resp->signature.bytes);
#else
  hdnode_sign(node, digest, 32, 0, resp->signature.bytes, NULL, NULL);
#endif
  resp->signature.size = 64;
  msg_write(MessageType_MessageType_BenfenMessageSignature, resp);
}

void benfen_signing_abort(void) {
  if (benfen_signing) {
    memzero(&node_cache, sizeof(node_cache));
    layoutHome();
    benfen_signing = false;
  }
}

static inline void hash_data(const uint8_t *buf, size_t size) {
  blake2b_Update(&hash_ctx, buf, size);
}

static void send_signature(void) {
  uint8_t digest[32] = {0};
  BenfenSignedTx tx;

  blake2b_Final(&hash_ctx, digest, 32);

#if EMULATOR
  ed25519_sign(digest, 32, node_cache.private_key, tx.signature.bytes);
#else
  hdnode_sign(&node_cache, digest, 32, 0, tx.signature.bytes, NULL, NULL);
#endif

  memcpy(tx.public_key.bytes, pubkey, 32);
  tx.signature.size = 64;
  tx.public_key.size = 32;
  msg_write(MessageType_MessageType_BenfenSignedTx, &tx);

  memzero(&node_cache, sizeof(node_cache));
  benfen_signing_abort();
}

static void send_request_chunk(void) {
  msg_tx_request.has_data_length = true;
  msg_tx_request.data_length = data_left <= 1024 ? data_left : 1024;
  msg_write(MessageType_MessageType_BenfenTxRequest, &msg_tx_request);
}

void benfen_signing_init(const BenfenSignTx *msg, const HDNode *node) {
  char address[67] = {0};

  benfen_signing = true;
  blake2b_Init(&hash_ctx, 32);

  benfen_get_address_from_public_key(node->public_key + 1, address);
  // INTENT_BYTES = b'\x00\x00\x00'
  if ((msg->data_initial_chunk.bytes[0] != 0x00) &&
      ((msg->data_initial_chunk.bytes[1] != 0x00)) &&
      ((msg->data_initial_chunk.bytes[2] != 0x00))) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid raw tx");
    benfen_signing_abort();
    return;
  }
  if (!layoutBlindSign(
          "Benfen", false, NULL, address, msg->data_initial_chunk.bytes,
          msg->data_initial_chunk.size, NULL, NULL, NULL, NULL, NULL, NULL)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    layoutHome();
    return;
  }

  memcpy(&node_cache, node, sizeof(HDNode));
  memcpy(pubkey, node->public_key + 1, 32);

  hash_data(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size);

  data_total = msg->data_length;
  data_left = data_total - msg->data_initial_chunk.size;
  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void benfen_signing_txack(BenfenTxAck *tx) {
  if (!benfen_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in benfen signing mode");
    layoutHome();
    return;
  }
  if (tx->data_chunk.size > data_left) {
    fsm_sendFailure(FailureType_Failure_DataError, "Too much data");
    benfen_signing_abort();
    return;
  }
  if (data_left > 0 && tx->data_chunk.size == 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "Empty data chunk received");
    benfen_signing_abort();
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