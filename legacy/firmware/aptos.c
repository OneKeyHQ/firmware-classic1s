
#include "aptos.h"
#include <string.h>
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "stdint.h"
#include "util.h"

// Prefix_bytes with SHA3_256 hash bytes of string `APTOS::RawTransaction`
static const uint8_t APTOS_RAW_TX_PREFIX[32] = {
    181, 233, 125, 176, 127, 160, 189, 14,  85,  152, 170,
    54,  67,  169, 188, 111, 102, 147, 189, 220, 26,  159,
    236, 158, 103, 74,  70,  30,  170, 0,   177, 147};

// Prefix_bytes with SHA3_256 hash bytes of string
// `APTOS::RawTransactionWithData`
static const uint8_t APTOS_RAW_TX_WITH_DATA_PREFIX[32] = {
    94,  250, 60,  79,  2,   248, 58,  15,  75,  45,  105,
    252, 149, 198, 7,   204, 2,   130, 92,  196, 231, 190,
    83,  110, 240, 153, 45,  240, 80,  217, 230, 124};

static const char *MESSAGE_PREFIX = "APTOS\n";

// Prefix_bytes with SHA3_256 hash bytes of string `SIGN_IN_WITH_APTOS::`
static const uint8_t SIWA_MESSAGE_PREFIX[32] = {
    30,  194, 212, 140, 200, 207, 210, 166, 235, 16,  172,
    3,   47,  166, 181, 137, 39,  90,  198, 106, 176, 8,
    195, 158, 161, 26,  66,  136, 40,  163, 143, 254};

void aptos_get_address_from_public_key(const uint8_t *public_key,
                                       char *address) {
  uint8_t buf[SIZE_PUBKEY] = {0};
  struct SHA3_CTX ctx = {0};

  sha3_256_Init(&ctx);
  sha3_Update(&ctx, public_key, SIZE_PUBKEY);
  // append single-signature scheme identifier
  sha3_Update(&ctx, (const uint8_t *)"\x00", 1);
  sha3_Final(&ctx, buf);
  address[0] = '0';
  address[1] = 'x';
  data2hexaddr((const uint8_t *)buf, SIZE_PUBKEY, address + 2);
}

void aptos_sign_tx(const AptosSignTx *msg, const HDNode *node,
                   AptosSignedTx *resp) {
  char address[67] = {0};
  aptos_get_address_from_public_key(node->public_key + 1, address);

  if (!layoutBlindSign("Aptos", false, NULL, address, msg->raw_tx.bytes,
                       msg->raw_tx.size, NULL, NULL, NULL, NULL, NULL, NULL)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    layoutHome();
    return;
  }

  uint8_t buf[sizeof(AptosSignTx_raw_tx_t) + 32];
  memcpy(buf,
         msg->tx_type == AptosTransactionType_WITH_DATA
             ? APTOS_RAW_TX_WITH_DATA_PREFIX
             : APTOS_RAW_TX_PREFIX,
         32);
  memcpy(buf + 32, msg->raw_tx.bytes, msg->raw_tx.size);
#if EMULATOR
  ed25519_sign(buf, msg->raw_tx.size + 32, node->private_key,
               resp->signature.bytes);
#else
  hdnode_sign(node, buf, msg->raw_tx.size + 32, 0, resp->signature.bytes, NULL,
              NULL);
#endif
  memcpy(resp->public_key.bytes, node->public_key + 1, 32);
  resp->signature.size = 64;
  resp->public_key.size = 32;
  msg_write(MessageType_MessageType_AptosSignedTx, resp);
}

void aptos_sign_message(const AptosSignMessage *msg, const HDNode *node,
                        AptosMessageSignature *resp) {
  AptosMessagePayload payload = msg->payload;
  char full_message[sizeof(AptosMessagePayload) + 58] = {0};

  strcat(full_message, MESSAGE_PREFIX);
  if (payload.has_address) {
    char *address = payload.address;
    strcat(full_message, "address: ");
    strcat(full_message, address);
    strcat(full_message, "\n");
  }
  if (payload.has_application) {
    char *application = payload.application;
    strcat(full_message, "application: ");
    strcat(full_message, application);
    strcat(full_message, "\n");
  }
  if (payload.has_chain_id) {
    char *chain_id = payload.chain_id;
    strcat(full_message, "chainId: ");
    strcat(full_message, chain_id);
    strcat(full_message, "\n");
  }
  char *message = payload.message;
  strcat(full_message, "message: ");
  strcat(full_message, message);
  strcat(full_message, "\n");
  char *nonce = payload.nonce;
  strcat(full_message, "nonce: ");
  strcat(full_message, nonce);

  aptos_get_address_from_public_key(node->public_key + 1, resp->address);
  // display here
  if (!fsm_layoutSignMessage("Aptos", resp->address,
                             (const uint8_t *)full_message,
                             strlen(full_message))) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
#if EMULATOR
  ed25519_sign((const uint8_t *)full_message, strlen(full_message),
               node->private_key, resp->signature.bytes);
#else
  hdnode_sign(node, (const uint8_t *)full_message, strlen(full_message), 0,
              resp->signature.bytes, NULL, NULL);
#endif
  resp->signature.size = 64;
  msg_write(MessageType_MessageType_AptosMessageSignature, resp);
}

void aptos_sign_siwa_message(const AptosSignSIWAMessage *msg,
                             const HDNode *node, AptosMessageSignature *resp) {
  size_t payload_len = strlen(msg->siwa_payload);
  size_t signing_message_len = payload_len + 32;

  uint8_t signing_message[signing_message_len];

  memcpy(signing_message, SIWA_MESSAGE_PREFIX, 32);
  memcpy(signing_message + 32, (const uint8_t *)msg->siwa_payload, payload_len);

  aptos_get_address_from_public_key(node->public_key + 1, resp->address);

  if (!fsm_layoutSignMessage("SIWA", resp->address,
                             (const uint8_t *)msg->siwa_payload, payload_len)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return;
  }
#if EMULATOR
  ed25519_sign(signing_message, signing_message_len, node->private_key,
               resp->signature.bytes);
#else
  hdnode_sign(node, signing_message, signing_message_len, 0,
              resp->signature.bytes, NULL, NULL);
#endif
  resp->signature.size = 64;
  msg_write(MessageType_MessageType_AptosMessageSignature, resp);
}
