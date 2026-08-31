#include "babylon.h"

#include <string.h>

#include "memzero.h"

#include "bignum.h"
#include "bip32.h"
#include "config_root.h"
#include "curves.h"
#include "hmac.h"
#include "messages-bitcoin.pb.h"
#include "sha2.h"

#define BABYLON_IKM_CHILD (73681862U | 0x80000000U)

// trezor-crypto retries an invalid BIP32 child candidate internally. Babylon
// fixes this exact child, so reject an invalid first candidate instead.
static bool babylon_bip32_child_is_valid(const HDNode *node, uint32_t child) {
  uint8_t data[1 + 32 + 4];
  uint8_t digest[SHA512_DIGEST_LENGTH];
  bignum256 parent_key;
  bignum256 child_key;
  bool valid = false;

  memzero(data, sizeof(data));
  memzero(digest, sizeof(digest));
  memzero(&parent_key, sizeof(parent_key));
  memzero(&child_key, sizeof(child_key));

  if (node->curve == NULL || node->curve->params == NULL) {
    goto cleanup;
  }

  memcpy(data + 1, node->private_key, sizeof(node->private_key));
  write_be(data + 33, child);
  hmac_sha512(node->chain_code, sizeof(node->chain_code), data, sizeof(data),
              digest);

  bn_read_be(digest, &child_key);
  if (!bn_is_less(&child_key, &node->curve->params->order)) {
    goto cleanup;
  }

  bn_read_be(node->private_key, &parent_key);
  bn_add(&child_key, &parent_key);
  bn_mod(&child_key, &node->curve->params->order);
  valid = !bn_is_zero(&child_key);

cleanup:
  memzero(&child_key, sizeof(child_key));
  memzero(&parent_key, sizeof(parent_key));
  memzero(digest, sizeof(digest));
  memzero(data, sizeof(data));
  return valid;
}

static const char *babylon_canonical_network_name(uint8_t network) {
  switch ((CanonicalBitcoinNetwork)network) {
    case CanonicalBitcoinNetwork_BITCOIN_MAINNET:
      return "bitcoin-mainnet";
    case CanonicalBitcoinNetwork_BITCOIN_TESTNET:
      return "bitcoin-testnet";
    case CanonicalBitcoinNetwork_BITCOIN_SIGNET:
      return "bitcoin-signet";
    case CanonicalBitcoinNetwork_BITCOIN_REGTEST:
      return "bitcoin-regtest";
    default:
      return NULL;
  }
}

bool babylon_derive_context_hash(const uint8_t connected_public_key[33],
                                 const uint8_t *app_name, size_t app_name_len,
                                 uint8_t network, const uint8_t *context,
                                 size_t context_len,
                                 uint8_t out[BABYLON_CONTEXT_HASH_LEN]) {
  static const uint8_t salt[] = "derive-context-hash";
  static const uint8_t block_index = 1;

  HDNode node;
  HMAC_SHA256_CTX hmac;
  uint8_t app_name_hash[SHA256_DIGEST_LENGTH];
  uint8_t network_hash[SHA256_DIGEST_LENGTH];
  uint8_t prk[SHA256_DIGEST_LENGTH];
  bool success = false;

  memzero(&node, sizeof(node));
  memzero(&hmac, sizeof(hmac));
  memzero(app_name_hash, sizeof(app_name_hash));
  memzero(network_hash, sizeof(network_hash));
  memzero(prk, sizeof(prk));

  if (out == NULL) {
    return false;
  }
  memzero(out, BABYLON_CONTEXT_HASH_LEN);

  if (connected_public_key == NULL || app_name == NULL || app_name_len == 0 ||
      app_name_len > BABYLON_APP_NAME_MAX_LEN || context == NULL ||
      context_len == 0 || context_len > BABYLON_CONTEXT_MAX_LEN) {
    goto cleanup;
  }

  const char *network_name = babylon_canonical_network_name(network);
  if (network_name == NULL || !config_getRootNode(&node, SECP256K1_NAME) ||
      !babylon_bip32_child_is_valid(&node, BABYLON_IKM_CHILD) ||
      hdnode_private_ckd(&node, BABYLON_IKM_CHILD) == 0) {
    goto cleanup;
  }

  sha256_Raw(app_name, app_name_len, app_name_hash);
  sha256_Raw((const uint8_t *)network_name, strlen(network_name), network_hash);

  hmac_sha256(salt, sizeof(salt) - 1, node.private_key,
              sizeof(node.private_key), prk);
  memzero(&node, sizeof(node));
  hmac_sha256_Init(&hmac, prk, sizeof(prk));
  memzero(prk, sizeof(prk));
  hmac_sha256_Update(&hmac, app_name_hash, sizeof(app_name_hash));
  hmac_sha256_Update(&hmac, network_hash, sizeof(network_hash));
  hmac_sha256_Update(&hmac, connected_public_key, 33);
  hmac_sha256_Update(&hmac, context, (uint32_t)context_len);
  hmac_sha256_Update(&hmac, &block_index, sizeof(block_index));
  hmac_sha256_Final(&hmac, out);
  success = true;

cleanup:
  if (!success) {
    memzero(out, BABYLON_CONTEXT_HASH_LEN);
  }
  memzero(prk, sizeof(prk));
  memzero(network_hash, sizeof(network_hash));
  memzero(app_name_hash, sizeof(app_name_hash));
  memzero(&hmac, sizeof(hmac));
  memzero(&node, sizeof(node));
  return success;
}
