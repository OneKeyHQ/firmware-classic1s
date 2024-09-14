#include "bip322_simple.h"
#include <stdint.h>
#include <string.h>
#include "../psbt/psbt.h"
#include "../transaction.h"
#include "zkp_bip340.h"

static const uint8_t zero_1byte = 0;
static const uint32_t zero_4bytes = 0;
static const uint64_t zero_8bytes = 0;
static const uint8_t OP_RETURN = 0x6a;
static const uint8_t one = 1;
static const uint32_t MAX_UINT32 = 0xFFFFFFFF;

static void create_to_spend(const uint8_t *message, size_t message_len,
                            const uint8_t *script_pub, size_t script_pub_len,
                            uint8_t *tx_id) {
  const char TAG[] = "BIP0322-signed-message";
  const uint8_t UTXO[32] = {0};
  Hasher tag_hasher = {0};
  tagged_hasher_init(&tag_hasher, (uint8_t *)TAG, sizeof(TAG) - 1);
  hasher_Update(&tag_hasher, message, message_len);
  uint8_t script_sig[34] = {0x00, 0x20};
  hasher_Final(&tag_hasher, script_sig + 2);

  Hasher tx_hasher = {0};
  hasher_Init(&tx_hasher, HASHER_SHA2D);
  // nVersion
  hasher_Update(&tx_hasher, (uint8_t *)&zero_4bytes, sizeof(zero_4bytes));
  // inputs
  hasher_Update(&tx_hasher, (uint8_t *)&one, 1);
  hasher_Update(&tx_hasher, UTXO, sizeof(UTXO));  // tx hash
  hasher_Update(&tx_hasher, (uint8_t *)&MAX_UINT32,
                sizeof(MAX_UINT32));                          // output index
  ser_length_hash(&tx_hasher, sizeof(script_sig));            // script sig
  hasher_Update(&tx_hasher, script_sig, sizeof(script_sig));  // script sig
  hasher_Update(&tx_hasher, (uint8_t *)&zero_4bytes,
                sizeof(zero_4bytes));  // sequence
  // outputs
  hasher_Update(&tx_hasher, (uint8_t *)&one, 1);
  hasher_Update(&tx_hasher, (uint8_t *)&zero_8bytes,
                sizeof(zero_8bytes));           // amount
  ser_length_hash(&tx_hasher, script_pub_len);  // script pubkey
  hasher_Update(&tx_hasher, script_pub, script_pub_len);
  // nLockTime
  hasher_Update(&tx_hasher, (uint8_t *)&zero_4bytes, sizeof(zero_4bytes));
  hasher_Final(&tx_hasher, tx_id);
}

static void write_output_script_p2pkh_hash(Hasher *hasher,
                                           const uint8_t *pubkeyhash,
                                           bool prefixed) {
  uint8_t script[26] = {0};
  if (prefixed) {
    script[0] = 25;
  }
  script[1] = 0x76;  // OP_DUP
  script[2] = 0xA9;  // OP_HASH160
  script[3] = 0x14;  // OP_DATA_20
  memcpy(script + 4, pubkeyhash, 20);
  script[24] = 0x88;  // OP_EQUALVERIFY
  script[25] = 0xAC;  // OP_CHECKSIG
  hasher_Update(hasher, prefixed ? script : script + 1,
                prefixed ? sizeof(script) : sizeof(script) - 1);
}

static void sighash_bip341(const uint8_t *message, size_t message_len,
                           const uint8_t *script_pub, size_t script_pub_len,
                           uint8_t *sighash) {
  uint8_t hash[32] = {0};
  create_to_spend(message, message_len, script_pub, script_pub_len, hash);
  Hasher h_sigmsg = {0};
  Hasher hasher = {0};
  hasher_Init(&hasher, HASHER_SHA2);
  hasher_Init(&h_sigmsg, HASHER_SHA2_TAPSIGHASH);
  // sighash epoch 0
  hasher_Update(&h_sigmsg, (uint8_t *)&zero_1byte, 1);
  // nHashType
  hasher_Update(&h_sigmsg, (uint8_t *)&zero_1byte, 1);
  // nVersion
  hasher_Update(&h_sigmsg, (uint8_t *)&zero_4bytes, 4);
  // nLockTime
  hasher_Update(&h_sigmsg, (uint8_t *)&zero_4bytes, 4);
  // sha_prevouts
  hasher_Update(&hasher, hash, sizeof(hash));
  hasher_Update(&hasher, (uint8_t *)&zero_4bytes, 4);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_sigmsg, hash, sizeof(hash));
  // sha_amounts
  hasher_Reset(&hasher);
  hasher_Update(&hasher, (uint8_t *)&zero_8bytes, 8);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_sigmsg, hash, sizeof(hash));
  // sha_scriptpubkeys
  hasher_Reset(&hasher);
  ser_length_hash(&hasher, script_pub_len);
  hasher_Update(&hasher, script_pub, script_pub_len);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_sigmsg, hash, sizeof(hash));
  // sha_sequences
  hasher_Reset(&hasher);
  hasher_Update(&hasher, (uint8_t *)&zero_4bytes, 4);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_sigmsg, hash, sizeof(hash));
  // sha_outputs
  hasher_Reset(&hasher);
  hasher_Update(&hasher, (uint8_t *)&zero_8bytes, 8);
  hasher_Update(&hasher, (uint8_t *)&one, 1);  // length of OP_RETURN
  hasher_Update(&hasher, (uint8_t *)&OP_RETURN, 1);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_sigmsg, hash, sizeof(hash));
  // spend_type 0 (no tapscript message extension, no annex)
  hasher_Update(&h_sigmsg, (uint8_t *)&zero_1byte, 1);
  // input_index
  hasher_Update(&h_sigmsg, (uint8_t *)&zero_4bytes, 4);

  hasher_Final(&h_sigmsg, sighash);
}

static void sighash_bip143(const uint8_t *message, size_t message_len,
                           const uint8_t *script_pub, size_t script_pub_len,
                           const uint8_t *pubkeyhash, bool sign_hash_double,
                           uint8_t *sighash) {
  uint8_t hash[32] = {0};
  uint8_t tx_id[32] = {0};
  create_to_spend(message, message_len, script_pub, script_pub_len, tx_id);
  HasherType hasher_type = sign_hash_double ? HASHER_SHA2D : HASHER_SHA2;
  Hasher h_preimage = {0};
  Hasher hasher = {0};
  hasher_Init(&h_preimage, hasher_type);
  hasher_Init(&hasher, hasher_type);
  // nVersion
  hasher_Update(&h_preimage, (uint8_t *)&zero_4bytes, 4);
  // hashPrevouts
  hasher_Update(&hasher, tx_id, sizeof(tx_id));
  hasher_Update(&hasher, (uint8_t *)&zero_4bytes, 4);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_preimage, hash, sizeof(hash));
  // hashSequence
  hasher_Reset(&hasher);
  hasher_Update(&hasher, (uint8_t *)&zero_4bytes, 4);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_preimage, hash, sizeof(hash));
  // outpoint
  hasher_Update(&h_preimage, tx_id, sizeof(tx_id));
  hasher_Update(&h_preimage, (uint8_t *)&zero_4bytes, 4);
  // scriptCode
  write_output_script_p2pkh_hash(&h_preimage, pubkeyhash, true);
  // amount
  hasher_Update(&h_preimage, (uint8_t *)&zero_8bytes, 8);
  // nSequence
  hasher_Update(&h_preimage, (uint8_t *)&zero_4bytes, 4);
  // hashOutputs
  hasher_Reset(&hasher);
  hasher_Update(&hasher, (uint8_t *)&zero_8bytes, 8);
  hasher_Update(&hasher, (uint8_t *)&one, 1);  // length of OP_RETURN
  hasher_Update(&hasher, (uint8_t *)&OP_RETURN, 1);
  hasher_Final(&hasher, hash);
  hasher_Update(&h_preimage, hash, sizeof(hash));
  // nLockTime
  hasher_Update(&h_preimage, (uint8_t *)&zero_4bytes, 4);
  // nHashType
  hasher_Update(&h_preimage, (uint8_t *)&one, 4);

  hasher_Final(&h_preimage, sighash);
}

bool sign_bip322_simple_taproot(const HDNode *node, const uint8_t *message,
                                size_t message_len, uint8_t *signature_out,
                                size_t *signature_size_out) {
  uint8_t script_pub[34] = {0x51, 0x20};
  uint8_t sig_hash[32];
  uint8_t signature[64];

  zkp_bip340_tweak_public_key(node->public_key + 1, NULL, script_pub + 2);
  sighash_bip341(message, message_len, script_pub, sizeof(script_pub),
                 sig_hash);

  if (hdnode_bip340_sign_digest(node, sig_hash, signature) != 0) {
    return false;
  }

  *signature_size_out = serialize_p2tr_witness(
      signature, sizeof(signature), SIGHASH_ALL_TAPROOT, signature_out);
  return true;
}

bool sign_bip322_simple_segwit(const HDNode *node, const CoinInfo *coin,
                               const uint8_t *message, size_t message_len,
                               uint8_t *signature_out,
                               size_t *signature_size_out) {
  uint8_t script_pub[22] = {0x00, 0x14};
  uint8_t sig_hash[32];
  uint8_t signature[64];
  uint8_t der_sig[72];

  ecdsa_get_pubkeyhash(node->public_key, coin->curve->hasher_pubkey,
                       script_pub + 2);
  sighash_bip143(message, message_len, script_pub, sizeof(script_pub),
                 script_pub + 2, coin->curve->hasher_sign == HASHER_SHA2D,
                 sig_hash);

  if (hdnode_sign_digest(node, sig_hash, signature, NULL, NULL) != 0) {
    return false;
  }

  int der_sig_size = ecdsa_sig_to_der(signature, der_sig);
  *signature_size_out = serialize_p2wpkh_witness(
      der_sig, der_sig_size, node->public_key, 33, SIGHASH_ALL, signature_out);
  return true;
}
