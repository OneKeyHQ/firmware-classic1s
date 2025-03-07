#ifndef PSBT_H
#define PSBT_H
#include "../crypto.h"
#include "segwit_addr.h"

#define MAX_INPUTS 5
#define MAX_OUTPUTS 5

typedef struct {
  uint8_t fingerprint[4];
  size_t path_len;
  uint32_t path[8];
} KeyOriginInfo;

typedef struct {
  uint8_t hash[32];
  uint32_t n;
} COutPoint;

typedef struct {
  uint8_t scriptSig[1];  // ignore, assume it's empty
  COutPoint prevout;
  size_t scriptSig_len;
  uint32_t nSequence;
} CTxIn;

typedef struct {
  uint8_t scriptPubKey[83];
  int64_t nValue;
  size_t scriptPubKey_len;
} CTxOut;

typedef struct {
  CTxIn vin[MAX_INPUTS];
  CTxOut vout[MAX_OUTPUTS];
  int32_t nVersion;
  size_t vin_len;
  size_t vout_len;
  uint32_t nLockTime;
} CTransaction;

typedef struct {
  uint8_t sig[72];
  uint8_t pubkey[65];
  size_t sig_len;
  size_t pubkey_len;
} Partial_Sig;

typedef struct {
  uint8_t pubkey[78];
  KeyOriginInfo key_origin;
  size_t pubkey_len;
} HD_KEYPATH;
typedef struct {
  uint8_t signature[65];
  uint8_t x_only_pubkey[32];
  uint8_t leaf_hash[32];
  uint8_t signature_len;
} TAP_SCRIPT_SIG;

typedef struct {
  uint8_t script[1024];
  uint8_t control_block[193];
  size_t control_block_len;
  size_t script_len;
  uint8_t leaf_version;
} TAP_LEAF_SCRIPT;

typedef struct {
  uint8_t tap_leaf_hashs[5][32];
  KeyOriginInfo key_origin;
  uint8_t x_only_pubkey[32];
  size_t tap_leaf_hashs_len;
} TAP_BIP32_DERIVATION;
typedef struct {
  CTransaction non_witness_utxo;
  CTxOut witness_utxo;
  Partial_Sig partial_sigs[MAX_INPUTS - 1];
  TAP_SCRIPT_SIG tap_script_sig;
  TAP_LEAF_SCRIPT tap_leaf_script;
  TAP_BIP32_DERIVATION tap_bip32_path;
  HD_KEYPATH bip32_path;

  uint8_t redeem_script[1];         // ignore, assume it's empty
  uint8_t witness_script[1];        // ignore, assume it's empty
  uint8_t final_script_witness[1];  // ignore, assume it's empty
  uint8_t final_script_sig[1];      // ignore, assume it's empty

  uint8_t tap_key_sig[65];
  uint8_t prev_txid[32];
  uint8_t tap_internal_key[32];
  uint8_t tap_merkle_root[32];

  uint32_t sighash_type;
  uint32_t prev_out_index;
  uint32_t sequence;
  uint32_t time_locktime;
  uint32_t height_locktime;
  uint32_t version;

  size_t partial_sigs_len;
  size_t redeem_script_len;
  size_t witness_script_len;
  size_t tap_key_sig_len;
  size_t final_script_witness_len;
  size_t final_script_sig_len;

  bool non_witness_utxo_lookuped : 1;
  bool witness_utxo_lookuped : 1;
  bool sighash_type_lookuped : 1;
  bool redeem_script_lookuped : 1;
  bool witness_script_lookuped : 1;
  bool tap_key_sig_lookuped : 1;
  bool tap_script_sig_lookuped : 1;
  bool tap_leaf_script_lookuped : 1;
  bool prev_txid_lookuped : 1;
  bool prev_out_index_lookuped : 1;
  bool sequence_lookuped : 1;
  bool time_locktime_lookuped : 1;
  bool height_locktime_lookuped : 1;
  bool tap_bip32_path_lookuped : 1;
  bool bip32_path_lookuped : 1;
  bool tap_internal_key_lookuped : 1;
  bool tap_merkle_root_lookuped : 1;
  bool final_script_witness_lookuped : 1;
  bool final_script_sig_lookuped : 1;
} PartiallySignedInput;

typedef struct {
  uint8_t redeem_script[1];   // ignore, assume it's empty
  uint8_t tap_tree[1];        // ignore, assume it's empty
  uint8_t witness_script[1];  // ignore, assume it's empty
  uint8_t script[83];         // the limit of OP_RETURN is 83 bytes
  HD_KEYPATH bip32_path;
  TAP_BIP32_DERIVATION tap_bip32_path;
  int64_t amount;
  size_t redeem_script_len;
  size_t tap_tree_len;
  size_t witness_script_len;
  size_t script_len;
  uint8_t tap_internal_key[32];
  uint8_t version;
  bool redeem_script_lookuped : 1;
  bool witness_script_lookuped : 1;
  bool amount_lookuped : 1;
  bool script_lookuped : 1;
  bool tap_internal_key_lookuped : 1;
  bool tap_tree_lookuped : 1;
  bool tap_bip32_path_lookuped : 1;
  bool bip32_path_lookuped : 1;
} PartiallySignedOutput;

typedef struct {
  CTransaction tx;
  PartiallySignedInput inputs[MAX_INPUTS];
  PartiallySignedOutput outputs[MAX_OUTPUTS];
  HD_KEYPATH xpubs[5];
  size_t xpubs_len;
  uint32_t tx_version;
  uint32_t fallback_locktime;
  uint32_t global_version;
  uint8_t inputs_len;
  uint8_t outputs_len;
  uint8_t tx_modifiable;
  bool tx_lookuped : 1;
  bool inputs_len_lookuped : 1;
  bool outputs_len_lookuped : 1;
  bool tx_version_lookuped : 1;
  bool fallback_locktime_lookuped : 1;
  bool tx_modifiable_lookuped : 1;
  bool global_version_lookuped : 1;
  bool explicit_version : 1;
} PSBT;

typedef struct {
  Hasher hasher_prevouts;
  Hasher hasher_amounts;
  Hasher hasher_scriptpubkeys;
  Hasher hasher_sequences;
  Hasher hasher_outputs;
  uint8_t hash_prevouts[32];
  uint8_t hash_amounts[32];
  uint8_t hash_scriptpubkeys[32];
  uint8_t hash_sequences[32];
  uint8_t hash_outputs[32];
} BitcoinSigHasher;

bool psbt_deserialize(const uint8_t *psbt_bytes, size_t psbt_len, PSBT *psbt);
bool psbt_serialize(const PSBT *psbt, uint8_t *buffer, size_t buffer_size,
                    size_t *psbt_size);
bool is_witness(const uint8_t *script, size_t script_len,
                uint8_t *witness_version);
bool is_opreturn(const uint8_t *script, size_t script_len);
bool is_p2sh(const uint8_t *script, size_t script_len);
bool is_p2pkh(const uint8_t *script, size_t script_len);
bool compute_locktime(const PSBT *psbt, uint32_t *locktime);
bool locktime_disabled(const PSBT *psbt);
void *custom_memmem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen);

void sig_hasher_init(BitcoinSigHasher *hasher);
void sig_hasher_add_input(BitcoinSigHasher *hasher,
                          const PartiallySignedInput *input);
void sig_hasher_add_output(BitcoinSigHasher *hasher,
                           const PartiallySignedOutput *output);
void sig_hasher_final(BitcoinSigHasher *hasher);
void sig_hasher_hash_341(const BitcoinSigHasher *hasher, uint32_t i,
                         uint8_t sighash_type, uint8_t *hash, uint32_t version,
                         uint32_t locktime, uint8_t *leaf_hash);
void tagged_hasher_init(Hasher *hasher, const uint8_t *tag, size_t tag_len);
#endif  // PSBT_H
