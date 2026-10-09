#include "kaspa.h"
#include <stdint.h>
#include <string.h>
#include "blake2b.h"
#include "buttons.h"
#include "cash_addr.h"
#include "fsm.h"
#include "gettext.h"
#include "i18n/keys.h"
#include "layout2.h"
#include "memzero.h"
#include "messages-common.pb.h"
#include "messages.h"
#include "protect.h"
#include "sha2.h"
#include "util.h"
#include "zkp_bip340.h"

#if EMULATOR
#include "secp256k1.h"
#include "transaction.h"
#endif

#define PUBKEY_VERSION 0
#define PUBKEY_ECDSA_VERSION 1
#define SCRIPT_HASH_VERSION 8
// schnorr pubkey is 32 bytes
#define PUBKEY_LEN 32
// ecdsa pubkey is 33 bytes
#define PUBKEY_ECDSA_LEN 33
#define KASPA_SUBNETWORK_ID_LEN 20
#define KASPA_OP_DATA_32 0x20
#define KASPA_OP_DATA_33 0x21
#define KASPA_OP_EQUAL 0x87
#define KASPA_OP_BLAKE2B 0xaa
#define KASPA_OP_CHECK_SIG_ECDSA 0xab
#define KASPA_OP_CHECK_SIG 0xac
#define KASPA_SCRIPT_P2PK_SCHNORR_LEN 34
#define KASPA_SCRIPT_P2PK_ECDSA_LEN 35
#define KASPA_SCRIPT_P2SH_LEN 35
#define KASPA_SIG_HASH_ALL 0x01
#define KASPA_HASH_SIZE 32
#define KASPA_TX_ID_LEN 32
#define KASPA_PAYLOAD_CHUNK_SIZE 1024
#define KASPA_PROGRESS_MAX 1000
#define KASPA_PROGRESS_VERIFY_END 500
// Avoid flashing a progress page for short transactions. Once enabled, update
// only after a visible percentage change to bound OLED refreshes.
#define KASPA_PROGRESS_MIN_INPUT_COUNT 10
#define KASPA_PROGRESS_UPDATE_PERCENT 5
// Signer-side guard derived from the pre-Toccata standard relay mass cap.
#define KASPA_MAX_PAYLOAD_LENGTH 25000
#define KASPA_ACCOUNT_ROOT_LEN 3
#define KASPA_CHANGE_BRANCH_INDEX 3
#define KASPA_EXTERNAL_BRANCH 0
#define KASPA_INTERNAL_CHANGE_BRANCH 1
#define KASPA_SCHEME_SCHNORR "schnorr"
#define KASPA_SCHEME_ECDSA "ecdsa"
#define KASPA_PREFIX_MAINNET "kaspa"
#define KASPA_PREFIX_TESTNET "kaspatest"
#define KASPA_PREFIX_SIMNET "kaspasim"
#define KASPA_PREFIX_DEVNET "kaspadev"
#define KASPA_SUFFIX_MAINNET "KAS"
#define KASPA_SUFFIX_TESTNET "TKAS"
#define KASPA_SUFFIX_SIMNET "SKAS"
#define KASPA_SUFFIX_DEVNET "DKAS"
static const char *TRANSACTION_SIGNING_DOMAIN = "TransactionSigningHash";
static const char *TRANSACTION_ID_DOMAIN = "TransactionID";
static const char *INPUT_CHECKSUM_DOMAIN = "KaspaInputChecksum";
static const uint8_t TRANSACTION_SIGNING_ECDSA_DOMAIN_HASH[32] = {
    164, 242, 236, 228, 90, 40, 108, 177, 236, 10, 78,  77, 56,  52,  104, 208,
    0,   247, 23,  87,  5,  43, 21,  4,   170, 52, 149, 50, 141, 245, 244, 234};

uint32_t input_count;
uint32_t input_index;
static bool kaspa_signing = false;
static KaspaSigningMode signing_mode = KASPA_SIGNING_MODE_NONE;
static bool use_tweak_g = true;
static bool is_schnorr = true;
static char prefix[10] = {0};
static char previous_address[72] = {0};

typedef struct {
  BLAKE2B_CTX previous_outputs_hasher;
  BLAKE2B_CTX sequences_hasher;
  BLAKE2B_CTX sig_op_counts_hasher;
  BLAKE2B_CTX input_checksum_hasher;
} KaspaCollectInputState;

typedef struct {
  BLAKE2B_CTX outputs_hasher;
} KaspaCollectOutputState;

typedef struct {
  BLAKE2B_CTX payload_hasher;
  uint32_t pending_payload_length;
} KaspaCollectPayloadState;

typedef enum {
  KASPA_PROGRESS_STAGE_NONE = 0,
  KASPA_PROGRESS_STAGE_LOADING_INPUTS,
  KASPA_PROGRESS_STAGE_LOADING_PAYLOAD,
  KASPA_PROGRESS_STAGE_VERIFYING,
  KASPA_PROGRESS_STAGE_SIGNING,
} KaspaProgressStage;

typedef struct {
  BLAKE2B_CTX input_checksum_hasher;
  BLAKE2B_CTX prev_tx_hasher;
  uint64_t active_amount;
  uint64_t prev_lock_time;
  uint64_t prev_gas;
  uint32_t current_input_index;
  uint32_t active_prev_output_index;
  uint32_t active_script_public_key_len;
  uint32_t prev_input_count;
  uint32_t prev_output_count;
  uint32_t prev_payload_length;
  uint32_t prev_payload_left;
  uint32_t pending_payload_length;
  uint8_t active_prev_tx_id[KASPA_TX_ID_LEN];
  uint8_t active_script_public_key[KASPA_MAX_SCRIPT_PUBLIC_KEY_LEN];
  uint8_t prev_subnetwork_id[KASPA_SUBNETWORK_ID_LEN];
  bool selected_output_verified;
} KaspaVerifyState;

typedef struct {
  uint64_t lock_time;
  uint64_t total_input;
  uint64_t total_change;
  uint64_t total_output;
  uint64_t gas;
  uint32_t input_count;
  uint32_t output_count;
  uint32_t shared_account_root[KASPA_ACCOUNT_ROOT_LEN];
  uint32_t request_index;
  uint32_t sign_index;
  uint32_t version;
  uint32_t payload_length;
  uint32_t payload_left;
  KaspaSigningPhase phase;
  KaspaProgressStage progress_stage;
  uint8_t previous_outputs_hash[32];
  uint8_t sequences_hash[32];
  uint8_t sig_op_counts_hash[32];
  uint8_t outputs_hash[32];
  uint8_t payload_hash[32];
  uint8_t input_checksum[KASPA_HASH_SIZE];
  uint8_t subnetwork_id[20];
  uint8_t displayed_progress_percent;
  bool has_shared_account_root;
  bool all_inputs_same_account_root;
  union {
    KaspaCollectInputState collect_inputs;
    KaspaCollectOutputState collect_outputs;
    KaspaCollectPayloadState collect_payload;
    KaspaVerifyState verify;
  } phase_state;
} KaspaSigningContext;

static KaspaSigningContext signing_ctx;

#define CALCULATE_SIGNING_HASH(pre_image, pre_image_len)           \
  uint8_t schnorr_digest[32] = {0};                                \
  BLAKE2B_CTX ctx;                                                 \
  blake2b_InitKey(&ctx, 32, (uint8_t *)TRANSACTION_SIGNING_DOMAIN, \
                  strlen(TRANSACTION_SIGNING_DOMAIN));             \
  blake2b_Update(&ctx, pre_image, pre_image_len);                  \
  blake2b_Final(&ctx, schnorr_digest, 32);

#define CALCULATE_SIGNING_HASH_ECDSA                                  \
  uint8_t ecdsa_digest[32] = {0};                                     \
  SHA256_CTX sha_ctx;                                                 \
  sha256_Init(&sha_ctx);                                              \
  sha256_Update(&sha_ctx, TRANSACTION_SIGNING_ECDSA_DOMAIN_HASH, 32); \
  sha256_Update(&sha_ctx, schnorr_digest, 32);                        \
  sha256_Final(&sha_ctx, ecdsa_digest);

bool kaspa_valid_scheme(const char *scheme) {
  return strcmp(scheme, KASPA_SCHEME_SCHNORR) == 0 ||
         strcmp(scheme, KASPA_SCHEME_ECDSA) == 0;
}

bool kaspa_valid_prefix(const char *addr_prefix) {
  return strcmp(addr_prefix, KASPA_PREFIX_MAINNET) == 0 ||
         strcmp(addr_prefix, KASPA_PREFIX_TESTNET) == 0 ||
         strcmp(addr_prefix, KASPA_PREFIX_SIMNET) == 0 ||
         strcmp(addr_prefix, KASPA_PREFIX_DEVNET) == 0;
}

static const char *kaspa_suffix_from_prefix(const char *addr_prefix) {
  if (strcmp(addr_prefix, KASPA_PREFIX_TESTNET) == 0) {
    return KASPA_SUFFIX_TESTNET;
  }
  if (strcmp(addr_prefix, KASPA_PREFIX_SIMNET) == 0) {
    return KASPA_SUFFIX_SIMNET;
  }
  if (strcmp(addr_prefix, KASPA_PREFIX_DEVNET) == 0) {
    return KASPA_SUFFIX_DEVNET;
  }
  return KASPA_SUFFIX_MAINNET;
}

static void kaspa_blake2b_init(BLAKE2B_CTX *ctx) {
  blake2b_InitKey(ctx, 32, (uint8_t *)TRANSACTION_SIGNING_DOMAIN,
                  strlen(TRANSACTION_SIGNING_DOMAIN));
}

static void kaspa_transaction_id_init(BLAKE2B_CTX *ctx) {
  blake2b_InitKey(ctx, KASPA_HASH_SIZE, (uint8_t *)TRANSACTION_ID_DOMAIN,
                  strlen(TRANSACTION_ID_DOMAIN));
}

static void kaspa_input_checksum_init(BLAKE2B_CTX *ctx) {
  blake2b_InitKey(ctx, KASPA_HASH_SIZE, (uint8_t *)INPUT_CHECKSUM_DOMAIN,
                  strlen(INPUT_CHECKSUM_DOMAIN));
}

static void kaspa_hash_update_u8(BLAKE2B_CTX *ctx, uint8_t value) {
  blake2b_Update(ctx, &value, sizeof(value));
}

static void kaspa_hash_update_u16(BLAKE2B_CTX *ctx, uint16_t value) {
  uint8_t data[2] = {value & 0xff, value >> 8};
  blake2b_Update(ctx, data, sizeof(data));
}

static void kaspa_hash_update_u32(BLAKE2B_CTX *ctx, uint32_t value) {
  uint8_t data[4] = {value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff,
                     value >> 24};
  blake2b_Update(ctx, data, sizeof(data));
}

static void kaspa_hash_update_u64(BLAKE2B_CTX *ctx, uint64_t value) {
  uint8_t data[8] = {value & 0xff,         (value >> 8) & 0xff,
                     (value >> 16) & 0xff, (value >> 24) & 0xff,
                     (value >> 32) & 0xff, (value >> 40) & 0xff,
                     (value >> 48) & 0xff, value >> 56};
  blake2b_Update(ctx, data, sizeof(data));
}

static void kaspa_hash_update_var_bytes(BLAKE2B_CTX *ctx, const uint8_t *bytes,
                                        uint64_t len) {
  kaspa_hash_update_u64(ctx, len);
  blake2b_Update(ctx, bytes, len);
}

static void kaspa_blake2b_finalize_into(BLAKE2B_CTX *ctx, uint8_t hash[32]) {
  blake2b_Final(ctx, hash, 32);
}

static void kaspa_hash_input_outpoint(BLAKE2B_CTX *ctx, const uint8_t tx_id[32],
                                      uint32_t index) {
  blake2b_Update(ctx, tx_id, 32);
  kaspa_hash_update_u32(ctx, index);
}

static void kaspa_hash_input_sequence(BLAKE2B_CTX *ctx, uint64_t sequence) {
  kaspa_hash_update_u64(ctx, sequence);
}

static void kaspa_hash_input_sig_op_count(BLAKE2B_CTX *ctx,
                                          uint8_t sig_op_count) {
  kaspa_hash_update_u8(ctx, sig_op_count);
}

static KaspaInputScriptType kaspa_input_script_type(
    const KaspaTxAckInput *input) {
  return input->has_script_type ? input->script_type
                                : KaspaInputScriptType_KASPA_SPEND_P2PK_SCHNORR;
}

static bool kaspa_input_is_schnorr(const KaspaTxAckInput *input) {
  return kaspa_input_script_type(input) ==
         KaspaInputScriptType_KASPA_SPEND_P2PK_SCHNORR;
}

static bool kaspa_input_use_tweak(const KaspaTxAckInput *input) {
  return !input->has_use_tweak || input->use_tweak;
}

static void kaspa_hash_input_checksum(BLAKE2B_CTX *ctx,
                                      const KaspaTxAckInput *input) {
  blake2b_Update(ctx, input->previous_outpoint.tx_id.bytes,
                 input->previous_outpoint.tx_id.size);
  kaspa_hash_update_u32(ctx, input->previous_outpoint.index);
  kaspa_hash_update_u64(ctx, input->amount);
  kaspa_hash_update_u64(ctx, input->sequence);
  kaspa_hash_update_u8(ctx, input->sig_op_count);
  kaspa_hash_update_u32(ctx, input->address_n_count);
  for (uint32_t i = 0; i < input->address_n_count; i++) {
    kaspa_hash_update_u32(ctx, input->address_n[i]);
  }
  kaspa_hash_update_u8(ctx, (uint8_t)kaspa_input_script_type(input));
  kaspa_hash_update_u8(ctx, (uint8_t)kaspa_input_use_tweak(input));
}

static void kaspa_hash_output(BLAKE2B_CTX *ctx, uint64_t amount,
                              uint16_t script_version,
                              const uint8_t *script_public_key,
                              uint32_t script_public_key_len) {
  kaspa_hash_update_u64(ctx, amount);
  kaspa_hash_update_u16(ctx, script_version);
  kaspa_hash_update_var_bytes(ctx, script_public_key, script_public_key_len);
}

static bool kaspa_extract_account_root(
    const uint32_t *address_n, uint32_t address_n_count,
    uint32_t account_root[KASPA_ACCOUNT_ROOT_LEN]) {
  if (address_n_count < KASPA_ACCOUNT_ROOT_LEN) {
    return false;
  }
  memcpy(account_root, address_n,
         KASPA_ACCOUNT_ROOT_LEN * sizeof(account_root[0]));
  return true;
}

static bool kaspa_account_roots_equal(
    const uint32_t lhs[KASPA_ACCOUNT_ROOT_LEN],
    const uint32_t rhs[KASPA_ACCOUNT_ROOT_LEN]) {
  return memcmp(lhs, rhs, KASPA_ACCOUNT_ROOT_LEN * sizeof(lhs[0])) == 0;
}

static bool kaspa_output_path_has_allowed_branch(const uint32_t *address_n,
                                                 uint32_t address_n_count) {
  if (address_n_count <= KASPA_CHANGE_BRANCH_INDEX) {
    return false;
  }
  uint32_t branch = address_n[KASPA_CHANGE_BRANCH_INDEX];
  return branch == KASPA_EXTERNAL_BRANCH ||
         branch == KASPA_INTERNAL_CHANGE_BRANCH;
}

static bool kaspa_output_is_trusted_hidden_change(
    const KaspaTxAckOutput *output) {
  uint32_t output_account_root[KASPA_ACCOUNT_ROOT_LEN] = {0};

  if (!signing_ctx.has_shared_account_root ||
      !signing_ctx.all_inputs_same_account_root) {
    return false;
  }
  if (!kaspa_extract_account_root(output->address_n, output->address_n_count,
                                  output_account_root)) {
    return false;
  }
  if (!kaspa_account_roots_equal(output_account_root,
                                 signing_ctx.shared_account_root)) {
    return false;
  }
  return kaspa_output_path_has_allowed_branch(output->address_n,
                                              output->address_n_count);
}

static bool kaspa_sign_bip340_digest(HDNode *node, bool use_tweak,
                                     const uint8_t digest[32],
                                     uint8_t *signature,
                                     pb_size_t *signature_len) {
#if EMULATOR
  if (use_tweak) {
    tx_sign_bip340(node->private_key, digest, signature, signature_len);
  } else {
    tx_sign_bip340_internal(node->private_key, digest, signature,
                            signature_len);
  }
#else
  int ret = use_tweak
                ? hdnode_bip340_sign_digest(node, digest, signature)
                : hdnode_bip340_sign_digest_internal(node, digest, signature);
  if (ret != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    kaspa_signing_abort();
    return false;
  }
  *signature_len = 64;
#endif
  return true;
}

static bool kaspa_sign_ecdsa_digest(HDNode *node, const uint8_t digest[32],
                                    uint8_t *signature,
                                    pb_size_t *signature_len) {
#if EMULATOR
  tx_sign_ecdsa(&secp256k1, node->private_key, digest, signature,
                signature_len);
#else
  uint8_t sig[64];
  int ret = hdnode_sign_digest(node, digest, sig, NULL, NULL);
  if (ret != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    kaspa_signing_abort();
    return false;
  }
  *signature_len = ecdsa_sig_to_der(sig, signature);
#endif
  return true;
}

static void kaspa_streaming_init_input_hashers(void) {
  kaspa_blake2b_init(
      &signing_ctx.phase_state.collect_inputs.previous_outputs_hasher);
  kaspa_blake2b_init(&signing_ctx.phase_state.collect_inputs.sequences_hasher);
  kaspa_blake2b_init(
      &signing_ctx.phase_state.collect_inputs.sig_op_counts_hasher);
  kaspa_input_checksum_init(
      &signing_ctx.phase_state.collect_inputs.input_checksum_hasher);
}

static void kaspa_streaming_init_output_hasher(void) {
  kaspa_blake2b_init(&signing_ctx.phase_state.collect_outputs.outputs_hasher);
}

static void kaspa_streaming_init_payload_hasher(void) {
  kaspa_blake2b_init(&signing_ctx.phase_state.collect_payload.payload_hasher);
  // Kaspa payload_hash uses write_var_bytes(payload): length prefix followed by
  // the streamed payload bytes.
  kaspa_hash_update_u64(&signing_ctx.phase_state.collect_payload.payload_hasher,
                        signing_ctx.payload_left);
  signing_ctx.phase_state.collect_payload.pending_payload_length = 0;
}

static void kaspa_streaming_finalize_input_hashes(void) {
  kaspa_blake2b_finalize_into(
      &signing_ctx.phase_state.collect_inputs.previous_outputs_hasher,
      signing_ctx.previous_outputs_hash);
  kaspa_blake2b_finalize_into(
      &signing_ctx.phase_state.collect_inputs.sequences_hasher,
      signing_ctx.sequences_hash);
  kaspa_blake2b_finalize_into(
      &signing_ctx.phase_state.collect_inputs.sig_op_counts_hasher,
      signing_ctx.sig_op_counts_hash);
  kaspa_blake2b_finalize_into(
      &signing_ctx.phase_state.collect_inputs.input_checksum_hasher,
      signing_ctx.input_checksum);
}

static void kaspa_streaming_begin_verification(void) {
  memzero(&signing_ctx.phase_state, sizeof(signing_ctx.phase_state));
  kaspa_input_checksum_init(
      &signing_ctx.phase_state.verify.input_checksum_hasher);
  signing_ctx.request_index = 0;
  signing_ctx.phase_state.verify.current_input_index = 0;
  signing_ctx.phase = KASPA_PHASE_REPLAY_INPUT;
}

static void kaspa_streaming_finalize_output_hashes(void) {
  kaspa_blake2b_finalize_into(
      &signing_ctx.phase_state.collect_outputs.outputs_hasher,
      signing_ctx.outputs_hash);
}

static void kaspa_calculate_schnorr_digest(const KaspaTxAckInput *input,
                                           const uint8_t *script_public_key,
                                           uint32_t script_public_key_len,
                                           uint8_t *digest) {
  BLAKE2B_CTX ctx;
  kaspa_blake2b_init(&ctx);
  kaspa_hash_update_u16(&ctx, signing_ctx.version);
  blake2b_Update(&ctx, signing_ctx.previous_outputs_hash,
                 sizeof(signing_ctx.previous_outputs_hash));
  blake2b_Update(&ctx, signing_ctx.sequences_hash,
                 sizeof(signing_ctx.sequences_hash));
  blake2b_Update(&ctx, signing_ctx.sig_op_counts_hash,
                 sizeof(signing_ctx.sig_op_counts_hash));
  blake2b_Update(&ctx, input->previous_outpoint.tx_id.bytes,
                 input->previous_outpoint.tx_id.size);
  kaspa_hash_update_u32(&ctx, input->previous_outpoint.index);
  kaspa_hash_update_u16(&ctx, 0);
  kaspa_hash_update_var_bytes(&ctx, script_public_key, script_public_key_len);
  kaspa_hash_update_u64(&ctx, input->amount);
  kaspa_hash_update_u64(&ctx, input->sequence);
  kaspa_hash_update_u8(&ctx, input->sig_op_count);
  blake2b_Update(&ctx, signing_ctx.outputs_hash,
                 sizeof(signing_ctx.outputs_hash));
  kaspa_hash_update_u64(&ctx, signing_ctx.lock_time);
  blake2b_Update(&ctx, signing_ctx.subnetwork_id,
                 sizeof(signing_ctx.subnetwork_id));
  kaspa_hash_update_u64(&ctx, signing_ctx.gas);
  blake2b_Update(&ctx, signing_ctx.payload_hash,
                 sizeof(signing_ctx.payload_hash));
  kaspa_hash_update_u8(&ctx, KASPA_SIG_HASH_ALL);
  kaspa_blake2b_finalize_into(&ctx, digest);
}

static uint32_t kaspa_build_standard_script(HDNode *node, bool schnorr,
                                            bool use_tweak, uint8_t *script) {
  hdnode_fill_public_key(node);
  if (schnorr) {
    script[0] = KASPA_OP_DATA_32;
    if (use_tweak) {
      zkp_bip340_tweak_public_key(node->public_key + 1, NULL, script + 1);
    } else {
      memcpy(script + 1, node->public_key + 1, PUBKEY_LEN);
    }
    script[33] = KASPA_OP_CHECK_SIG;
    return KASPA_SCRIPT_P2PK_SCHNORR_LEN;
  }

  script[0] = KASPA_OP_DATA_33;
  memcpy(script + 1, node->public_key, PUBKEY_ECDSA_LEN);
  script[34] = KASPA_OP_CHECK_SIG_ECDSA;
  return KASPA_SCRIPT_P2PK_ECDSA_LEN;
}

// static bool kaspa_script_to_address(const uint8_t *script, uint32_t
// script_len,
//                                     const char *addr_prefix, char *address,
//                                     size_t address_len) {
//   uint8_t payload[PUBKEY_ECDSA_LEN + 1] = {0};
//   size_t payload_len = 0;
//   if (script_len == KASPA_SCRIPT_P2PK_SCHNORR_LEN &&
//       script[0] == KASPA_OP_DATA_32 && script[33] == KASPA_OP_CHECK_SIG) {
//     payload[0] = PUBKEY_VERSION;
//     memcpy(payload + 1, script + 1, PUBKEY_LEN);
//     payload_len = PUBKEY_LEN + 1;
//   } else if (script_len == KASPA_SCRIPT_P2PK_ECDSA_LEN &&
//              script[0] == KASPA_OP_DATA_33 &&
//              script[34] == KASPA_OP_CHECK_SIG_ECDSA) {
//     payload[0] = PUBKEY_ECDSA_VERSION;
//     memcpy(payload + 1, script + 1, PUBKEY_ECDSA_LEN);
//     payload_len = PUBKEY_ECDSA_LEN + 1;
//   } else if (script_len == KASPA_SCRIPT_P2SH_LEN &&
//              script[0] == KASPA_OP_BLAKE2B && script[1] == KASPA_OP_DATA_32
//              && script[34] == KASPA_OP_EQUAL) {
//     payload[0] = SCRIPT_HASH_VERSION;
//     memcpy(payload + 1, script + 2, PUBKEY_LEN);
//     payload_len = PUBKEY_LEN + 1;
//   } else {
//     return false;
//   }
//   if (!cash_addr_encode(address, addr_prefix, payload, payload_len)) {
//     memzero(address, address_len);
//     return false;
//   }
//   return true;
// }

extern bool button_request(const ButtonRequestType code);

static void kaspa_format_amount(uint64_t amount, char *buf, size_t buflen) {
  char suffix[8] = {0};
  snprintf(suffix, sizeof(suffix), " %s", kaspa_suffix_from_prefix(prefix));
  bn_format_amount(amount, NULL, suffix, 8, buf, buflen);
}

static bool kaspa_confirm_payload_hash(void) {
  layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                              &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                              NULL, NULL,
                              _(SECURITY__SOLANA_RAW_SIGNING_TX_WARNING));
  if (protectWaitKeyValue(ButtonRequestType_ButtonRequest_SignTx, true, 0, 0) !=
      KEY_CONFIRM) {
    return false;
  }
  oledClear();
  layoutHeader(_(T__SIGN_TRANSACTION));
  oledDrawStringAdapter(0, 13, _(I__DATA_COLON), FONT_STANDARD);
  char message[65];
  data2hex(signing_ctx.payload_hash, sizeof(signing_ctx.payload_hash), message);
  uint8_t bubble_key = oledDrawPageableStringAdapter(
      0, 13 + 10, message, FONT_STANDARD, &bmp_bottom_left_close,
      &bmp_bottom_right_confirm);
  return bubble_key == KEY_CONFIRM;
}

bool kaspa_is_legacy_signing(const KaspaSignTx *msg) {
  return msg->has_raw_message;
}

bool kaspa_is_streaming_signing(const KaspaSignTx *msg) {
  // output_count is mandatory for streaming. Other streaming fields have
  // defaults and may be serialized by hosts that still use raw_message.
  return !msg->has_raw_message || msg->has_output_count;
}

KaspaSigningMode kaspa_signing_mode(void) { return signing_mode; }

KaspaSigningPhase kaspa_signing_phase(void) { return signing_ctx.phase; }

void kaspa_signing_init(const KaspaSignTx *msg) {
  kaspa_signing = true;
  signing_mode = KASPA_SIGNING_MODE_LEGACY;
  input_count = msg->input_count;
  input_index = 1;
  use_tweak_g = !msg->has_use_tweak || msg->use_tweak;
  is_schnorr = strcmp(msg->scheme, KASPA_SCHEME_SCHNORR) == 0;
  memzero(prefix, sizeof(prefix));
  memcpy(prefix, msg->prefix, sizeof(msg->prefix));
}

void kaspa_signing_clear_runtime_state(void) {
  if (kaspa_signing || signing_mode != KASPA_SIGNING_MODE_NONE) {
    kaspa_signing = false;
    signing_mode = KASPA_SIGNING_MODE_NONE;
    input_count = 0;
    input_index = 0;
    use_tweak_g = true;
    is_schnorr = true;
    memzero(prefix, sizeof(prefix));
    memzero(previous_address, sizeof(previous_address));
    memzero(&signing_ctx, sizeof(signing_ctx));
  }
}

void kaspa_signing_abort(void) {
  bool was_active = kaspa_signing || signing_mode != KASPA_SIGNING_MODE_NONE;
  kaspa_signing_clear_runtime_state();
  if (was_active) {
    layoutHome();
  }
}

bool kaspa_streaming_signing_init(const KaspaSignTx *msg) {
  if (msg->input_count < 1 || !msg->has_output_count || msg->output_count < 1) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid transaction counts");
    return false;
  }
  if (msg->has_scheme && !kaspa_valid_scheme(msg->scheme)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid scheme");
    return false;
  }
  if (msg->has_version && msg->version != 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid transaction version");
    return false;
  }
  if (strlen(msg->prefix) >= sizeof(prefix) ||
      !kaspa_valid_prefix(msg->prefix)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid prefix");
    return false;
  }
  if (msg->has_subnetwork_id &&
      msg->subnetwork_id.size != KASPA_SUBNETWORK_ID_LEN) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid subnetwork id");
    return false;
  }
  if (msg->has_subnetwork_id) {
    for (uint32_t i = 0; i < msg->subnetwork_id.size; i++) {
      if (msg->subnetwork_id.bytes[i] != 0) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Unsupported Kaspa subnetwork id");
        return false;
      }
    }
  }
  if ((msg->has_gas && msg->gas != 0)) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Unsupported Kaspa gas value");
    return false;
  }
  if (msg->has_payload_length &&
      msg->payload_length > KASPA_MAX_PAYLOAD_LENGTH) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid Kaspa payload length");
    return false;
  }

  kaspa_signing = true;
  signing_mode = KASPA_SIGNING_MODE_STREAMING;
  use_tweak_g = !msg->has_use_tweak || msg->use_tweak;
  is_schnorr =
      !msg->has_scheme || strcmp(msg->scheme, KASPA_SCHEME_SCHNORR) == 0;
  memzero(prefix, sizeof(prefix));
  memcpy(prefix, msg->prefix, sizeof(prefix));
  memzero(&signing_ctx, sizeof(signing_ctx));
  signing_ctx.all_inputs_same_account_root = true;
  kaspa_streaming_init_input_hashers();
  signing_ctx.input_count = msg->input_count;
  signing_ctx.output_count = msg->output_count;
  signing_ctx.version = msg->has_version ? msg->version : 0;
  signing_ctx.lock_time = msg->has_lock_time ? msg->lock_time : 0;
  signing_ctx.gas = msg->has_gas ? msg->gas : 0;
  signing_ctx.phase = KASPA_PHASE_COLLECT_INPUTS;
  signing_ctx.payload_length =
      msg->has_payload_length ? msg->payload_length : 0;
  signing_ctx.payload_left = signing_ctx.payload_length;
  return true;
}

static bool kaspa_script_from_address(const char *address, uint8_t *script,
                                      uint32_t *script_len,
                                      const char *expected_prefix) {
  uint8_t payload[65] = {0};
  size_t payload_len = sizeof(payload);
  if (!cash_addr_decode(payload, &payload_len, expected_prefix, address)) {
    return false;
  }

  if (payload_len == PUBKEY_LEN + 1 && payload[0] == PUBKEY_VERSION) {
    script[0] = KASPA_OP_DATA_32;
    memcpy(script + 1, payload + 1, PUBKEY_LEN);
    script[33] = KASPA_OP_CHECK_SIG;
    *script_len = KASPA_SCRIPT_P2PK_SCHNORR_LEN;
    return true;
  }

  if (payload_len == PUBKEY_ECDSA_LEN + 1 &&
      payload[0] == PUBKEY_ECDSA_VERSION) {
    script[0] = KASPA_OP_DATA_33;
    memcpy(script + 1, payload + 1, PUBKEY_ECDSA_LEN);
    script[34] = KASPA_OP_CHECK_SIG_ECDSA;
    *script_len = KASPA_SCRIPT_P2PK_ECDSA_LEN;
    return true;
  }

  if (payload_len == PUBKEY_LEN + 1 && payload[0] == SCRIPT_HASH_VERSION) {
    script[0] = KASPA_OP_BLAKE2B;
    script[1] = KASPA_OP_DATA_32;
    memcpy(script + 2, payload + 1, PUBKEY_LEN);
    script[34] = KASPA_OP_EQUAL;
    *script_len = KASPA_SCRIPT_P2SH_LEN;
    return true;
  }

  return false;
}

static bool kaspa_validate_standard_input(const KaspaTxAckInput *input) {
  KaspaInputScriptType script_type = kaspa_input_script_type(input);

  if (input->previous_outpoint.tx_id.size != KASPA_TX_ID_LEN) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid Kaspa outpoint tx id");
    return false;
  }
  if (input->sig_op_count != 1) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid Kaspa sig op count");
    return false;
  }
  if (script_type != KaspaInputScriptType_KASPA_SPEND_P2PK_SCHNORR &&
      script_type != KaspaInputScriptType_KASPA_SPEND_P2PK_ECDSA) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Unsupported Kaspa input script type");
    return false;
  }

  return true;
}

bool kaspa_process_input(const KaspaTxAckInput *input) {
  uint32_t current_account_root[KASPA_ACCOUNT_ROOT_LEN] = {0};

  if (signing_mode != KASPA_SIGNING_MODE_STREAMING ||
      (signing_ctx.phase != KASPA_PHASE_COLLECT_INPUTS) ||
      signing_ctx.request_index >= signing_ctx.input_count) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa input collect state");
    return false;
  }
  if (!kaspa_validate_standard_input(input)) {
    return false;
  }
  if (!kaspa_extract_account_root(input->address_n, input->address_n_count,
                                  current_account_root)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid Kaspa input path");
    return false;
  }
  if (!signing_ctx.has_shared_account_root) {
    memcpy(signing_ctx.shared_account_root, current_account_root,
           sizeof(signing_ctx.shared_account_root));
    signing_ctx.has_shared_account_root = true;
  } else if (signing_ctx.all_inputs_same_account_root &&
             !kaspa_account_roots_equal(signing_ctx.shared_account_root,
                                        current_account_root)) {
    signing_ctx.all_inputs_same_account_root = false;
  }
  if (UINT64_MAX - signing_ctx.total_input < input->amount) {
    fsm_sendFailure(FailureType_Failure_DataError, "Input amount overflow");
    return false;
  }

  kaspa_hash_input_outpoint(
      &signing_ctx.phase_state.collect_inputs.previous_outputs_hasher,
      input->previous_outpoint.tx_id.bytes, input->previous_outpoint.index);
  kaspa_hash_input_sequence(
      &signing_ctx.phase_state.collect_inputs.sequences_hasher,
      input->sequence);
  kaspa_hash_input_sig_op_count(
      &signing_ctx.phase_state.collect_inputs.sig_op_counts_hasher,
      input->sig_op_count);
  kaspa_hash_input_checksum(
      &signing_ctx.phase_state.collect_inputs.input_checksum_hasher, input);

  signing_ctx.total_input += input->amount;
  signing_ctx.request_index++;
  if (signing_ctx.request_index == signing_ctx.input_count) {
    kaspa_streaming_finalize_input_hashes();
    signing_ctx.request_index = 0;
    signing_ctx.phase = KASPA_PHASE_COLLECT_OUTPUTS;
    kaspa_streaming_init_output_hasher();
  }
  return true;
}

bool kaspa_prepare_prev_tx_verification(const KaspaTxAckInput *input,
                                        HDNode *node) {
  KaspaVerifyState *verify = &signing_ctx.phase_state.verify;

  if (signing_mode != KASPA_SIGNING_MODE_STREAMING ||
      signing_ctx.phase != KASPA_PHASE_REPLAY_INPUT ||
      signing_ctx.request_index >= signing_ctx.input_count ||
      signing_ctx.request_index != verify->current_input_index) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa verification input");
    return false;
  }
  if (!kaspa_validate_standard_input(input)) {
    return false;
  }

  kaspa_hash_input_checksum(&verify->input_checksum_hasher, input);
  verify->active_script_public_key_len = kaspa_build_standard_script(
      node, kaspa_input_is_schnorr(input), kaspa_input_use_tweak(input),
      verify->active_script_public_key);
  memcpy(verify->active_prev_tx_id, input->previous_outpoint.tx_id.bytes,
         KASPA_TX_ID_LEN);
  verify->active_prev_output_index = input->previous_outpoint.index;
  verify->active_amount = input->amount;
  verify->selected_output_verified = false;
  signing_ctx.request_index = 0;
  signing_ctx.phase = KASPA_PHASE_VERIFY_PREV_META;
  return true;
}

static void kaspa_prev_tx_begin_outputs(KaspaVerifyState *verify) {
  kaspa_hash_update_u64(&verify->prev_tx_hasher, verify->prev_output_count);
  signing_ctx.request_index = 0;
  signing_ctx.phase = KASPA_PHASE_VERIFY_PREV_OUTPUTS;
}

static bool kaspa_finish_verified_prev_tx(void) {
  KaspaVerifyState *verify = &signing_ctx.phase_state.verify;
  uint8_t calculated_tx_id[KASPA_TX_ID_LEN] = {0};

  kaspa_blake2b_finalize_into(&verify->prev_tx_hasher, calculated_tx_id);
  if (memcmp(calculated_tx_id, verify->active_prev_tx_id,
             sizeof(calculated_tx_id)) != 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Kaspa previous transaction id mismatch");
    return false;
  }

  verify->current_input_index++;
  if (verify->current_input_index < signing_ctx.input_count) {
    signing_ctx.request_index = verify->current_input_index;
    signing_ctx.phase = KASPA_PHASE_REPLAY_INPUT;
    return true;
  }

  uint8_t verification_checksum[KASPA_HASH_SIZE] = {0};
  kaspa_blake2b_finalize_into(&verify->input_checksum_hasher,
                              verification_checksum);
  if (memcmp(verification_checksum, signing_ctx.input_checksum,
             sizeof(verification_checksum)) != 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Kaspa inputs changed during verification");
    return false;
  }

  signing_ctx.request_index = 0;
  signing_ctx.sign_index = 0;
  signing_ctx.phase = KASPA_PHASE_CONFIRM_TOTAL;
  if (!kaspa_confirm_total()) {
    return false;
  }
  signing_ctx.phase = KASPA_PHASE_SIGN_INPUTS;
  return true;
}

bool kaspa_process_prev_meta(const KaspaTxAckPrevMeta *meta) {
  KaspaVerifyState *verify = &signing_ctx.phase_state.verify;

  if (signing_mode != KASPA_SIGNING_MODE_STREAMING ||
      signing_ctx.phase != KASPA_PHASE_VERIFY_PREV_META) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa previous transaction metadata");
    return false;
  }
  if (meta->version != 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Unsupported Kaspa previous transaction version");
    return false;
  }
  if (meta->subnetwork_id.size != KASPA_SUBNETWORK_ID_LEN) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid Kaspa previous subnetwork id");
    return false;
  }
  if (verify->active_prev_output_index >= meta->output_count) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid Kaspa previous output index");
    return false;
  }

  verify->prev_input_count = meta->input_count;
  verify->prev_output_count = meta->output_count;
  verify->prev_lock_time = meta->lock_time;
  verify->prev_gas = meta->gas;
  verify->prev_payload_length = meta->payload_length;
  verify->prev_payload_left = verify->prev_payload_length;
  verify->pending_payload_length = 0;
  memcpy(verify->prev_subnetwork_id, meta->subnetwork_id.bytes,
         KASPA_SUBNETWORK_ID_LEN);

  kaspa_transaction_id_init(&verify->prev_tx_hasher);
  kaspa_hash_update_u16(&verify->prev_tx_hasher, 0);
  kaspa_hash_update_u64(&verify->prev_tx_hasher, verify->prev_input_count);
  signing_ctx.request_index = 0;
  if (verify->prev_input_count > 0) {
    signing_ctx.phase = KASPA_PHASE_VERIFY_PREV_INPUTS;
  } else {
    kaspa_prev_tx_begin_outputs(verify);
  }
  return true;
}

bool kaspa_process_prev_input(const KaspaTxAckPrevInput *input) {
  KaspaVerifyState *verify = &signing_ctx.phase_state.verify;

  if (signing_mode != KASPA_SIGNING_MODE_STREAMING ||
      signing_ctx.phase != KASPA_PHASE_VERIFY_PREV_INPUTS ||
      signing_ctx.request_index >= verify->prev_input_count) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa previous input");
    return false;
  }
  if (input->previous_outpoint.tx_id.size != KASPA_TX_ID_LEN) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid Kaspa previous input tx id");
    return false;
  }

  kaspa_hash_input_outpoint(&verify->prev_tx_hasher,
                            input->previous_outpoint.tx_id.bytes,
                            input->previous_outpoint.index);
  kaspa_hash_update_u64(&verify->prev_tx_hasher, 0);
  kaspa_hash_input_sequence(&verify->prev_tx_hasher, input->sequence);

  signing_ctx.request_index++;
  if (signing_ctx.request_index == verify->prev_input_count) {
    kaspa_prev_tx_begin_outputs(verify);
  }
  return true;
}

bool kaspa_process_prev_output(const KaspaTxAckPrevOutput *output) {
  KaspaVerifyState *verify = &signing_ctx.phase_state.verify;

  if (signing_mode != KASPA_SIGNING_MODE_STREAMING ||
      signing_ctx.phase != KASPA_PHASE_VERIFY_PREV_OUTPUTS ||
      signing_ctx.request_index >= verify->prev_output_count) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa previous output");
    return false;
  }
  if (output->script_version > UINT16_MAX) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid Kaspa previous script version");
    return false;
  }
  kaspa_hash_output(
      &verify->prev_tx_hasher, output->amount, (uint16_t)output->script_version,
      output->script_public_key.bytes, output->script_public_key.size);

  if (signing_ctx.request_index == verify->active_prev_output_index) {
    if (output->amount != verify->active_amount ||
        output->script_version != 0 ||
        output->script_public_key.size !=
            verify->active_script_public_key_len ||
        memcmp(output->script_public_key.bytes,
               verify->active_script_public_key,
               verify->active_script_public_key_len) != 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Kaspa previous output does not match input");
      return false;
    }
    verify->selected_output_verified = true;
  }

  signing_ctx.request_index++;
  if (signing_ctx.request_index < verify->prev_output_count) {
    return true;
  }
  if (!verify->selected_output_verified) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Kaspa previous output was not verified");
    return false;
  }

  kaspa_hash_update_u64(&verify->prev_tx_hasher, verify->prev_lock_time);
  blake2b_Update(&verify->prev_tx_hasher, verify->prev_subnetwork_id,
                 sizeof(verify->prev_subnetwork_id));
  kaspa_hash_update_u64(&verify->prev_tx_hasher, verify->prev_gas);
  kaspa_hash_update_u64(&verify->prev_tx_hasher, verify->prev_payload_left);
  signing_ctx.request_index = 0;
  if (verify->prev_payload_left > 0) {
    verify->pending_payload_length = 0;
    signing_ctx.phase = KASPA_PHASE_VERIFY_PREV_PAYLOAD;
    return true;
  }
  return kaspa_finish_verified_prev_tx();
}

static bool kaspa_output_is_schnorr(const KaspaTxAckOutput *output) {
  return !output->has_scheme ||
         strcmp(output->scheme, KASPA_SCHEME_SCHNORR) == 0;
}

static bool kaspa_output_use_tweak(const KaspaTxAckOutput *output) {
  return !output->has_use_tweak || output->use_tweak;
}

static bool kaspa_prepare_output_address(const KaspaTxAckOutput *output,
                                         HDNode *node, bool is_change,
                                         char *address, size_t address_size) {
  if (!is_change && output->has_address) {
    strlcpy(address, output->address, address_size);
    return true;
  }

  if (output->address_n_count == 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid output parameters");
    return false;
  }
  hdnode_fill_public_key(node);
  bool is_schnorr_output = kaspa_output_is_schnorr(output);
  uint8_t public_key_len = is_schnorr_output ? PUBKEY_LEN : PUBKEY_ECDSA_LEN;
  uint8_t *public_key = node->public_key + (is_schnorr_output ? 1 : 0);
  kaspa_get_address(public_key, public_key_len, prefix, address,
                    kaspa_output_use_tweak(output));
  return true;
}

static bool kaspa_retrieve_derived_output_script(
    const KaspaTxAckOutput *output, HDNode *node, uint8_t *script_public_key,
    uint32_t *script_public_key_len) {
  if (output->address_n_count == 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid self-transfer output parameters");
    return false;
  }
  if (output->has_scheme && !kaspa_valid_scheme(output->scheme)) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid self-transfer output scheme");
    return false;
  }
  *script_public_key_len = kaspa_build_standard_script(
      node, kaspa_output_is_schnorr(output), kaspa_output_use_tweak(output),
      script_public_key);
  return true;
}

static bool kaspa_retrieve_output_script(const KaspaTxAckOutput *output,
                                         HDNode *node,
                                         uint8_t *script_public_key,
                                         uint32_t *script_public_key_len) {
  if (output->has_address) {
    if (!kaspa_script_from_address(output->address, script_public_key,
                                   script_public_key_len, prefix)) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid external output address");
      return false;
    }
    return true;
  }
  return kaspa_retrieve_derived_output_script(output, node, script_public_key,
                                              script_public_key_len);
}

bool kaspa_process_output(const KaspaTxAckOutput *output, HDNode *node) {
  if (signing_mode != KASPA_SIGNING_MODE_STREAMING ||
      signing_ctx.phase != KASPA_PHASE_COLLECT_OUTPUTS ||
      signing_ctx.request_index >= signing_ctx.output_count) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa output collect state");
    return false;
  }
  if (UINT64_MAX - signing_ctx.total_output < output->amount) {
    fsm_sendFailure(FailureType_Failure_DataError, "Output amount overflow");
    return false;
  }

  bool declared_change =
      output->script_type == KaspaOutputScriptType_KASPA_PAYTOCHANGE;
  if (declared_change && output->address_n_count == 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid change output parameters");
    return false;
  }
  bool trusted_change =
      declared_change && kaspa_output_is_trusted_hidden_change(output);
  uint8_t script_public_key[KASPA_MAX_SCRIPT_PUBLIC_KEY_LEN] = {0};
  uint32_t script_public_key_len = 0;

  if (trusted_change) {
    if (!kaspa_retrieve_derived_output_script(output, node, script_public_key,
                                              &script_public_key_len)) {
      return false;
    }
    if (UINT64_MAX - signing_ctx.total_change < output->amount) {
      fsm_sendFailure(FailureType_Failure_DataError, "Change amount overflow");
      return false;
    }
    signing_ctx.total_change += output->amount;
  } else {
    char address[72] = {0};
    char amount[60] = {0};

    if (!kaspa_prepare_output_address(output, node, false, address,
                                      sizeof(address))) {
      return false;
    }
    if (!kaspa_retrieve_output_script(output, node, script_public_key,
                                      &script_public_key_len)) {
      return false;
    }

    kaspa_format_amount(output->amount, amount, sizeof(amount));
    if (!button_request(ButtonRequestType_ButtonRequest_SignTx) ||
        !layoutConfirmOutputSimple("Kaspa", amount, address, output->address_n,
                                   output->address_n_count)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      return false;
    }
  }

  kaspa_hash_output(&signing_ctx.phase_state.collect_outputs.outputs_hasher,
                    output->amount, 0, script_public_key,
                    script_public_key_len);
  signing_ctx.total_output += output->amount;
  signing_ctx.request_index++;
  if (signing_ctx.request_index == signing_ctx.output_count) {
    kaspa_streaming_finalize_output_hashes();
    signing_ctx.request_index = 0;
    signing_ctx.sign_index = 0;
    if (signing_ctx.payload_left > 0) {
      signing_ctx.phase = KASPA_PHASE_COLLECT_PAYLOAD;
      kaspa_streaming_init_payload_hasher();
    } else {
      kaspa_streaming_begin_verification();
    }
  }
  return true;
}

bool kaspa_confirm_total(void) {
  char total_amount[60] = {0};
  char fee[60] = {0};

  if (signing_ctx.phase != KASPA_PHASE_CONFIRM_TOTAL) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Kaspa transaction not ready");
    return false;
  }
  if (signing_ctx.total_input < signing_ctx.total_output) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid output amount");
    return false;
  }

  kaspa_format_amount(signing_ctx.total_input - signing_ctx.total_change,
                      total_amount, sizeof(total_amount));
  kaspa_format_amount(signing_ctx.total_input - signing_ctx.total_output, fee,
                      sizeof(fee));
  if (!button_request(ButtonRequestType_ButtonRequest_SignTx) ||
      !layoutConfirmTxSimple("Kaspa", total_amount, fee)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    return false;
  }
  return true;
}

static void kaspa_set_prev_tx_request(KaspaTxRequest *resp) {
  KaspaVerifyState *verify = &signing_ctx.phase_state.verify;
  resp->has_prev_tx_id = true;
  resp->prev_tx_id.size = KASPA_TX_ID_LEN;
  memcpy(resp->prev_tx_id.bytes, verify->active_prev_tx_id, KASPA_TX_ID_LEN);
}

static uint32_t kaspa_payload_chunk_size(uint32_t remaining) {
  return remaining > KASPA_PAYLOAD_CHUNK_SIZE ? KASPA_PAYLOAD_CHUNK_SIZE
                                              : remaining;
}

static uint64_t kaspa_payload_chunk_count(uint32_t length) {
  return length / KASPA_PAYLOAD_CHUNK_SIZE +
         (length % KASPA_PAYLOAD_CHUNK_SIZE != 0);
}

static uint32_t kaspa_scale_progress(uint64_t completed, uint64_t total,
                                     uint32_t start, uint32_t span) {
  if (total == 0) {
    return start + span;
  }
  if (completed > total) {
    completed = total;
  }
  return start + (uint32_t)(completed * span / total);
}

static uint32_t kaspa_loading_progress(void) {
  uint64_t payload_chunks =
      kaspa_payload_chunk_count(signing_ctx.payload_length);
  // Current outputs have their own confirmation screens and are intentionally
  // excluded from loading progress.
  uint64_t total = (uint64_t)signing_ctx.input_count + payload_chunks;
  uint64_t completed = 0;

  if (signing_ctx.phase == KASPA_PHASE_COLLECT_INPUTS) {
    completed = signing_ctx.request_index;
  } else if (signing_ctx.phase == KASPA_PHASE_COLLECT_PAYLOAD) {
    completed = (uint64_t)signing_ctx.input_count + payload_chunks -
                kaspa_payload_chunk_count(signing_ctx.payload_left);
  }

  return kaspa_scale_progress(completed, total, 0, KASPA_PROGRESS_MAX);
}

static uint32_t kaspa_prev_tx_progress(void) {
  const KaspaVerifyState *verify = &signing_ctx.phase_state.verify;
  uint64_t payload_chunks =
      kaspa_payload_chunk_count(verify->prev_payload_length);
  uint64_t total = (uint64_t)verify->prev_input_count +
                   verify->prev_output_count + payload_chunks;
  uint64_t completed = 0;

  if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_INPUTS) {
    completed = signing_ctx.request_index;
  } else if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_OUTPUTS) {
    completed = (uint64_t)verify->prev_input_count + signing_ctx.request_index;
  } else if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_PAYLOAD) {
    completed = (uint64_t)verify->prev_input_count + verify->prev_output_count +
                payload_chunks -
                kaspa_payload_chunk_count(verify->prev_payload_left);
  }

  return kaspa_scale_progress(completed, total, 0, KASPA_PROGRESS_MAX);
}

static uint32_t kaspa_verification_progress(void) {
  const KaspaVerifyState *verify = &signing_ctx.phase_state.verify;
  uint32_t prev_tx_progress = 0;

  if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_INPUTS ||
      signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_OUTPUTS ||
      signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_PAYLOAD) {
    prev_tx_progress = kaspa_prev_tx_progress();
  }

  uint64_t completed =
      (uint64_t)verify->current_input_index * KASPA_PROGRESS_MAX +
      prev_tx_progress;
  uint64_t total = (uint64_t)signing_ctx.input_count * KASPA_PROGRESS_MAX;
  return kaspa_scale_progress(completed, total, 0, KASPA_PROGRESS_VERIFY_END);
}

static void kaspa_report_progress(void) {
  if (signing_ctx.input_count < KASPA_PROGRESS_MIN_INPUT_COUNT) {
    return;
  }

  KaspaProgressStage stage = KASPA_PROGRESS_STAGE_NONE;
  const char *label = NULL;
  uint32_t progress = 0;

  if (signing_ctx.phase == KASPA_PHASE_COLLECT_INPUTS) {
    stage = KASPA_PROGRESS_STAGE_LOADING_INPUTS;
    label = _(T__LOADING_TRANSACTION);
    progress = kaspa_loading_progress();
  } else if (signing_ctx.phase == KASPA_PHASE_COLLECT_PAYLOAD) {
    stage = KASPA_PROGRESS_STAGE_LOADING_PAYLOAD;
    label = _(T__LOADING_TRANSACTION);
    progress = kaspa_loading_progress();
  } else if (signing_ctx.phase == KASPA_PHASE_REPLAY_INPUT ||
             signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_META ||
             signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_INPUTS ||
             signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_OUTPUTS ||
             signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_PAYLOAD) {
    stage = KASPA_PROGRESS_STAGE_VERIFYING;
    label = _(T__SIGNING_TRANSACTION);
    progress = kaspa_verification_progress();
  } else if (signing_ctx.phase == KASPA_PHASE_SIGN_INPUTS) {
    stage = KASPA_PROGRESS_STAGE_SIGNING;
    label = _(T__SIGNING_TRANSACTION);
    progress =
        kaspa_scale_progress(signing_ctx.sign_index, signing_ctx.input_count,
                             KASPA_PROGRESS_VERIFY_END,
                             KASPA_PROGRESS_MAX - KASPA_PROGRESS_VERIFY_END);
  } else {
    return;
  }

  uint8_t progress_percent = progress / 10;
  bool force = signing_ctx.progress_stage != stage;
  if (!force && progress_percent < signing_ctx.displayed_progress_percent +
                                       KASPA_PROGRESS_UPDATE_PERCENT) {
    return;
  }

  layoutProgressAdapter(label, progress);
  signing_ctx.progress_stage = stage;
  signing_ctx.displayed_progress_percent = progress_percent;
}

bool kaspa_send_request(KaspaTxRequest *resp) {
  if (signing_mode != KASPA_SIGNING_MODE_STREAMING) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Kaspa signing mode");
    return false;
  }
  if (signing_ctx.phase == KASPA_PHASE_COLLECT_INPUTS ||
      signing_ctx.phase == KASPA_PHASE_REPLAY_INPUT ||
      signing_ctx.phase == KASPA_PHASE_SIGN_INPUTS) {
    resp->request_type = KaspaRequestType_KASPA_TX_INPUT;
    resp->has_request_index = true;
    resp->request_index = signing_ctx.request_index;
    if (signing_ctx.phase == KASPA_PHASE_SIGN_INPUTS &&
        signing_ctx.sign_index > 0) {
      resp->has_signature = true;
      resp->signature.signature_index = signing_ctx.sign_index - 1;
    }
  } else if (signing_ctx.phase == KASPA_PHASE_COLLECT_OUTPUTS) {
    resp->request_type = KaspaRequestType_KASPA_TX_OUTPUT;
    resp->has_request_index = true;
    resp->request_index = signing_ctx.request_index;
  } else if (signing_ctx.phase == KASPA_PHASE_COLLECT_PAYLOAD) {
    if (signing_ctx.payload_left == 0) {
      fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                      "No Kaspa payload pending");
      return false;
    }
    resp->request_type = KaspaRequestType_KASPA_TX_PAYLOAD;
    resp->has_request_payload_length = true;
    signing_ctx.phase_state.collect_payload.pending_payload_length =
        kaspa_payload_chunk_size(signing_ctx.payload_left);
    resp->request_payload_length =
        signing_ctx.phase_state.collect_payload.pending_payload_length;
  } else if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_META) {
    resp->request_type = KaspaRequestType_KASPA_TX_PREV_META;
    kaspa_set_prev_tx_request(resp);
  } else if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_INPUTS) {
    resp->request_type = KaspaRequestType_KASPA_TX_INPUT;
    resp->has_request_index = true;
    resp->request_index = signing_ctx.request_index;
    kaspa_set_prev_tx_request(resp);
  } else if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_OUTPUTS) {
    resp->request_type = KaspaRequestType_KASPA_TX_OUTPUT;
    resp->has_request_index = true;
    resp->request_index = signing_ctx.request_index;
    kaspa_set_prev_tx_request(resp);
  } else if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_PAYLOAD) {
    KaspaVerifyState *verify = &signing_ctx.phase_state.verify;
    if (verify->prev_payload_left == 0) {
      fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                      "No Kaspa previous payload pending");
      return false;
    }
    resp->request_type = KaspaRequestType_KASPA_TX_PAYLOAD;
    resp->has_request_payload_length = true;
    verify->pending_payload_length =
        kaspa_payload_chunk_size(verify->prev_payload_left);
    resp->request_payload_length = verify->pending_payload_length;
    kaspa_set_prev_tx_request(resp);
  } else if (signing_ctx.phase == KASPA_PHASE_FINISHED) {
    resp->request_type = KaspaRequestType_KASPA_TX_FINISHED;
    if (signing_ctx.sign_index > 0) {
      resp->has_signature = true;
      resp->signature.signature_index = signing_ctx.sign_index - 1;
    }
    kaspa_signing_abort();
  } else {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "No Kaspa request pending");
    return false;
  }
  kaspa_report_progress();
  msg_write(MessageType_MessageType_KaspaTxRequest, resp);
  return true;
}

bool kaspa_receive_payload(const KaspaTxAckPayloadChunk *payload) {
  if (signing_mode != KASPA_SIGNING_MODE_STREAMING) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa payload");
    return false;
  }

  if (signing_ctx.phase == KASPA_PHASE_COLLECT_PAYLOAD) {
    KaspaCollectPayloadState *collect =
        &signing_ctx.phase_state.collect_payload;
    if (signing_ctx.payload_left == 0 || collect->pending_payload_length == 0) {
      fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                      "Unexpected Kaspa payload");
      return false;
    }
    if (payload->payload_chunk.size != collect->pending_payload_length) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid Kaspa payload chunk length");
      return false;
    }

    blake2b_Update(&collect->payload_hasher, payload->payload_chunk.bytes,
                   payload->payload_chunk.size);
    signing_ctx.payload_left -= payload->payload_chunk.size;
    collect->pending_payload_length = 0;
    if (signing_ctx.payload_left == 0) {
      kaspa_blake2b_finalize_into(&collect->payload_hasher,
                                  signing_ctx.payload_hash);
      if (!kaspa_confirm_payload_hash()) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled by user");
        return false;
      }
      kaspa_streaming_begin_verification();
    }
    return true;
  }

  if (signing_ctx.phase == KASPA_PHASE_VERIFY_PREV_PAYLOAD) {
    KaspaVerifyState *verify = &signing_ctx.phase_state.verify;
    if (verify->prev_payload_left == 0 || verify->pending_payload_length == 0) {
      fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                      "Unexpected Kaspa previous payload");
      return false;
    }
    if (payload->payload_chunk.size != verify->pending_payload_length) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid Kaspa previous payload chunk length");
      return false;
    }

    blake2b_Update(&verify->prev_tx_hasher, payload->payload_chunk.bytes,
                   payload->payload_chunk.size);
    verify->prev_payload_left -= payload->payload_chunk.size;
    verify->pending_payload_length = 0;
    if (verify->prev_payload_left == 0) {
      return kaspa_finish_verified_prev_tx();
    }
    return true;
  }

  fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                  "Unexpected Kaspa payload");
  return false;
}

bool kaspa_sign_input(const KaspaTxAckInput *input, HDNode *node,
                      uint8_t *signature, pb_size_t *signature_len) {
  uint8_t schnorr_digest[32] = {0};
  uint8_t signing_script_public_key[KASPA_MAX_SCRIPT_PUBLIC_KEY_LEN] = {0};
  uint32_t signing_script_public_key_len = 0;

  if (signing_mode != KASPA_SIGNING_MODE_STREAMING ||
      signing_ctx.phase != KASPA_PHASE_SIGN_INPUTS ||
      signing_ctx.request_index >= signing_ctx.input_count) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Unexpected Kaspa input");
    return false;
  }
  if (!kaspa_validate_standard_input(input)) {
    return false;
  }
  // All prevouts and the ordered input replay are authenticated before this
  // phase. A changed signing-pass input cannot match both the collected shared
  // hashes and the chain's amount/script for its outpoint.
  signing_script_public_key_len = kaspa_build_standard_script(
      node, kaspa_input_is_schnorr(input), kaspa_input_use_tweak(input),
      signing_script_public_key);
  kaspa_calculate_schnorr_digest(input, signing_script_public_key,
                                 signing_script_public_key_len, schnorr_digest);

  if (kaspa_input_is_schnorr(input)) {
    if (!kaspa_sign_bip340_digest(node, kaspa_input_use_tweak(input),
                                  schnorr_digest, signature, signature_len)) {
      return false;
    }
  } else {
    uint8_t ecdsa_digest[32] = {0};
    SHA256_CTX sha_ctx;
    sha256_Init(&sha_ctx);
    sha256_Update(&sha_ctx, TRANSACTION_SIGNING_ECDSA_DOMAIN_HASH, 32);
    sha256_Update(&sha_ctx, schnorr_digest, 32);
    sha256_Final(&sha_ctx, ecdsa_digest);
    if (!kaspa_sign_ecdsa_digest(node, ecdsa_digest, signature,
                                 signature_len)) {
      return false;
    }
  }

  signing_ctx.sign_index++;
  signing_ctx.request_index++;
  if (signing_ctx.sign_index == signing_ctx.input_count) {
    signing_ctx.phase = KASPA_PHASE_FINISHED;
  }
  return true;
}

static bool show_confirm_signing(const char *address, uint8_t address_len) {
  if (strcmp(address, previous_address) == 0) {
    return false;
  } else {
    memcpy(previous_address, address, address_len);
    return true;
  }
}
void kaspa_get_address(const uint8_t *pubkey, const uint8_t pubkey_len,
                       const char *addr_prefix, char *addr, bool use_tweak) {
  if (!kaspa_valid_prefix(addr_prefix)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid prefix");
    return;
  }

  uint8_t payload[pubkey_len + 1];
  if (pubkey_len == PUBKEY_ECDSA_LEN) {
    payload[0] = PUBKEY_ECDSA_VERSION;
    memcpy(payload + 1, pubkey, pubkey_len);
  } else if (pubkey_len == PUBKEY_LEN) {
    payload[0] = PUBKEY_VERSION;
    if (use_tweak) {
      uint8_t tweaked_pubkey[32];
      zkp_bip340_tweak_public_key(pubkey, NULL, tweaked_pubkey);
      memcpy(payload + 1, tweaked_pubkey, sizeof(tweaked_pubkey));
    } else {
      memcpy(payload + 1, pubkey, pubkey_len);
    }
  } else {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid pubkey length");
    return;
  }
  if (!cash_addr_encode(addr, addr_prefix, payload, sizeof(payload))) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to encode Kaspa address");
  }
}

bool kaspa_sign_sighash(HDNode *node, const uint8_t *raw_message,
                        uint32_t raw_message_len, uint8_t *signature,
                        pb_size_t *signature_len) {
  if (!kaspa_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Kaspa signing mode");
    layoutHome();
    return false;
  }
  input_count--;
  char address[72] = {0};
  uint8_t *pub_key = node->public_key + (is_schnorr ? 1 : 0);
  uint32_t key_len = is_schnorr ? 32 : 33;
  kaspa_get_address(pub_key, key_len, prefix, address, use_tweak_g);
  // show display
  if (show_confirm_signing(address, sizeof(address))) {
    if (!layoutBlindSign("Kaspa", false, NULL, address, raw_message,
                         raw_message_len, NULL, NULL, NULL, NULL, NULL, NULL)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      return false;
    }
  }

  CALCULATE_SIGNING_HASH(raw_message, raw_message_len);
  if (is_schnorr) {
    if (!kaspa_sign_bip340_digest(node, use_tweak_g, schnorr_digest, signature,
                                  signature_len)) {
      return false;
    }
  } else {
    // ecdsa sign
    CALCULATE_SIGNING_HASH_ECDSA;
    if (!kaspa_sign_ecdsa_digest(node, ecdsa_digest, signature,
                                 signature_len)) {
      return false;
    }
  }
  return true;
}
