#if !defined(EMULATOR) || !EMULATOR

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef APPVER
#include "bip32.h"
#include "cardano.h"
#include "config.h"
#include "curves.h"
#include "fido2/resident_credential.h"
#include "gettext.h"
#endif
#include "aes/aes.h"
#include "common.h"
#include "flash.h"
#include "memzero.h"
#include "nist256p1.h"
#include "otp.h"
#include "rand.h"
#include "se_chip.h"
#include "se_version.h"
#include "se_thd89_v2.h"
#include "secp256k1.h"
#include "thd89.h"
#include "transport_limits.h"

#define CURVE_NIST256P1 (0x00)
#define CURVE_SECP256K1 (0x01)
#define CURVE_ED25519 (0x02)
#define CURVE_SR25519 (0x03)
#define CURVE_ED25519_ICARUS (0x04)

#define ECDH_NIST256P1 (0x00)
#define ECDH_SECP256K1 (0x01)
#define ECDH_CURVE25519 (0x08)

#define SE_INS_READ_DATA 0xE3
#define SE_INS_WRITE_DATA 0xE4
#define SE_INS_PIN 0xE5
#define SE_INS_SESSION 0xE6
#define SE_INS_DERIVE 0xE7
#define SE_INS_SIGN 0xE8
#define SE_INS_ECDH 0xE9
#define SE_INS_AES 0xEA
#define SE_INS_COINJOIN 0xEC
#define SE_INS_HASHR 0xED
#define SE_INS_HASHRAM 0xEE
#define SE_INS_FIDO 0xF9

typedef enum {
  SE_FIDO_GEN_SEED = 0x00,
  SE_FIDO_U2F_REGISTER,
  SE_FIDO_U2F_GEN_HANDLE,
  SE_FIDO_U2F_VALIDATE_HANDLE,
  SE_FIDO_U2F_AUTHENTICATE,
  SE_FIDO_GET_COUNTER,
  SE_FIDO_NEXT_COUNTER,
  SE_FIDO_SET_COUNTER,
  SE_FIDO_DERIVE_NODE,
  SE_FIDO_NODE_SIGN,
  SE_FIDO_ATT_SIGN,
  SE_FIDO_HMAC_SECRET = 0x0e,
  SE_FIDO_RESIDENT_LIST = 0x0F,
  SE_FIDO_RESIDENT_READ = 0x10,
  SE_FIDO_CREDENTIAL_CREATE = 0x11,
  SE_FIDO_CREDENTIAL_VALIDATE = 0x12,
  SE_FIDO_RESIDENT_DELETE = 0x13,
  SE_FIDO_RESIDENT_CLEAR = 0x14,
  SE_FIDO_RESIDENT_IMPORT = 0x15,
} SE_FIDO_P2;

#define SESSION_KEYLEN (16)

#define SE_PIN_RETRY_MAX 10

#define SE_BUF_MAX_LEN TRANSPORT_MAX_RESPONSE

#define SE_LONG_OPERATION_MAX_POLLS 1200U
#define SE_LONG_OPERATION_POLL_DELAY_MS 100U

typedef enum {
  SE_LONG_OPERATION_NONE = 0,
  SE_LONG_OPERATION_SET_PASSPHRASE_PIN,
  SE_LONG_OPERATION_SESSION_SEED,
  SE_LONG_OPERATION_CARDANO_SEED,
  SE_LONG_OPERATION_FIDO_SEED,
} se_long_operation_t;

typedef struct {
  uint8_t enc_key[16];
  uint8_t mac_key[16];
  bool valid;
} se_secure_channel_context_t;

typedef struct {
  uint8_t response[SE_BUF_MAX_LEN];
  uint8_t plaintext[SE_BUF_MAX_LEN];
  bool in_use;
} se_secure_workspace_t;

static se_secure_channel_context_t se_secure_channel;
static se_secure_workspace_t se_secure_workspace
    __attribute__((aligned(AES_BLOCK_SIZE)));
static bool se_fido_seed_ready_hint;

#ifdef APPVER
// Static variable to store the last PIN result
static pin_result_t g_last_pin_result = PIN_SUCCESS;
#endif

static uint8_t se_send_buffer[SE_BUF_MAX_LEN];

static const uint8_t se_secure_a4_command[7] = {0xa4, 0x84, 0x00, 0x00,
                                                0x02, 0x00, 0x10};
static const uint8_t se_zero_transaction[16] = {0};

#define APDU_DATA (se_send_buffer + 5)

static UI_WAIT_CALLBACK ui_callback = NULL;
static void (*se_long_operation_keepalive)(void) = NULL;

#ifndef APPVER
void session_clear(bool lock);
#endif
void fsm_clear_runtime_state(void);

typedef struct {
  bool se_init_state_cache;
  bool se_init_state;
  bool se_pin_unlocked_state_cache;
  bool se_pin_unlocked_state;
} se_state_cache_t;

se_state_cache_t se_state_cache = {0};

static bool se_get_string_length(const char *value, size_t max_len,
                                 size_t *value_len) {
  size_t length;

  if (value == NULL || value_len == NULL) {
    return false;
  }
  length = strnlen(value, max_len + 1U);
  if (length > max_len) {
    return false;
  }
  *value_len = length;
  return true;
}

void se_set_ui_callback(UI_WAIT_CALLBACK callback) { ui_callback = callback; }
UI_WAIT_CALLBACK se_get_ui_callback(void) { return ui_callback; }

secbool se_get_rand(uint8_t *rand, uint16_t rand_len) {
  uint8_t rand_cmd[7] = {0x00, 0x84, 0x00, 0x00, 0x02};
  uint16_t resp_len = rand_len;

  if (rand == NULL || rand_len == 0) {
    return secfalse;
  }
  rand_cmd[5] = (rand_len >> 8) & 0xff;
  rand_cmd[6] = rand_len & 0xff;
  if (!thd89_transmit(rand_cmd, sizeof(rand_cmd), rand, &resp_len) ||
      resp_len != rand_len) {
    memzero(rand, rand_len);
    return secfalse;
  }
  return sectrue;
}

typedef enum {
  SE_SECURE_OK = 0,
  SE_SECURE_AUTHENTICATED_ERROR,
  SE_SECURE_NO_MAC_PROGRESS,
  SE_SECURE_OUTPUT_TOO_SMALL,
  SE_SECURE_PROTOCOL_ERROR,
} se_secure_result_t;

static void se_invalidate_secure_channel(void) {
  memzero(&se_secure_channel, sizeof(se_secure_channel));
  se_fido_seed_ready_hint = false;
}

static se_long_operation_t se_long_operation_for(uint8_t ins, uint8_t p1,
                                                 uint8_t p2) {
  if (ins == 0xe5 && p1 == 0 && p2 == 0x09)
    return SE_LONG_OPERATION_SET_PASSPHRASE_PIN;
  if (ins == 0xe6 && p1 == 0 && p2 == 0x05)
    return SE_LONG_OPERATION_SESSION_SEED;
  if (ins == 0xe6 && p1 == 0 && p2 == 0x06)
    return SE_LONG_OPERATION_CARDANO_SEED;
  if (ins == 0xf9 && p1 == 0 && p2 == 0x00) return SE_LONG_OPERATION_FIDO_SEED;
  return SE_LONG_OPERATION_NONE;
}

static bool se_long_operation_progress_status(uint16_t status) {
  return status >= 0x6c00 && status <= 0x6c64;
}

static se_secure_result_t se_poll_long_operation(uint16_t *out_len) {
  static const uint8_t poll_command[5] = {0x80, 0xca, 0x00, 0x08, 0x00};
  uint8_t response[1] = {0};

  for (uint16_t poll = 0; poll < SE_LONG_OPERATION_MAX_POLLS; poll++) {
    uint16_t response_len = sizeof(response);
    uint16_t status = 0;

    hal_delay(SE_LONG_OPERATION_POLL_DELAY_MS);
    if (thd89_transmit_raw(poll_command, sizeof(poll_command), response,
                           &response_len, &status) == secfalse ||
        response_len != 0) {
      return SE_SECURE_PROTOCOL_ERROR;
    }
    if (status == 0x9000) {
      if (out_len != NULL) {
        *out_len = 0;
      }
      return SE_SECURE_OK;
    }
    if (!se_long_operation_progress_status(status)) {
      return SE_SECURE_PROTOCOL_ERROR;
    }
#ifdef APPVER
    if (ui_callback != NULL) {
      ui_callback(_(C__PROCESSING_ETC), (status & 0xffU) * 10U);
    }
#endif
    if (se_long_operation_keepalive != NULL) {
      se_long_operation_keepalive();
    }
  }
  return SE_SECURE_PROTOCOL_ERROR;
}

void se_clear_runtime_state(void) {
  se_invalidate_secure_channel();
  memzero(&se_secure_workspace, sizeof(se_secure_workspace));
  memzero(&se_state_cache, sizeof(se_state_cache));
  memzero(se_send_buffer, sizeof(se_send_buffer));
  ui_callback = NULL;
  se_long_operation_keepalive = NULL;
#ifdef APPVER
  g_last_pin_result = PIN_FAILED;
#endif
}

static void se_clear_application_runtime_state(void) {
  session_clear(false);
  fsm_clear_runtime_state();
}

void __attribute__((noreturn)) se_security_halt(void) {
  se_clear_runtime_state();
  se_clear_application_runtime_state();
  error_shutdown("Security alert", "Secure element authentication", "failed.",
                 "Please restart.");
}

void __attribute__((noreturn)) se_configuration_halt(void) {
  se_clear_runtime_state();
  se_clear_application_runtime_state();
  error_shutdown("SE configuration error", "Secure element configuration",
                 "failed.", "Please restart.");
}

static void se_halt_for_authenticated_status(uint16_t status);

typedef secbool (*se_secure_response_handler_t)(const uint8_t *response,
                                                uint16_t response_len,
                                                void *context);

static se_secure_result_t se_secure_exchange_with_response(
    uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data,
    uint16_t data_len, uint8_t *out, uint16_t *out_len, uint16_t *sw1sw2,
    se_secure_response_handler_t response_handler, void *response_context) {
  uint8_t *request = se_send_buffer;
  uint8_t *response = se_secure_workspace.response;
  uint8_t *plaintext = se_secure_workspace.plaintext;
  uint8_t expected_mac[4] = {0};
  uint8_t transaction_iv[16] = {0};
  uint8_t cipher_iv[16] = {0};
  uint16_t a4_len = sizeof(se_secure_workspace.response);
  uint16_t response_len = sizeof(se_secure_workspace.response);
  uint16_t status = 0;
  uint16_t padded_len = 0;
  uint16_t plaintext_len = 0;
  uint16_t request_header_len = 0;
  uint16_t request_len = 0;
  uint16_t ciphertext_len = 0;
  thd89_v2_response_shape_t response_shape;
  aes_decrypt_ctx decrypt_ctx = {0};
  aes_encrypt_ctx encrypt_ctx = {0};
  se_secure_result_t result = SE_SECURE_PROTOCOL_ERROR;
  bool invalidate_channel = false;
  bool workspace_acquired = false;

  if (!se_secure_channel.valid || (data == NULL && data_len != 0) ||
      (out != NULL && out_len == NULL) ||
      (response_handler != NULL && out != NULL)) {
    goto cleanup;
  }
  if (se_secure_workspace.in_use) {
    goto cleanup;
  }
  se_secure_workspace.in_use = true;
  workspace_acquired = true;

  if (thd89_transmit_raw(se_secure_a4_command, sizeof(se_secure_a4_command),
                         response, &a4_len, &status) == secfalse ||
      thd89_v2_classify_response(a4_len, status) !=
          THD89_V2_RESPONSE_MAC_REQUIRED) {
    invalidate_channel = true;
    goto cleanup;
  }
  ciphertext_len = a4_len - 4;
  if (!thd89_v2_calculate_response_mac(
          se_secure_channel.mac_key, se_secure_a4_command, se_zero_transaction,
          response, ciphertext_len, status, expected_mac) ||
      !thd89_v2_constant_time_equal(expected_mac, response + ciphertext_len,
                                    sizeof(expected_mac))) {
    invalidate_channel = true;
    goto cleanup;
  }
  se_halt_for_authenticated_status(status);
  if (status != 0x9000) {
    if (sw1sw2 != NULL) {
      *sw1sw2 = status;
    }
    result = SE_SECURE_AUTHENTICATED_ERROR;
    goto cleanup;
  }
  if (aes_decrypt_key128(se_secure_channel.enc_key, &decrypt_ctx) !=
          EXIT_SUCCESS ||
      aes_ecb_decrypt(response, plaintext, ciphertext_len, &decrypt_ctx) !=
          EXIT_SUCCESS ||
      !thd89_v2_unpad_iso7816_4(plaintext, ciphertext_len, &plaintext_len) ||
      plaintext_len != sizeof(transaction_iv)) {
    invalidate_channel = true;
    goto cleanup;
  }
  memcpy(transaction_iv, plaintext, sizeof(transaction_iv));

  if (!thd89_v2_pad_iso7816_4(data, data_len, plaintext,
                              sizeof(se_secure_workspace.plaintext),
                              &padded_len)) {
    goto cleanup;
  }
  request_header_len = padded_len > UINT8_MAX ? 7U : 5U;
  if ((uint32_t)request_header_len + padded_len + sizeof(expected_mac) >
      sizeof(se_send_buffer)) {
    goto cleanup;
  }
  request[0] = 0x84;
  request[1] = ins;
  request[2] = p1;
  request[3] = p2;
  if (padded_len > 255) {
    request[4] = 0;
    request[5] = (uint8_t)(padded_len >> 8);
    request[6] = (uint8_t)padded_len;
  } else {
    request[4] = (uint8_t)padded_len;
  }
  memcpy(cipher_iv, transaction_iv, sizeof(cipher_iv));
  if (aes_encrypt_key128(se_secure_channel.enc_key, &encrypt_ctx) !=
          EXIT_SUCCESS ||
      aes_cbc_encrypt(plaintext, request + request_header_len, padded_len,
                      cipher_iv, &encrypt_ctx) != EXIT_SUCCESS) {
    invalidate_channel = true;
    goto cleanup;
  }
  request_len = request_header_len + padded_len;
  if (!thd89_v2_calculate_request_mac(se_secure_channel.mac_key, transaction_iv,
                                      request, request_len, expected_mac)) {
    invalidate_channel = true;
    goto cleanup;
  }
  memcpy(request + request_len, expected_mac, sizeof(expected_mac));
  request_len += sizeof(expected_mac);
  response_len = sizeof(se_secure_workspace.response);
  if (thd89_transmit_raw(request, request_len, response, &response_len,
                         &status) == secfalse) {
    invalidate_channel = true;
    goto cleanup;
  }
  response_shape = thd89_v2_classify_response(response_len, status);
  if (response_shape != THD89_V2_RESPONSE_MAC_REQUIRED) {
    se_long_operation_t operation = se_long_operation_for(ins, p1, p2);
    if (response_shape == THD89_V2_RESPONSE_NO_MAC_6C &&
        se_long_operation_progress_status(status) &&
        operation != SE_LONG_OPERATION_NONE) {
      result = se_poll_long_operation(out_len);
      if (result != SE_SECURE_OK) {
        invalidate_channel = true;
      }
    } else {
      result = response_shape == THD89_V2_RESPONSE_NO_MAC_6C
                   ? SE_SECURE_NO_MAC_PROGRESS
                   : SE_SECURE_PROTOCOL_ERROR;
      invalidate_channel = true;
    }
    goto cleanup;
  }
  ciphertext_len = response_len - 4;
  if (!thd89_v2_calculate_response_mac(se_secure_channel.mac_key, request,
                                       transaction_iv, response, ciphertext_len,
                                       status, expected_mac) ||
      !thd89_v2_constant_time_equal(expected_mac, response + ciphertext_len,
                                    sizeof(expected_mac))) {
    invalidate_channel = true;
    goto cleanup;
  }
  se_halt_for_authenticated_status(status);
  if (sw1sw2 != NULL) {
    *sw1sw2 = status;
  }
  plaintext_len = 0;
  if (ciphertext_len != 0) {
    memcpy(cipher_iv, transaction_iv, sizeof(cipher_iv));
    if (aes_decrypt_key128(se_secure_channel.enc_key, &decrypt_ctx) !=
            EXIT_SUCCESS ||
        aes_cbc_decrypt(response, plaintext, ciphertext_len, cipher_iv,
                        &decrypt_ctx) != EXIT_SUCCESS ||
        !thd89_v2_unpad_iso7816_4(plaintext, ciphertext_len, &plaintext_len)) {
      invalidate_channel = true;
      goto cleanup;
    }
  }
  if (status != 0x9000) {
    if (ins == SE_INS_FIDO && status == 0x6985) {
      se_fido_seed_ready_hint = false;
    }
    result = SE_SECURE_AUTHENTICATED_ERROR;
    goto cleanup;
  }
  if (response_handler != NULL) {
    if (response_handler(plaintext, plaintext_len, response_context) != sectrue) {
      result = SE_SECURE_PROTOCOL_ERROR;
      goto cleanup;
    }
  } else {
    if (out_len != NULL && *out_len < plaintext_len) {
      result = SE_SECURE_OUTPUT_TOO_SMALL;
      goto cleanup;
    }
    if (out_len != NULL) {
      *out_len = plaintext_len;
    }
    if (out != NULL && plaintext_len != 0) {
      memcpy(out, plaintext, plaintext_len);
    }
  }
  result = SE_SECURE_OK;

cleanup:
  if (result == SE_SECURE_OK && !se_secure_channel.valid) {
    result = SE_SECURE_PROTOCOL_ERROR;
  }
  if (invalidate_channel) {
    se_invalidate_secure_channel();
  }
  if (workspace_acquired) {
    memzero(se_send_buffer, sizeof(se_send_buffer));
    memzero(se_secure_workspace.response, sizeof(se_secure_workspace.response));
    memzero(se_secure_workspace.plaintext,
            sizeof(se_secure_workspace.plaintext));
    se_secure_workspace.in_use = false;
  }
  memzero(expected_mac, sizeof(expected_mac));
  memzero(transaction_iv, sizeof(transaction_iv));
  memzero(cipher_iv, sizeof(cipher_iv));
  memzero(&decrypt_ctx, sizeof(decrypt_ctx));
  memzero(&encrypt_ctx, sizeof(encrypt_ctx));
  return result;
}

static se_secure_result_t se_secure_exchange(uint8_t ins, uint8_t p1,
                                             uint8_t p2, const uint8_t *data,
                                             uint16_t data_len, uint8_t *out,
                                             uint16_t *out_len,
                                             uint16_t *sw1sw2) {
  return se_secure_exchange_with_response(ins, p1, p2, data, data_len, out,
                                          out_len, sw1sw2, NULL, NULL);
}

static void se_halt_for_authenticated_status(uint16_t status) {
  switch (status) {
    case 0x6601:
      se_security_halt();
    case 0x6f01:
      se_configuration_halt();
    default:
      return;
  }
}

secbool se_transmit_mac(uint8_t ins, uint8_t p1, uint8_t p2, uint8_t *data,
                        uint16_t data_len, uint8_t *recv, uint16_t *recv_len) {
  return se_transmit_mac_with_status(ins, p1, p2, data, data_len, recv,
                                     recv_len, NULL);
}

secbool se_transmit_mac_with_status(uint8_t ins, uint8_t p1, uint8_t p2,
                                    uint8_t *data, uint16_t data_len,
                                    uint8_t *recv, uint16_t *recv_len,
                                    uint16_t *authenticated_sw1sw2) {
  uint16_t empty_response_len = 0;

  if (authenticated_sw1sw2 != NULL) {
    *authenticated_sw1sw2 = 0;
  }
  if (recv == NULL && recv_len == NULL) {
    recv_len = &empty_response_len;
  }
  return se_secure_exchange(ins, p1, p2, data, data_len, recv, recv_len,
                            authenticated_sw1sw2) == SE_SECURE_OK
             ? sectrue
             : secfalse;
}

secbool se_random_encrypted(uint8_t *rand, uint16_t len) {
  uint8_t data[2];
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t recv_len = len;
  secbool result = secfalse;

  if (rand == NULL || len == 0 || len > sizeof(response)) {
    goto cleanup;
  }
  data[0] = (len >> 8) & 0xff;
  data[1] = len & 0xff;
  if (!se_transmit_mac(0x84, 0x00, 0x00, data, 2, response, &recv_len) ||
      recv_len != len) {
    goto cleanup;
  }
  memcpy(rand, response, len);
  result = sectrue;

cleanup:
  if (result != sectrue && rand != NULL) {
    memzero(rand, len);
  }
  memzero(response, sizeof(response));
  return result;
}

secbool se_sync_session_key(void) {
  uint8_t otp_public_key[65] = {0};
  uint8_t ephemeral_private_key[32] = {0};
  uint8_t ephemeral_public_key[65] = {0};
  uint8_t shared_point[65] = {0};
  uint8_t se_random[16] = {0};
  uint8_t mcu_random[16] = {0};
  uint8_t candidate_enc_key[16] = {0};
  uint8_t candidate_mac_key[16] = {0};
  uint8_t candidate_confirm_key[32] = {0};
  uint8_t challenge[16] = {0};
  uint8_t request[101] = {0x00, 0xfa, 0x01, 0x00, 0x60};
  uint8_t confirmation[32] = {0};
  uint8_t expected_confirmation[32] = {0};
  uint16_t response_len = sizeof(se_random);
  uint16_t status = 0;
  uint16_t fatal_status = 0;
  aes_encrypt_ctx encrypt_ctx = {0};
  secbool transport_result = secfalse;
  secbool result = secfalse;

  se_invalidate_secure_channel();
  otp_public_key[0] = 0x04;
  if (!flash_otp_read(FLASH_OTP_BLOCK_THD89_PUBLIC_KEY1, 0, otp_public_key + 1,
                      32) ||
      !flash_otp_read(FLASH_OTP_BLOCK_THD89_PUBLIC_KEY2, 0, otp_public_key + 33,
                      32)) {
    goto cleanup;
  }
  transport_result =
      thd89_transmit_raw((uint8_t[]){0x00, 0x84, 0x00, 0x00, 0x02, 0x00, 0x10},
                         7, se_random, &response_len, &status);
  if (transport_result == secfalse) {
    goto cleanup;
  }
  if (status == 0x6601 || status == 0x6f01) {
    fatal_status = status;
    goto cleanup;
  }
  if (response_len != sizeof(se_random) || status != 0x9000) {
    goto cleanup;
  }
  random_buffer(mcu_random, sizeof(mcu_random));
  for (uint8_t attempt = 0; attempt < 16; attempt++) {
    random_buffer(ephemeral_private_key, sizeof(ephemeral_private_key));
    if (ecdsa_get_public_key65(&secp256k1, ephemeral_private_key,
                               ephemeral_public_key) == 0) {
      break;
    }
    memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
  }
  if (ephemeral_public_key[0] != 0x04 ||
      ecdh_multiply(&secp256k1, ephemeral_private_key, otp_public_key,
                    shared_point) != 0) {
    goto cleanup;
  }
  thd89_v2_derive_session_keys(shared_point + 1, se_random, mcu_random,
                               candidate_enc_key, candidate_mac_key,
                               candidate_confirm_key);
  if (aes_encrypt_key128(candidate_enc_key, &encrypt_ctx) != EXIT_SUCCESS ||
      aes_ecb_encrypt(se_random, challenge, sizeof(challenge), &encrypt_ctx) !=
          EXIT_SUCCESS) {
    goto cleanup;
  }
  memcpy(request + 5, mcu_random, sizeof(mcu_random));
  memcpy(request + 21, challenge, sizeof(challenge));
  memcpy(request + 37, ephemeral_public_key + 1, 64);
  response_len = sizeof(confirmation);
  transport_result = thd89_transmit_raw(request, sizeof(request), confirmation,
                                        &response_len, &status);
  if (transport_result == secfalse) {
    goto cleanup;
  }
  if (status == 0x6601 || status == 0x6f01) {
    fatal_status = status;
    goto cleanup;
  }
  if (response_len != sizeof(confirmation) || status != 0x9000) {
    goto cleanup;
  }
  thd89_v2_calculate_confirmation(candidate_confirm_key, se_random, request + 5,
                                  expected_confirmation);
  if (!thd89_v2_constant_time_equal(expected_confirmation, confirmation,
                                    sizeof(expected_confirmation))) {
    goto cleanup;
  }
  memcpy(se_secure_channel.enc_key, candidate_enc_key,
         sizeof(se_secure_channel.enc_key));
  memcpy(se_secure_channel.mac_key, candidate_mac_key,
         sizeof(se_secure_channel.mac_key));
  se_secure_channel.valid = true;
  result = sectrue;

cleanup:
  memzero(otp_public_key, sizeof(otp_public_key));
  memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
  memzero(ephemeral_public_key, sizeof(ephemeral_public_key));
  memzero(shared_point, sizeof(shared_point));
  memzero(se_random, sizeof(se_random));
  memzero(mcu_random, sizeof(mcu_random));
  memzero(candidate_enc_key, sizeof(candidate_enc_key));
  memzero(candidate_mac_key, sizeof(candidate_mac_key));
  memzero(candidate_confirm_key, sizeof(candidate_confirm_key));
  memzero(challenge, sizeof(challenge));
  memzero(request, sizeof(request));
  memzero(confirmation, sizeof(confirmation));
  memzero(expected_confirmation, sizeof(expected_confirmation));
  memzero(&encrypt_ctx, sizeof(encrypt_ctx));
  if (fatal_status != 0) {
    se_halt_for_authenticated_status(fatal_status);
  }
  return result;
}

secbool se_reset_storage(void) {
  uint8_t rand[16];

  se_fido_seed_ready_hint = false;
  if (!se_get_rand(rand, sizeof(rand))) {
    return secfalse;
  }

  if (!se_secure_channel.valid) {
    ensure(se_sync_session_key(), "se sync session key failed");
  }
  se_state_cache.se_init_state_cache = false;
  if (!se_transmit_mac(0xE1, 0x00, 0x00, rand, sizeof(rand), NULL, NULL)) {
    return secfalse;
  }
  return sectrue;
}

#ifdef APPVER

secbool se_reset_se(void) {
  uint8_t cmd[5] = {0x00, 0xF0, 0x00, 0x00, 0x00};
  uint16_t resp_len = 0;

  se_clear_runtime_state();
  return thd89_transmit(cmd, sizeof(cmd), NULL, &resp_len);
}

static bool se_prepare_derivation_request(const char *curve,
                                          const uint32_t *address_n,
                                          size_t address_n_count,
                                          uint16_t *encoded_len) {
  const size_t request_capacity =
      (((SE_BUF_MAX_LEN - 9U) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE) - 1U;
  size_t curve_len;
  size_t request_len = 1;

  if (curve == NULL || encoded_len == NULL) {
    return false;
  }
  curve_len = strnlen(curve, UINT8_MAX + 1U);
  if (curve_len > UINT8_MAX || curve_len > request_capacity - request_len) {
    return false;
  }
  APDU_DATA[0] = (uint8_t)curve_len;
  memcpy(APDU_DATA + request_len, curve, curve_len);
  request_len += curve_len;

  if ((address_n == NULL && address_n_count != 0) ||
      address_n_count > (request_capacity - request_len) / sizeof(*address_n)) {
    return false;
  }
  if (address_n_count != 0) {
    memcpy(APDU_DATA + request_len, address_n,
           address_n_count * sizeof(*address_n));
    request_len += address_n_count * sizeof(*address_n);
  }
  if (request_len > UINT16_MAX) {
    return false;
  }
  *encoded_len = (uint16_t)request_len;
  return true;
}

secbool se_derive_keys(HDNode *out, const char *curve,
                       const uint32_t *address_n, size_t address_n_count,
                       uint32_t *fingerprint) {
  const curve_info *curve_descriptor =
      curve != NULL ? get_curve_by_name(curve) : NULL;
  uint8_t resp[256];
  uint16_t resp_len = sizeof(resp);
  uint16_t request_len = 0;
  secbool result = secfalse;

  if (out == NULL || curve_descriptor == NULL || address_n_count > 8) {
    if (out != NULL) memzero(out, sizeof(*out));
    if (fingerprint != NULL) *fingerprint = 0;
    goto cleanup;
  }
  if (!se_prepare_derivation_request(curve, address_n, address_n_count,
                                     &request_len) ||
      !se_transmit_mac(SE_INS_DERIVE, 0x00, 0x00, APDU_DATA, request_len, resp,
                       &resp_len) ||
      resp_len != 4 + sizeof(HDNode) - 4) {
    memzero(out, sizeof(*out));
    if (fingerprint) *fingerprint = 0;
    goto cleanup;
  }
  out->curve = curve_descriptor;
  if (fingerprint) {
    memcpy(fingerprint, resp, 4);
  }
  memcpy((void *)out, resp + 4, sizeof(HDNode) - 4);
  result = sectrue;

cleanup:
  memzero(resp, sizeof(resp));
  return result;
}

secbool se_set_sn(const char *serial, uint8_t len) {
  uint8_t cmd[40] = {0x00, 0xF6, 0x00, 0x0, 0x00};
  uint16_t resp_len = 0;
  if (len > 32 || (serial == NULL && len != 0)) {
    return secfalse;
  }
  cmd[4] = len;
  if (len != 0) memcpy(cmd + 5, serial, len);
  return thd89_transmit(cmd, len + 5, NULL, &resp_len);
}

secbool se_get_sn(char **serial) {
  uint8_t get_sn[5] = {0x00, 0xf5, 0x00, 0x00, 0x00};
  static char sn[33] = {0};
  uint16_t sn_len = sizeof(sn) - 1;

  if (serial == NULL) {
    return secfalse;
  }
  memzero(sn, sizeof(sn));
  if (!thd89_transmit(get_sn, sizeof(get_sn), (uint8_t *)sn, &sn_len) ||
      sn_len == 0 || sn_len >= sizeof(sn) || memchr(sn, '\0', sn_len) != NULL) {
    memzero(sn, sizeof(sn));
    return secfalse;
  }
  sn[sn_len] = '\0';
  *serial = sn;
  return sectrue;
}

const char *se_get_version_checked(uint16_t *sw1sw2) {
  uint8_t get_ver[5] = {0x00, 0xf7, 0x00, 0x00, 0x00};
  static char ver[8] = {0};
  uint16_t ver_len = sizeof(ver) - 1;
  uint16_t status = 0;

  memzero(ver, sizeof(ver));
  if (thd89_transmit_raw(get_ver, sizeof(get_ver), (uint8_t *)ver, &ver_len,
                         &status) == secfalse) {
    if (sw1sw2 != NULL) {
      *sw1sw2 = status;
    }
    return NULL;
  }
  if (sw1sw2 != NULL) {
    *sw1sw2 = status;
  }
  if (status != 0x9000 || ver_len == 0 || ver_len >= sizeof(ver) ||
      memchr(ver, '\0', ver_len) != NULL) {
    memzero(ver, sizeof(ver));
    return NULL;
  }
  ver[ver_len] = '\0';

  return ver;
}

char *se_get_version(void) { return (char *)se_get_version_checked(NULL); }

char *se_get_build_id(void) {
  uint8_t get_build_id[5] = {0x00, 0xf7, 0x00, 0x01, 0x00};
  static char build_id[8] = {0};
  uint16_t len = sizeof(build_id) - 1;

  memzero(build_id, sizeof(build_id));
  if (!thd89_transmit(get_build_id, sizeof(get_build_id), (uint8_t *)build_id,
                      &len) ||
      len != sizeof(build_id) - 1) {
    memzero(build_id, sizeof(build_id));
    return NULL;
  }
  build_id[len] = '\0';

  return build_id;
}

char *se_get_hash(void) {
  uint8_t get_hash[5] = {0x00, 0xf7, 0x00, 0x02, 0x00};
  static char hash[32] = {0};
  uint16_t len = 32;

  memzero(hash, sizeof(hash));
  if (!thd89_transmit(get_hash, sizeof(get_hash), (uint8_t *)hash, &len) ||
      len != sizeof(hash)) {
    memzero(hash, sizeof(hash));
    return NULL;
  }

  return hash;
}

secbool se_get_pubkey(uint8_t *public_key) {
  uint8_t cmd[5] = {0x00, 0xF5, 0x00, 0x01, 0x00};
  uint8_t response[64] = {0};
  uint16_t resp_len = sizeof(response);
  if (public_key == NULL) {
    return secfalse;
  }
  if (!thd89_transmit(cmd, sizeof(cmd), response, &resp_len) ||
      resp_len != sizeof(response)) {
    memzero(public_key, 64);
    return secfalse;
  }
  memcpy(public_key, response, sizeof(response));
  return sectrue;
}

secbool se_get_ecdh_pubkey(uint8_t *key) {
  uint8_t cmd[5] = {0x00, 0xF5, 0x00, 0x05, 0x00};
  uint8_t response[64] = {0};
  uint16_t resp_len = sizeof(response);
  if (key == NULL) {
    return secfalse;
  }
  if (!thd89_transmit(cmd, sizeof(cmd), response, &resp_len) ||
      resp_len != sizeof(response)) {
    memzero(key, 64);
    return secfalse;
  }
  memcpy(key, response, sizeof(response));
  return sectrue;
}

secbool se_lock_ecdh_pubkey(void) {
  uint8_t cmd[5] = {0x00, 0xF5, 0x00, 0x06, 0x00};
  return thd89_transmit(cmd, sizeof(cmd), NULL, NULL);
}

secbool se_write_certificate(const uint8_t *cert, uint16_t len) {
  uint8_t cmd[TRANSPORT_MAX_PAYLOAD + 7] = {0x00, 0xF6, 0x00, 0x01, 0x00};
  uint16_t cmd_len = 0;
  uint16_t resp_len = 0;
  if ((cert == NULL && len != 0) || len > TRANSPORT_MAX_PAYLOAD) {
    return secfalse;
  }
  if (len > 255) {
    cmd[4] = 0x00;
    cmd[5] = (len >> 8) & 0xff;
    cmd[6] = len & 0xff;
    cmd_len = 7;
  } else {
    cmd[4] = len;
    cmd_len = 5;
  }
  if (len != 0) memcpy(cmd + cmd_len, cert, len);
  return thd89_transmit(cmd, cmd_len + len, NULL, &resp_len);
}

secbool se_read_certificate(uint8_t *cert, uint16_t *len) {
  uint8_t cmd[5] = {0x00, 0xF5, 0x00, 0x02, 0x00};
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t capacity;
  if (cert == NULL || len == NULL) {
    return secfalse;
  }
  capacity = *len;
  uint16_t response_len = capacity;
  if (capacity > sizeof(response) ||
      !thd89_transmit(cmd, sizeof(cmd), response, &response_len) ||
      response_len > capacity) {
    memzero(cert, capacity);
    *len = 0;
    return secfalse;
  }
  memcpy(cert, response, response_len);
  *len = response_len;
  return sectrue;
}

secbool se_has_cerrificate(void) {
  uint8_t cert[512];
  uint16_t cert_len = sizeof(cert);
  return se_read_certificate(cert, &cert_len) == sectrue && cert_len != 0
             ? sectrue
             : secfalse;
}

secbool se_sign_message(uint8_t *msg, uint32_t msg_len, uint8_t *signature) {
  uint8_t sign[37] = {0x00, 0xF5, 0x00, 0x03, 0x20};
  uint16_t signature_len = 64;

  SHA256_CTX ctx = {0};
  uint8_t result[32] = {0};

  if ((msg == NULL && msg_len != 0) || signature == NULL) {
    return secfalse;
  }

  sha256_Init(&ctx);
  sha256_Update(&ctx, msg, msg_len);
  sha256_Final(&ctx, result);

  memcpy(sign + 5, result, 32);
  if (!thd89_transmit(sign, sizeof(sign), signature, &signature_len) ||
      signature_len != 64) {
    memzero(signature, 64);
    return secfalse;
  }
  return sectrue;
}

secbool se_sign_message_feitian(uint8_t *msg, uint32_t msg_len,
                                uint8_t *signature) {
  uint8_t sign[37] = {0x00, 0xF5, 0x00, 0x04, 0x20};
  uint16_t signature_len = 64;

  if (msg == NULL || signature == NULL || msg_len != 32) {
    return secfalse;
  }

  memcpy(sign + 5, msg, 32);
  if (!thd89_transmit(sign, sizeof(sign), signature, &signature_len) ||
      signature_len != 64) {
    memzero(signature, 64);
    return secfalse;
  }
  return sectrue;
}

secbool se_set_private_key_feitian(uint8_t *key) {
  uint8_t sign[37] = {0x00, 0xF6, 0x00, 0x03, 0x20};
  uint16_t response_len = 0;

  if (key == NULL) {
    return secfalse;
  }
  memcpy(sign + 5, key, 32);
  return thd89_transmit(sign, sizeof(sign), NULL, &response_len);
}

secbool se_set_session_key(const uint8_t *session_key) {
  uint8_t cmd[32] = {0x00, 0xF6, 0x00, 0x02, 0x10};
  uint16_t resp_len = 0;

  if (session_key == NULL) {
    return secfalse;
  }
  memcpy(cmd + 5, session_key, SESSION_KEYLEN);
  return thd89_transmit(cmd, 21, NULL, &resp_len);
}

secbool se_isInitialized(void) {
  if (se_state_cache.se_init_state_cache) {
    return se_state_cache.se_init_state ? sectrue : secfalse;
  }
  uint8_t cmd[5] = {0x00, 0xf8, 0x00, 00, 0x00};
  uint8_t init = 0xff;
  uint16_t len = sizeof(init);
  if (!thd89_transmit(cmd, sizeof(cmd), &init, &len) || len != sizeof(init)) {
    return secfalse;
  }
  se_state_cache.se_init_state = (init == 0x55);
  se_state_cache.se_init_state_cache = true;
  return se_state_cache.se_init_state ? sectrue : secfalse;
}

secbool se_hasPin(void) {
  uint8_t hasPin = 0xff;
  uint16_t len = sizeof(hasPin);

  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x00, NULL, 0, &hasPin, &len) ||
      len != sizeof(hasPin)) {
    return secfalse;
  }

  // 0x55 exist ,0xff not
  return sectrue * (hasPin == 0x55);
}

secbool se_verifyPin(const char *pin, pin_type_t pin_type) {
  uint8_t pin_buf[50 + 2] = {0};
  uint8_t resp[1] = {0};
  uint16_t resp_len = 1;
  uint16_t authenticated_sw1sw2 = 0;
  uint8_t data_len = 0;
  size_t pin_len = 0;

  if (!se_get_string_length(pin, 50, &pin_len)) {
    return secfalse;
  }

  if (pin_type >= PIN_TYPE_MAX) {
    return secfalse;
  }

  pin_buf[0] = (uint8_t)pin_len;
  memcpy(pin_buf + 1, pin, pin_len);
  data_len = pin_buf[0] + 1;

  // Add pin_type as additional data
  pin_buf[pin_buf[0] + 1] = pin_type;
  data_len++;

  se_state_cache.se_pin_unlocked_state_cache = false;

  secbool transmit_result =
      se_transmit_mac_with_status(SE_INS_PIN, 0x00, 0x03, pin_buf, data_len,
                                  resp, &resp_len, &authenticated_sw1sw2);
  memzero(pin_buf, sizeof(pin_buf));
  switch (authenticated_sw1sw2) {
    case 0x9000:
      if (transmit_result != sectrue || resp_len != sizeof(resp)) {
        se_clear_runtime_state();
        return secfalse;
      }
      break;
    case 0x6985:
      g_last_pin_result = PIN_FAILED;
      return secfalse;
    case 0x6983:
      g_last_pin_result = SE_PIN_RETRY_LIMIT_WIPED;
      return secfalse;
    case 0x6f80:
      g_last_pin_result = WIPE_CODE_ENTERED;
      return secfalse;
    default:
      se_clear_runtime_state();
      return secfalse;
  }

  // Store the pin result like reference implementation
  g_last_pin_result = resp[0];

  if (pin_type == PIN_TYPE_PASSPHRASE_PIN) {
    return (g_last_pin_result == PASSPHRASE_PIN_ENTERED) ? sectrue : secfalse;
  } else if (pin_type == PIN_TYPE_USER || pin_type == PIN_TYPE_USER_CHECK) {
    return (g_last_pin_result == USER_PIN_ENTERED ||
            g_last_pin_result == PIN_SUCCESS)
               ? sectrue
               : secfalse;
  } else if (pin_type == PIN_TYPE_PASSPHRASE_PIN_CHECK) {
    return (g_last_pin_result == PIN_SUCCESS ||
            g_last_pin_result == PASSPHRASE_PIN_ENTERED)
               ? sectrue
               : secfalse;
  } else if (pin_type == PIN_TYPE_USER_AND_PASSPHRASE_PIN) {
    bool success = (g_last_pin_result == USER_PIN_ENTERED ||
                    g_last_pin_result == PASSPHRASE_PIN_ENTERED);
    return success ? sectrue : secfalse;
  } else if (pin_type == PIN_TYPE_USER_AND_PASSPHRASE_PIN_CHECK) {
    return (g_last_pin_result == USER_PIN_ENTERED ||
            g_last_pin_result == PASSPHRASE_PIN_ENTERED)
               ? sectrue
               : secfalse;
  }

  return sectrue;
}

secbool se_setPin(const char *pin) {
  uint8_t pin_buf[64] = {0};
  size_t pin_len = 0;

  if (!se_get_string_length(pin, 50, &pin_len)) {
    return secfalse;
  }
  pin_buf[0] = (uint8_t)pin_len;
  memcpy(pin_buf + 1, pin, pin_len);
  se_state_cache.se_pin_unlocked_state_cache = false;
  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x01, pin_buf, pin_buf[0] + 1, NULL,
                       NULL)) {
    memzero(pin_buf, sizeof(pin_buf));
    return secfalse;
  }
  memzero(pin_buf, sizeof(pin_buf));
  return sectrue;
}

secbool se_changePin(const char *oldpin, const char *newpin) {
  uint8_t pin_buff[110] = {0};
  size_t oldpin_len = 0;
  size_t newpin_len = 0;

  if (!se_get_string_length(oldpin, 50, &oldpin_len) ||
      !se_get_string_length(newpin, 50, &newpin_len)) {
    return secfalse;
  }
  pin_buff[0] = (uint8_t)oldpin_len;
  memcpy(pin_buff + 1, oldpin, oldpin_len);
  pin_buff[oldpin_len + 1] = (uint8_t)newpin_len;
  memcpy(pin_buff + oldpin_len + 2, newpin, newpin_len);
  se_state_cache.se_pin_unlocked_state_cache = false;
  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x02, pin_buff,
                       (uint16_t)(oldpin_len + newpin_len + 2U), NULL, NULL)) {
    memzero(pin_buff, sizeof(pin_buff));
    return secfalse;
  }
  memzero(pin_buff, sizeof(pin_buff));
  return sectrue;
}

uint32_t se_pinFailedCounter(void) {
  uint8_t retry_cnts = 0;
  if (!se_getRetryTimes(&retry_cnts)) {
    return 0;
  }

  return (uint32_t)(SE_PIN_RETRY_MAX - retry_cnts);
}

secbool se_getRetryTimes(uint8_t *ptimes) {
  uint8_t remain = 0;
  uint16_t recv_len = 1;

  if (ptimes == NULL) {
    return secfalse;
  }
  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x05, NULL, 0, &remain, &recv_len) ||
      recv_len != sizeof(remain)) {
    *ptimes = 0;
    return secfalse;
  }
  *ptimes = remain;
  return sectrue;
}

secbool se_clearSecsta(void) {
  uint16_t recv_len = 0;
  se_fido_seed_ready_hint = false;
  se_state_cache.se_pin_unlocked_state_cache = false;
  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x06, NULL, 0, NULL, &recv_len)) {
    return secfalse;
  }
  return sectrue;
}

secbool se_getSecsta(void) {
  if (se_state_cache.se_pin_unlocked_state_cache) {
    return se_state_cache.se_pin_unlocked_state ? sectrue : secfalse;
  }
  uint8_t cur_secsta = 0xff;
  uint16_t recv_len = sizeof(cur_secsta);
  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x04, NULL, 0, &cur_secsta,
                       &recv_len) ||
      recv_len != sizeof(cur_secsta)) {
    return secfalse;
  }
  // 0x55 is verified pin 0x00 is not verified pin
  se_state_cache.se_pin_unlocked_state = (cur_secsta == 0x55);
  se_state_cache.se_pin_unlocked_state_cache = true;
  return se_state_cache.se_pin_unlocked_state ? sectrue : secfalse;
}

static secbool se_prepare_fido_seed_ready(void) {
  return se_fido_seed_ready_hint ? sectrue : secfalse;
}

secbool se_set_u2f_counter(uint32_t u2fcounter) {
  uint16_t response_len = 0;
  if (se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_SET_COUNTER,
                         (uint8_t *)&u2fcounter, sizeof(u2fcounter), NULL,
                         &response_len, NULL) != SE_SECURE_OK) {
    return secfalse;
  }
  if (response_len != 0) {
    return secfalse;
  }
  return sectrue;
}

secbool se_get_u2f_next_counter(uint32_t *u2fcounter) {
  uint32_t counter = 0;
  uint16_t recv_len = 4;
  if (u2fcounter == NULL ||
      se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_NEXT_COUNTER, NULL, 0,
                         (uint8_t *)&counter, &recv_len,
                         NULL) != SE_SECURE_OK ||
      recv_len != sizeof(counter)) {
    if (u2fcounter != NULL) memzero(u2fcounter, sizeof(*u2fcounter));
    return secfalse;
  }
  *u2fcounter = counter;
  return sectrue;
}

secbool se_set_mnemonic(const char *mnemonic, uint16_t len) {
  if (mnemonic == NULL || len == 0 || len > MAX_MNEMONIC_LEN) {
    return secfalse;
  }
  se_fido_seed_ready_hint = false;
  se_state_cache.se_init_state_cache = false;
  return se_transmit_mac(0xE2, 0x00, 0x00, (uint8_t *)mnemonic, len, NULL,
                         NULL);
}

secbool se_sessionStart(uint8_t *session_id_bytes) {
  uint8_t response[32] = {0};
  uint16_t recv_len = sizeof(response);
  secbool result = secfalse;

  if (session_id_bytes == NULL) {
    goto cleanup;
  }
  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x00, NULL, 0, response,
                       &recv_len) ||
      recv_len != sizeof(response)) {
    memzero(session_id_bytes, 32);
    goto cleanup;
  }

  memcpy(session_id_bytes, response, sizeof(response));
  result = sectrue;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

secbool se_sessionOpen(uint8_t *session_id_bytes) {
  uint8_t response[32] = {0};
  uint16_t recv_len = sizeof(response);
  secbool result = secfalse;

  if (session_id_bytes == NULL) {
    goto cleanup;
  }
  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x01, session_id_bytes, 32,
                       response, &recv_len) ||
      recv_len != sizeof(response)) {
    memzero(session_id_bytes, 32);
    goto cleanup;
  }
  memcpy(session_id_bytes, response, sizeof(response));
  result = sectrue;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

secbool se_sessionClose(void) {
  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x02, NULL, 0, NULL, NULL)) {
    return secfalse;
  }
  return sectrue;
}

secbool se_sessionClear(void) {
  // Clear PIN unlock state cache when session is cleared
  se_state_cache.se_pin_unlocked_state_cache = false;
  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x03, NULL, 0, NULL, NULL)) {
    return secfalse;
  }
  return sectrue;
}

void se_clearPinStateCache(void) {
  se_state_cache.se_pin_unlocked_state_cache = false;
}

secbool se_set_public_region(const uint16_t offset, const void *val_dest,
                             uint16_t len) {
  uint8_t cmd[4] = {0};
  if ((uint32_t)offset + len > PUBLIC_REGION_SIZE ||
      4U + len > SE_BUF_MAX_LEN - 5 || (val_dest == NULL && len != 0))
    return secfalse;

  cmd[0] = (offset >> 8) & 0xFF;
  cmd[1] = offset & 0xFF;
  cmd[2] = (len >> 8) & 0xFF;
  cmd[3] = len & 0xFF;
  memcpy(APDU_DATA, cmd, 4);
  if (len != 0) memcpy(APDU_DATA + 4, val_dest, len);
  if (!se_transmit_mac(SE_INS_WRITE_DATA, 0x00, 0x00, APDU_DATA, 4 + len, NULL,
                       NULL)) {
    return secfalse;
  }
  return sectrue;
}

secbool se_get_public_region(uint16_t offset, void *val_dest, uint16_t len) {
  uint8_t cmd[4] = {0};
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t recv_len = len;
  if ((uint32_t)offset + len > PUBLIC_REGION_SIZE || len > sizeof(response) ||
      (val_dest == NULL && len != 0)) {
    if (val_dest != NULL) memzero(val_dest, len);
    return secfalse;
  }
  cmd[0] = (offset >> 8) & 0xFF;
  cmd[1] = offset & 0xFF;
  cmd[2] = (len >> 8) & 0xFF;
  cmd[3] = len & 0xFF;
  if (!se_transmit_mac(SE_INS_READ_DATA, 0x00, 0x00, cmd, sizeof(cmd), response,
                       &recv_len) ||
      recv_len != len) {
    if (val_dest != NULL) memzero(val_dest, len);
    return secfalse;
  }
  if (len != 0) memcpy(val_dest, response, len);
  return sectrue;
}

secbool se_set_private_region(uint16_t offset, const void *val_dest,
                              uint16_t len) {
  uint8_t cmd[4] = {0};
  if ((uint32_t)offset + len > PRIVATE_REGION_SIZE ||
      4U + len > SE_BUF_MAX_LEN - 5 || (val_dest == NULL && len != 0))
    return secfalse;
  cmd[0] = (offset >> 8) & 0xFF;
  cmd[1] = offset & 0xFF;
  cmd[2] = (len >> 8) & 0xFF;
  cmd[3] = len & 0xFF;
  memcpy(APDU_DATA, cmd, 4);
  if (len != 0) memcpy(APDU_DATA + 4, val_dest, len);
  if (!se_transmit_mac(SE_INS_WRITE_DATA, 0x00, 0x01, APDU_DATA, 4 + len, NULL,
                       NULL)) {
    return secfalse;
  }
  return sectrue;
}

secbool se_get_private_region(uint16_t offset, void *val_dest, uint16_t len) {
  uint8_t cmd[4] = {0};
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t recv_len = len;
  secbool result = secfalse;

  if ((uint32_t)offset + len > PRIVATE_REGION_SIZE || len > sizeof(response) ||
      (val_dest == NULL && len != 0)) {
    if (val_dest != NULL) memzero(val_dest, len);
    goto cleanup;
  }
  cmd[0] = (offset >> 8) & 0xFF;
  cmd[1] = offset & 0xFF;
  cmd[2] = (len >> 8) & 0xFF;
  cmd[3] = len & 0xFF;
  if (!se_transmit_mac(SE_INS_READ_DATA, 0x00, 0x01, cmd, sizeof(cmd), response,
                       &recv_len) ||
      recv_len != len) {
    if (val_dest != NULL) memzero(val_dest, len);
    goto cleanup;
  }
  if (len != 0) memcpy(val_dest, response, len);
  result = sectrue;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

secbool se_containsMnemonic(const char *mnemonic) {
  uint8_t verify = 0xff;
  uint16_t len = sizeof(verify);
  size_t mnemonic_len = 0;

  if (!se_get_string_length(mnemonic, MAX_MNEMONIC_LEN, &mnemonic_len) ||
      !se_transmit_mac(0xE2, 0x00, 0x01, (uint8_t *)mnemonic,
                       (uint16_t)mnemonic_len, &verify, &len) ||
      len != sizeof(verify)) {
    return secfalse;
  }

  return sectrue * (verify == 0x55);
}

secbool se_hasWipeCode(void) {
  uint8_t wipe_code = 0xff;
  uint16_t len = sizeof(wipe_code);

  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x07, NULL, 0, &wipe_code, &len) ||
      len != sizeof(wipe_code)) {
    return secfalse;
  }

  // 0x55 exist ,0xff not
  return sectrue * (wipe_code == 0x55);
}
secbool se_changeWipeCode(const char *pin, const char *wipe_code) {
  uint8_t pin_buff[110] = {0};
  size_t pin_len = 0;
  size_t wipe_code_len = 0;

  if (!se_get_string_length(pin, 50, &pin_len) ||
      !se_get_string_length(wipe_code, 50, &wipe_code_len)) {
    return secfalse;
  }
  pin_buff[0] = (uint8_t)pin_len;
  memcpy(pin_buff + 1, pin, pin_len);
  pin_buff[pin_len + 1] = (uint8_t)wipe_code_len;
  memcpy(pin_buff + pin_len + 2, wipe_code, wipe_code_len);

  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x08, pin_buff,
                       (uint16_t)(pin_len + wipe_code_len + 2U), NULL, NULL)) {
    memzero(pin_buff, sizeof(pin_buff));
    return secfalse;
  }
  memzero(pin_buff, sizeof(pin_buff));
  return sectrue;
}

int se_ecdsa_sign_digest(const uint8_t curve, const uint8_t canonical,
                         const uint8_t *hash, uint8_t *sig, uint8_t *pby) {
  uint8_t resp[65], tmp[40] = {0};
  uint16_t resp_len = sizeof(resp);

  if (hash == NULL || sig == NULL) {
    if (pby != NULL) *pby = 0;
    return -1;
  }
  tmp[0] = curve;
  tmp[1] = canonical;
  memcpy(tmp + 2, hash, 32);

  if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x01, tmp, 34, resp, &resp_len) ||
      resp_len != 65) {
    memzero(sig, 64);
    if (pby) *pby = 0;
    return -1;
  }

  if (pby) *pby = resp[0];
  memcpy(sig, resp + 1, 64);
  // if (is_canonical && !is_canonical(*pby, sig)) return -1;
  return 0;
}

int se_secp256k1_sign_digest(const uint8_t canonical, const uint8_t *digest,
                             uint8_t *sig, uint8_t *pby) {
  return se_ecdsa_sign_digest(CURVE_SECP256K1, canonical, digest, sig, pby);
}

int se_nist256p1_sign_digest(const uint8_t *digest, uint8_t *sig,
                             uint8_t *pby) {
  return se_ecdsa_sign_digest(CURVE_NIST256P1, 0, digest, sig, pby);
}

#define HASH_FLAG_INIT 0x40
#define HASH_FLAG_UPDATE 0x00
#define HASH_FLAG_FINAL 0x80

#define ED25519_HASH_DEFAULT 0
#define ED25519_HASH_EXT 1
#define ED25519_HASH_KECCAK 2

static int _se_ed25519_send_msg(uint8_t ins, uint8_t type, const uint8_t *msg,
                                uint16_t msg_len) {
  uint8_t flag = HASH_FLAG_INIT;
  bool first = true;

  if (msg == NULL && msg_len != 0) {
    return -1;
  }
  while (msg_len) {
    uint16_t len =
        msg_len > TRANSPORT_MAX_PAYLOAD ? TRANSPORT_MAX_PAYLOAD : msg_len;
    if (first) {
      flag = HASH_FLAG_INIT;
      first = false;
    } else {
      flag = HASH_FLAG_UPDATE;
    }
    if (msg_len - len == 0) {
      flag |= HASH_FLAG_FINAL;
    }
    if (!se_transmit_mac(ins, type, flag, (uint8_t *)msg, len, NULL, NULL)) {
      return -1;
    }
    msg += len;
    msg_len -= len;
  }
  return 0;
}

static int _se_ed25519_sign_digest(uint8_t type, uint8_t *sig) {
  uint8_t response[64] = {0};
  uint16_t resp_len = sizeof(response);

  if (sig == NULL) {
    return -1;
  }
  if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x08, &type, 1, response,
                       &resp_len) ||
      resp_len != sizeof(response)) {
    memzero(sig, 64);
    return -1;
  }
  memcpy(sig, response, sizeof(response));
  return 0;
}

static int se_ed25519_sign_digest(const uint8_t *msg, uint16_t msg_len,
                                  uint8_t type, uint8_t *sig) {
  if (_se_ed25519_send_msg(SE_INS_HASHR, type, msg, msg_len) != 0) {
    return -1;
  }
  if (_se_ed25519_send_msg(SE_INS_HASHRAM, type, msg, msg_len) != 0) {
    return -1;
  }
  if (_se_ed25519_sign_digest(type, sig) != 0) {
    return -1;
  }
  return 0;
}

int se_ed25519_sign(const uint8_t *msg, uint16_t msg_len, uint8_t *sig) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);
  if ((msg == NULL && msg_len != 0) || sig == NULL) {
    return -1;
  }
  if (msg_len > TRANSPORT_MAX_PAYLOAD) {
    if (se_ed25519_sign_digest(msg, msg_len, ED25519_HASH_DEFAULT, resp) != 0) {
      return -1;
    }
  } else {
    if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x02, (uint8_t *)msg, msg_len, resp,
                         &resp_len) ||
        resp_len != sizeof(resp)) {
      memzero(sig, 64);
      return -1;
    }
  }
  memcpy(sig, resp, resp_len);
  return 0;
}

int se_ed25519_sign_ext(const uint8_t *msg, uint16_t msg_len, uint8_t *sig) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);
  if ((msg == NULL && msg_len != 0) || sig == NULL) {
    return -1;
  }
  if (msg_len > TRANSPORT_MAX_PAYLOAD) {
    if (se_ed25519_sign_digest(msg, msg_len, ED25519_HASH_EXT, resp) != 0) {
      return -1;
    }
  } else {
    if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x03, (uint8_t *)msg, msg_len, resp,
                         &resp_len) ||
        resp_len != sizeof(resp)) {
      memzero(sig, 64);
      return -1;
    }
  }
  memcpy(sig, resp, resp_len);
  return 0;
}

int se_ed25519_sign_keccak(const uint8_t *msg, uint16_t msg_len, uint8_t *sig) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);
  if ((msg == NULL && msg_len != 0) || sig == NULL) {
    return -1;
  }
  if (msg_len > TRANSPORT_MAX_PAYLOAD) {
    if (se_ed25519_sign_digest(msg, msg_len, ED25519_HASH_KECCAK, resp) != 0) {
      return -1;
    }
  } else {
    if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x04, (uint8_t *)msg, msg_len, resp,
                         &resp_len) ||
        resp_len != sizeof(resp)) {
      memzero(sig, 64);
      return -1;
    }
  }
  memcpy(sig, resp, resp_len);
  return 0;
}

secbool se_get_session_seed_state(uint8_t *state) {
  uint8_t response = 0;
  uint16_t recv_len = sizeof(response);

  if (state == NULL) {
    return secfalse;
  }
  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x04, NULL, 0, &response,
                       &recv_len) ||
      recv_len != sizeof(response)) {
    *state = 0;
    return secfalse;
  }
  *state = response;
  return sectrue;
}

secbool se_session_is_open() {
  uint8_t state = 0;
  uint16_t recv_len = 1;

  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x07, NULL, 0, &state,
                       &recv_len) ||
      recv_len != sizeof(state)) {
    return secfalse;
  }

  return sectrue * (state == 0x55);
}

secbool session_generate_master_seed(const char *passphrase, uint8_t *percent) {
  size_t passphrase_len = 0;
  if (percent == NULL ||
      !se_get_string_length(passphrase, 50, &passphrase_len)) {
    return secfalse;
  }
  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x05, (uint8_t *)passphrase,
                       (uint16_t)passphrase_len, NULL, NULL)) {
    *percent = 0;
    return secfalse;
  }
  *percent = 100;
  return sectrue;
}

secbool session_generate_cardano_seed(const char *passphrase,
                                      uint8_t *percent) {
  size_t passphrase_len = 0;
  if (percent == NULL ||
      !se_get_string_length(passphrase, 50, &passphrase_len)) {
    return secfalse;
  }
  if (!se_transmit_mac(SE_INS_SESSION, 0x00, 0x06, (uint8_t *)passphrase,
                       (uint16_t)passphrase_len, NULL, NULL)) {
    *percent = 0;
    return secfalse;
  }
  *percent = 100;
  return sectrue;
}

secbool se_node_sign_digest(const uint8_t *hash, uint8_t *sig, uint8_t *by) {
  uint8_t resp[65];
  uint16_t resp_len = sizeof(resp);

  if (hash == NULL || sig == NULL) {
    if (by != NULL) *by = 0;
    return secfalse;
  }
  if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x00, (uint8_t *)hash, 32, resp,
                       &resp_len) ||
      resp_len != 65) {
    memzero(sig, 64);
    if (by) *by = 0;
    return secfalse;
  }

  memcpy(sig, resp + 1, 64);
  if (by) *by = resp[0];
  return sectrue;
}

secbool se_gen_session_seed(const char *passphrase, bool cardano,
                            bool force_regen) {
  uint8_t status = 0;
  uint8_t percent;
  if (!se_get_session_seed_state(&status)) {
    return secfalse;
  }
  if (cardano) {
    if (!force_regen && (status & 0x40)) {
      return sectrue;
    }
    if (!session_generate_cardano_seed(passphrase, &percent)) {
      return secfalse;
    }
  } else {
    if (!force_regen && (status & 0x80)) {
      return sectrue;
    }
    if (!session_generate_master_seed(passphrase, &percent)) {
      return secfalse;
    }
  }

  return sectrue;
}

int se_ecdsa_ecdh(const uint8_t *publickey, uint8_t *sessionkey) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);
  int result = -1;

  if (publickey == NULL || sessionkey == NULL) {
    goto cleanup;
  }
  if (!se_transmit_mac(SE_INS_ECDH, 0x00, 0x00, (uint8_t *)publickey, 64, resp,
                       &resp_len) ||
      resp_len != 64) {
    memzero(sessionkey, 64);
    goto cleanup;
  }
  memcpy(sessionkey, resp, resp_len);
  result = 0;

cleanup:
  memzero(resp, sizeof(resp));
  return result;
}

int se_curve25519_ecdh(const uint8_t *publickey, uint8_t *sessionkey) {
  uint8_t resp[32];
  uint16_t resp_len = sizeof(resp);
  int result = -1;

  if (publickey == NULL || sessionkey == NULL) {
    goto cleanup;
  }
  if (!se_transmit_mac(SE_INS_ECDH, 0x00, 0x01, (uint8_t *)publickey, 32, resp,
                       &resp_len) ||
      resp_len != 32) {
    memzero(sessionkey, 32);
    goto cleanup;
  }
  memcpy(sessionkey, resp, resp_len);
  result = 0;

cleanup:
  memzero(resp, sizeof(resp));
  return result;
}

int se_get_shared_key(const char *curve, const uint8_t *peer_public_key,
                      uint8_t *session_key) {
  if (curve == NULL || peer_public_key == NULL || session_key == NULL) {
    return -1;
  }
  if (strcmp(curve, NIST256P1_NAME) == 0 ||
      strcmp(curve, SECP256K1_NAME) == 0) {
    if (peer_public_key[0] != 0x04) {
      return -1;
    }
    return se_ecdsa_ecdh(peer_public_key + 1, session_key);
  } else if (strcmp(curve, CURVE25519_NAME) == 0) {
    if (peer_public_key[0] != 0x40) {
      return -1;
    }
    return se_curve25519_ecdh(peer_public_key + 1, session_key);
  }
  return -1;
}

secbool se_derive_tweak_private_keys(const uint8_t *root_hash) {
  uint8_t *data = NULL;
  uint16_t data_len = 0;
  if (root_hash) {
    data = (uint8_t *)root_hash;
    data_len = 32;
  }
  if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x06, data, data_len, NULL, NULL)) {
    return secfalse;
  }
  return sectrue;
}

int se_bip340_sign_digest(const uint8_t *digest, uint8_t sig[64]) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);
  if (digest == NULL || sig == NULL) {
    return -1;
  }
  if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x07, (uint8_t *)digest, 32, resp,
                       &resp_len)) {
    memzero(sig, 64);
    return -1;
  }
  if (resp_len != 64) {
    memzero(sig, 64);
    return -1;
  }
  memcpy(sig, resp, resp_len);
  return 0;
}

int se_bch_sign_digest(const uint8_t *digest, uint8_t sig[64]) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);
  if (digest == NULL || sig == NULL) {
    return -1;
  }
  if (!se_transmit_mac(SE_INS_SIGN, 0x00, 0x09, (uint8_t *)digest, 32, resp,
                       &resp_len)) {
    memzero(sig, 64);
    return -1;
  }
  if (resp_len != 64) {
    memzero(sig, 64);
    return -1;
  }
  memcpy(sig, resp, resp_len);
  return 0;
}

int se_aes256_encrypt(const uint8_t *data, uint16_t data_len, const uint8_t *iv,
                      uint8_t *value, uint16_t value_len, uint8_t *out) {
  uint32_t len = 0;
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t resp_len = value_len;
  int result = -1;

  if ((data == NULL && data_len != 0) || (value == NULL && value_len != 0) ||
      (out == NULL && value_len != 0) ||
      (uint32_t)data_len + value_len + 4 + (iv != NULL ? 16 : 0) >
          SE_BUF_MAX_LEN - 5 ||
      value_len > sizeof(response)) {
    if (out != NULL) memzero(out, value_len);
    goto cleanup;
  }
  APDU_DATA[0] = (data_len >> 8) & 0xff;
  APDU_DATA[1] = data_len & 0xff;
  len += 2;
  if (data_len != 0) memcpy(APDU_DATA + len, data, data_len);
  len += data_len;
  APDU_DATA[len] = (value_len >> 8) & 0xff;
  APDU_DATA[len + 1] = value_len & 0xff;
  len += 2;
  if (value_len != 0) memcpy(APDU_DATA + len, value, value_len);
  len += value_len;
  if (iv != NULL) {
    memcpy(APDU_DATA + len, iv, 16);
    len += 16;
  }

  if (!se_transmit_mac(SE_INS_AES, 0x00, 0x00, APDU_DATA, len, response,
                       &resp_len) ||
      resp_len != value_len) {
    if (out != NULL) memzero(out, value_len);
    goto cleanup;
  }
  if (value_len != 0) memcpy(out, response, value_len);
  result = 0;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

int se_aes256_decrypt(const uint8_t *data, uint16_t data_len, const uint8_t *iv,
                      uint8_t *value, uint16_t value_len, uint8_t *out) {
  uint32_t len = 0;
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t resp_len = value_len;
  int result = -1;

  if ((data == NULL && data_len != 0) || (value == NULL && value_len != 0) ||
      (out == NULL && value_len != 0) ||
      (uint32_t)data_len + value_len + 4 + (iv != NULL ? 16 : 0) >
          SE_BUF_MAX_LEN - 5 ||
      value_len > sizeof(response)) {
    if (out != NULL) memzero(out, value_len);
    goto cleanup;
  }
  APDU_DATA[0] = (data_len >> 8) & 0xff;
  APDU_DATA[1] = data_len & 0xff;
  len += 2;
  if (data_len != 0) memcpy(APDU_DATA + len, data, data_len);
  len += data_len;
  APDU_DATA[len] = (value_len >> 8) & 0xff;
  APDU_DATA[len + 1] = value_len & 0xff;
  len += 2;
  if (value_len != 0) memcpy(APDU_DATA + len, value, value_len);
  len += value_len;
  if (iv != NULL) {
    memcpy(APDU_DATA + len, iv, 16);
    len += 16;
  }

  if (!se_transmit_mac(SE_INS_AES, 0x00, 0x01, APDU_DATA, len, response,
                       &resp_len) ||
      resp_len != value_len) {
    if (out != NULL) memzero(out, value_len);
    goto cleanup;
  }
  if (value_len != 0) memcpy(out, response, value_len);
  result = 0;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

int se_nem_aes256_encrypt(const uint8_t *ed25519_pubkey, const uint8_t *iv,
                          const uint8_t *salt, uint8_t *payload, uint16_t size,
                          uint8_t *out) {
  uint32_t len = 0;
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t resp_len = (size + AES_BLOCK_SIZE) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
  uint16_t expected_len = resp_len;
  int result = -1;

  if (ed25519_pubkey == NULL || iv == NULL || salt == NULL ||
      (payload == NULL && size != 0) || (out == NULL && resp_len != 0) ||
      (uint32_t)size + 80 > SE_BUF_MAX_LEN - 5 || resp_len > sizeof(response)) {
    if (out != NULL) memzero(out, resp_len);
    goto cleanup;
  }
  memcpy(APDU_DATA + len, ed25519_pubkey, 32);
  len += 32;
  memcpy(APDU_DATA + len, iv, 16);
  len += 16;
  memcpy(APDU_DATA + len, salt, 32);
  len += 32;
  if (size != 0) memcpy(APDU_DATA + len, payload, size);
  len += size;

  if (!se_transmit_mac(SE_INS_AES, 0x00, 0x02, APDU_DATA, len, response,
                       &resp_len) ||
      resp_len != expected_len) {
    if (out != NULL) memzero(out, expected_len);
    goto cleanup;
  }
  if (expected_len != 0) memcpy(out, response, expected_len);
  result = 0;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

int se_nem_aes256_decrypt(const uint8_t *ed25519_pubkey, const uint8_t *iv,
                          const uint8_t *salt, uint8_t *payload, uint16_t size,
                          uint8_t *out) {
  uint32_t len = 0;
  uint8_t response[SE_BUF_MAX_LEN] = {0};
  uint16_t resp_len = size;
  int result = -1;

  if (ed25519_pubkey == NULL || iv == NULL || salt == NULL ||
      (payload == NULL && size != 0) || (out == NULL && size != 0) ||
      (uint32_t)size + 80 > SE_BUF_MAX_LEN - 5 || resp_len > sizeof(response)) {
    if (out != NULL) memzero(out, size);
    goto cleanup;
  }
  memcpy(APDU_DATA + len, ed25519_pubkey, 32);
  len += 32;
  memcpy(APDU_DATA + len, iv, 16);
  len += 16;
  memcpy(APDU_DATA + len, salt, 32);
  len += 32;
  if (size != 0) memcpy(APDU_DATA + len, payload, size);
  len += size;

  if (!se_transmit_mac(SE_INS_AES, 0x00, 0x03, APDU_DATA, len, response,
                       &resp_len) ||
      resp_len != size) {
    if (out != NULL) memzero(out, size);
    goto cleanup;
  }
  if (size != 0) memcpy(out, response, size);
  result = 0;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

static secbool se_prepare_slip21_seed_ready(void) {
  uint8_t state = 0;

  if (se_get_session_seed_state(&state) != sectrue) {
    return secfalse;
  }
  return (state & 0x80U) != 0 ? sectrue : secfalse;
}

secbool se_slip21_ownership_id(const uint8_t *script_pubkey,
                               uint16_t script_pubkey_len,
                               uint8_t ownership_id[32]) {
  uint8_t response[32] = {0};
  uint16_t resp_len = sizeof(response);
  secbool result = secfalse;

  if (ownership_id == NULL) {
    goto cleanup;
  }
  memzero(ownership_id, 32);
  if ((script_pubkey == NULL && script_pubkey_len != 0) ||
      !se_prepare_slip21_seed_ready()) {
    goto cleanup;
  }
  if (!se_transmit_mac(0xEB, 0x01, 0x00, (uint8_t *)script_pubkey,
                       script_pubkey_len, response, &resp_len) ||
      resp_len != sizeof(response)) {
    goto cleanup;
  }
  memcpy(ownership_id, response, sizeof(response));
  result = sectrue;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

secbool se_slip21_slip25_mac(uint8_t mac[32]) {
  uint8_t response[32] = {0};
  uint16_t resp_len = sizeof(response);
  secbool result = secfalse;

  if (mac == NULL) {
    goto cleanup;
  }
  memzero(mac, 32);
  if (!se_prepare_slip21_seed_ready()) {
    goto cleanup;
  }
  if (!se_transmit_mac(0xEB, 0x01, 0x02, NULL, 0, response, &resp_len) ||
      resp_len != sizeof(response)) {
    goto cleanup;
  }
  memcpy(mac, response, sizeof(response));
  result = sectrue;

cleanup:
  memzero(response, sizeof(response));
  return result;
}

secbool se_authorization_set(const uint32_t authorization_type,
                             const uint8_t *authorization,
                             uint32_t authorization_len) {
  uint8_t data[MAX_AUTHORIZATION_LEN + 4];
  if (authorization_len > MAX_AUTHORIZATION_LEN ||
      (authorization == NULL && authorization_len != 0)) {
    return secfalse;
  }
  memcpy(data, &authorization_type, 4);
  if (authorization_len != 0) {
    memcpy(data + 4, authorization, authorization_len);
  }

  if (!se_transmit_mac(SE_INS_COINJOIN, 0x00, 0x00, data, authorization_len + 4,
                       NULL, NULL)) {
    return secfalse;
  }
  return sectrue;
}

secbool se_authorization_get_type(uint32_t *authorization_type) {
  uint32_t type = 0;
  uint16_t resp_len = sizeof(type);
  if (authorization_type == NULL) {
    return secfalse;
  }
  if (!se_transmit_mac(SE_INS_COINJOIN, 0x00, 0x01, NULL, 0, (uint8_t *)&type,
                       &resp_len) ||
      resp_len != sizeof(type)) {
    *authorization_type = 0;
    return secfalse;
  }
  *authorization_type = type;
  return sectrue;
}

secbool se_authorization_get_data(uint8_t *authorization_data,
                                  uint32_t *authorization_len) {
  uint8_t response[MAX_AUTHORIZATION_LEN] = {0};
  if (authorization_len == NULL) {
    return secfalse;
  }
  uint32_t capacity = *authorization_len;
  if ((authorization_data == NULL && capacity != 0) ||
      capacity > MAX_AUTHORIZATION_LEN) {
    *authorization_len = 0;
    return secfalse;
  }
  uint16_t resp_len =
      capacity < sizeof(response) ? (uint16_t)capacity : sizeof(response);
  if (!se_transmit_mac(SE_INS_COINJOIN, 0x00, 0x02, NULL, 0, response,
                       &resp_len) ||
      resp_len > capacity) {
    if (authorization_data != NULL) memzero(authorization_data, capacity);
    *authorization_len = 0;
    return secfalse;
  }
  if (resp_len != 0) memcpy(authorization_data, response, resp_len);
  *authorization_len = resp_len;
  return sectrue;
}

void se_authorization_clear(void) {
  se_transmit_mac(SE_INS_COINJOIN, 0x00, 0x03, NULL, 0, NULL, NULL);
}

/// hdnode api
int hdnode_private_ckd_cached(HDNode *inout, const uint32_t *address_n,
                              size_t address_n_count, uint32_t *fingerprint) {
  // this function `1` is success, `0` is faild
  if (inout == NULL || inout->curve == NULL) {
    if (fingerprint != NULL) *fingerprint = 0;
    return 0;
  }
  return se_derive_keys(inout, inout->curve->curve_name, address_n,
                        address_n_count, fingerprint)
             ? 1
             : 0;
}

int hdnode_sign(const HDNode *node, const uint8_t *msg, uint32_t msg_len,
                HasherType hasher_sign, uint8_t *sig, uint8_t *pby,
                int (*is_canonical)(uint8_t, uint8_t *)) {
  if (node == NULL || node->curve == NULL || (msg == NULL && msg_len != 0) ||
      sig == NULL) {
    if (pby != NULL) *pby = 0;
    return -1;
  }
  if (node->curve->params) {
    uint8_t hash[32] = {0};
    hasher_Raw(hasher_sign, msg, msg_len, hash);
    return hdnode_sign_digest(node, hash, sig, pby, is_canonical);
  } else {
    if (node->curve == &ed25519_info || node->curve == &ed25519_polkadot_info) {
      return se_ed25519_sign(msg, msg_len, sig);
    } else if (node->curve == &ed25519_sha3_info) {
      // ed25519_sign_sha3(msg, msg_len, sig);
      return -1;
#if USE_KECCAK
    } else if (node->curve == &ed25519_keccak_info) {
      return se_ed25519_sign_keccak(msg, msg_len, sig);
#endif
    } else if (node->curve == &ed25519_cardano_info) {
      return se_ed25519_sign_ext(msg, msg_len, sig);
    } else {
      return 1;  // unknown or unsupported curve
    }
  }
  return -1;
}

int hdnode_sign_digest(const HDNode *node, const uint8_t *digest, uint8_t *sig,
                       uint8_t *pby, int (*is_canonical)(uint8_t, uint8_t *)) {
  if (node == NULL || node->curve == NULL || digest == NULL || sig == NULL) {
    if (pby != NULL) *pby = 0;
    return -1;
  }
  const char *curve = node->curve->curve_name;
  uint8_t canonic_type = 0;

  if (node->curve->params) {
    if (strcmp(curve, NIST256P1_NAME) == 0) {
      return se_nist256p1_sign_digest(digest, sig, pby);
    } else {
      if (is_canonical != NULL) {
        canonic_type = CANONICAL_SIG_ETHEREUM;
      }
      return se_secp256k1_sign_digest(canonic_type, digest, sig, pby);
    }
  } else if (node->curve == &curve25519_info) {
    return 1;  // signatures are not supported
  } else {
    return hdnode_sign(node, digest, 32, 0, sig, pby, is_canonical);
  }
}

int hdnode_get_shared_key(const HDNode *node, const uint8_t *peer_public_key,
                          uint8_t *session_key, int *result_size) {
  if (result_size != NULL) *result_size = 0;
  if (node == NULL || node->curve == NULL || peer_public_key == NULL ||
      session_key == NULL || result_size == NULL) {
    return -1;
  }
  const char *curve = node->curve->curve_name;
  if (strcmp(curve, NIST256P1_NAME) == 0) {
    uint8_t extend_key[65];
    if (ecdsa_uncompress_pubkey(&nist256p1, peer_public_key, extend_key) == 0) {
      return -1;
    }
    if (se_ecdsa_ecdh(extend_key + 1, session_key + 1) != 0) {
      memzero(session_key, 65);
      return -1;
    }
    session_key[0] = 0x04;
    *result_size = 65;
    return 0;
  } else if (strcmp(curve, SECP256K1_NAME) == 0) {
    uint8_t extend_key[65];
    if (ecdsa_uncompress_pubkey(&secp256k1, peer_public_key, extend_key) == 0) {
      return -1;
    }
    if (se_ecdsa_ecdh(extend_key + 1, session_key + 1) != 0) {
      memzero(session_key, 65);
      return -1;
    }
    session_key[0] = 0x04;
    *result_size = 65;
    return 0;
  } else if (strcmp(curve, CURVE25519_NAME) == 0) {
    if (peer_public_key[0] != 0x40) {
      return -1;
    }
    if (se_curve25519_ecdh(peer_public_key + 1, session_key + 1) != 0) {
      memzero(session_key, 33);
      return -1;
    }
    session_key[0] = 0x04;  // bip32.c
    *result_size = 33;
    return 0;
  }
  return -1;
}

int hdnode_bip340_sign_digest(const HDNode *node, const uint8_t *digest,
                              uint8_t sig[64]) {
  (void)node;
  if (!se_derive_tweak_private_keys(NULL)) return 1;
  return se_bip340_sign_digest(digest, sig) == 0 ? 0 : 1;
}

int hdnode_bip340_sign_digest_internal(const HDNode *node,
                                       const uint8_t *digest, uint8_t sig[64]) {
  (void)node;
  return se_bip340_sign_digest(digest, sig) == 0 ? 0 : 1;
}

int hdnode_bch_sign_digest(const HDNode *node, const uint8_t *digest,
                           uint8_t sig[64]) {
  (void)node;
  return se_bch_sign_digest(digest, sig) == 0 ? 0 : 1;
}

int hdnode_bip340_get_shared_key(const HDNode *node,
                                 const uint8_t *peer_public_key,
                                 uint8_t session_key[65]) {
  int result_size;
  if (!se_derive_tweak_private_keys(NULL)) return 1;
  return hdnode_get_shared_key(node, peer_public_key, session_key,
                               &result_size);
}

int hdnode_bip340_get_shared_key_ln(const HDNode *node,
                                    const uint8_t *peer_public_key,
                                    uint8_t session_key[65]) {
  int result_size;
  return hdnode_get_shared_key(node, peer_public_key, session_key,
                               &result_size);
}

uint16_t se_lasterror(void) { return thd89_last_error(); }

bool se_isFactoryMode(void) {
  // char *serial;
  // if (!se_has_cerrificate()) {
  //   return true;
  // }
  // if (!se_get_sn(&serial)) {
  //   return true;
  // }
  uint8_t cmd[5] = {0x00, 0xf8, 0x04, 0x00, 0x00};
  uint8_t flag = 0xff;
  uint16_t len = sizeof(flag);
  if (!thd89_transmit(cmd, sizeof(cmd), &flag, &len)) {
    return false;
  }
  return flag == 0x00;
}

bool se_disableFactoryMode(void) {
  uint8_t cmd[5] = {0x00, 0xf8, 0x03, 0x00, 0x00};
  if (!thd89_transmit(cmd, sizeof(cmd), NULL, NULL)) {
    return false;
  }
  return true;
}

secbool se_gen_root_node(uint8_t *percent) {
  uint16_t recv_len = 0;
  if (percent == NULL ||
      se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_GEN_SEED, NULL, 0, NULL,
                         &recv_len, NULL) != SE_SECURE_OK ||
      recv_len != 0) {
    se_fido_seed_ready_hint = false;
    if (percent != NULL) *percent = 0;
    return secfalse;
  }
  se_fido_seed_ready_hint = true;
  *percent = 100;
  return sectrue;
}

secbool se_u2f_register(const uint8_t app_id[32], const uint8_t challenge[32],
                        uint8_t key_handle[64], uint8_t pub_key[65],
                        uint8_t sign[64]) {
  uint8_t data[64];
  uint8_t recv[193];
  uint16_t recv_len = sizeof(recv);
  secbool result = secfalse;

  if (app_id == NULL || challenge == NULL || key_handle == NULL ||
      pub_key == NULL || sign == NULL) {
    goto cleanup;
  }
  memzero(key_handle, 64);
  memzero(pub_key, 65);
  memzero(sign, 64);
  if (!se_prepare_fido_seed_ready()) goto cleanup;
  memcpy(data, app_id, 32);
  memcpy(data + 32, challenge, 32);

  se_secure_result_t exchange =
      se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_U2F_REGISTER, data,
                         sizeof(data), recv, &recv_len, NULL);
  if (exchange != SE_SECURE_OK || recv_len != 193) {
    goto cleanup;
  }
  memcpy(key_handle, recv, 64);
  memcpy(pub_key, recv + 64, 65);
  memcpy(sign, recv + 64 + 65, 64);
  result = sectrue;

cleanup:
  memzero(data, sizeof(data));
  memzero(recv, sizeof(recv));
  return result;
}

secbool se_u2f_validate_handle(const uint8_t app_id[32],
                               const uint8_t key_handle[64]) {
  uint8_t data[96];
  uint8_t response[1] = {0};
  uint16_t response_len = sizeof(response);
  secbool result = secfalse;

  if (app_id == NULL || key_handle == NULL || !se_prepare_fido_seed_ready())
    goto cleanup;
  memcpy(data, app_id, 32);
  memcpy(data + 32, key_handle, 64);

  se_secure_result_t exchange =
      se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_U2F_VALIDATE_HANDLE, data,
                         sizeof(data), response, &response_len, NULL);
  if (exchange == SE_SECURE_OK && response_len == 0) {
    result = sectrue;
  }

cleanup:
  memzero(data, sizeof(data));
  memzero(response, sizeof(response));
  return result;
}

secbool se_u2f_authenticate(const uint8_t app_id[32],
                            const uint8_t key_handle[64],
                            const uint8_t challenge[32], uint8_t *u2f_counter,
                            uint8_t sign[64]) {
  uint8_t data[128];
  uint8_t recv[68];
  uint16_t recv_len = sizeof(recv);
  secbool result = secfalse;

  if (u2f_counter != NULL) memzero(u2f_counter, 4);
  if (sign != NULL) memzero(sign, 64);
  if (app_id == NULL || key_handle == NULL || challenge == NULL ||
      u2f_counter == NULL || sign == NULL) {
    goto cleanup;
  }
  if (!se_prepare_fido_seed_ready()) goto cleanup;
  memcpy(data, app_id, 32);
  memcpy(data + 32, key_handle, 64);
  memcpy(data + 32 + 64, challenge, 32);

  se_secure_result_t exchange =
      se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_U2F_AUTHENTICATE, data,
                         sizeof(data), recv, &recv_len, NULL);
  if (exchange != SE_SECURE_OK || recv_len != 68) {
    goto cleanup;
  }
  memcpy(u2f_counter, recv, 4);
  memcpy(sign, recv + 4, 64);
  result = sectrue;

cleanup:
  memzero(data, sizeof(data));
  memzero(recv, sizeof(recv));
  return result;
}

secbool se_derive_fido_keys(HDNode *out, const char *curve,
                            const uint32_t *address_n, size_t address_n_count,
                            uint32_t *fingerprint) {
  const curve_info *curve_descriptor =
      curve != NULL ? get_curve_by_name(curve) : NULL;
  uint8_t resp[256];
  uint16_t resp_len = sizeof(resp);
  uint16_t request_len = 0;
  bool seed_ready = false;
  bool request_ready = false;
  se_secure_result_t exchange = SE_SECURE_PROTOCOL_ERROR;
  secbool result = secfalse;

  if (out == NULL || curve_descriptor == NULL || address_n_count > 9) {
    if (out != NULL) memzero(out, sizeof(*out));
    if (fingerprint != NULL) *fingerprint = 0;
    goto cleanup;
  }
  seed_ready = se_prepare_fido_seed_ready() == sectrue;
  if (seed_ready) {
    request_ready = se_prepare_derivation_request(
        curve, address_n, address_n_count, &request_len);
  }
  if (request_ready) {
    exchange =
        se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_DERIVE_NODE, APDU_DATA,
                           request_len, resp, &resp_len, NULL);
  }
  if (!seed_ready || !request_ready || exchange != SE_SECURE_OK ||
      resp_len != 4 + sizeof(HDNode) - 4) {
    memzero(out, sizeof(*out));
    if (fingerprint) *fingerprint = 0;
    goto cleanup;
  }
  out->curve = curve_descriptor;
  if (fingerprint) {
    memcpy(fingerprint, resp, 4);
  }
  memcpy((void *)out, resp + 4, sizeof(HDNode) - 4);
  result = sectrue;

cleanup:
  memzero(resp, sizeof(resp));
  return result;
}

secbool se_fido_hdnode_sign_digest(const uint8_t *hash, uint8_t *sig) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);

  if (hash == NULL || sig == NULL) {
    return secfalse;
  }
  if (!se_prepare_fido_seed_ready()) {
    memzero(sig, 64);
    return secfalse;
  }
  se_secure_result_t exchange = se_secure_exchange(
      SE_INS_FIDO, 0x00, SE_FIDO_NODE_SIGN, hash, 32, resp, &resp_len, NULL);
  if (exchange != SE_SECURE_OK || resp_len != sizeof(resp)) {
    memzero(sig, 64);
    return secfalse;
  }
  memcpy(sig, resp, resp_len);
  return sectrue;
}

secbool se_fido_att_sign_digest(const uint8_t *hash, uint8_t *sig) {
  uint8_t resp[64];
  uint16_t resp_len = sizeof(resp);

  if (hash == NULL || sig == NULL) {
    return secfalse;
  }
  if (!se_prepare_fido_seed_ready()) {
    memzero(sig, 64);
    return secfalse;
  }
  se_secure_result_t exchange = se_secure_exchange(
      SE_INS_FIDO, 0x00, SE_FIDO_ATT_SIGN, hash, 32, resp, &resp_len, NULL);
  if (exchange != SE_SECURE_OK || resp_len != sizeof(resp)) {
    memzero(sig, 64);
    return secfalse;
  }
  memcpy(sig, resp, resp_len);
  return sectrue;
}

static secbool se_fido_resident_api_is_supported(void) {
  const char *version = se_get_version();

  return version != NULL && se_version_is_at_least(version, 1, 3, 2)
             ? sectrue
             : secfalse;
}

secbool se_fido_resident_list(uint8_t *indexes, uint8_t *index_count) {
  uint8_t response[SE_FIDO_RESIDENT_SLOT_COUNT + 1U] = {0};
  uint8_t capacity = index_count != NULL ? *index_count : 0;
  uint16_t response_len = sizeof(response);
  secbool result = secfalse;

  if (index_count != NULL) {
    *index_count = 0;
  }
  if (indexes != NULL) {
    memzero(indexes, capacity);
  }
  if (indexes == NULL || index_count == NULL ||
      !se_prepare_fido_seed_ready() || !se_fido_resident_api_is_supported()) {
    goto cleanup;
  }
  if (se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_RESIDENT_LIST, NULL, 0,
                         response, &response_len, NULL) != SE_SECURE_OK ||
      response_len == 0 || response[0] > SE_FIDO_RESIDENT_SLOT_COUNT ||
      response_len != (uint16_t)response[0] + 1U || capacity < response[0]) {
    goto cleanup;
  }
  for (uint8_t i = 0; i < response[0]; i++) {
    if (response[i + 1U] >= SE_FIDO_RESIDENT_SLOT_COUNT ||
        (i != 0 && response[i] >= response[i + 1U])) {
      goto cleanup;
    }
  }
  memcpy(indexes, response + 1, response[0]);
  *index_count = response[0];
  result = sectrue;

cleanup:
  if (result != sectrue && indexes != NULL) {
    memzero(indexes, capacity);
  }
  memzero(response, sizeof(response));
  return result;
}

typedef struct {
  uint8_t *credential_id;
  uint16_t credential_capacity;
  uint16_t *credential_id_len;
  uint8_t *plaintext;
  uint16_t plaintext_capacity;
  uint16_t *plaintext_len;
} se_fido_resident_read_context_t;

static secbool se_fido_resident_read_response(const uint8_t *response,
                                              uint16_t response_len,
                                              void *context) {
  se_fido_resident_read_context_t *read_context = context;
  uint16_t id_len;
  uint16_t plain_len;

  if (read_context == NULL || response == NULL ||
      response_len < 2U + SE_FIDO_CREDENTIAL_ID_MIN_LEN + 2U + 1U) {
    return secfalse;
  }
  id_len = ((uint16_t)response[0] << 8) | response[1];
  if (id_len < SE_FIDO_CREDENTIAL_ID_MIN_LEN ||
      id_len > SE_FIDO_RESIDENT_CREDENTIAL_ID_MAX_LEN ||
      response_len < (uint16_t)(2U + id_len + 2U)) {
    return secfalse;
  }
  plain_len = ((uint16_t)response[2U + id_len] << 8) |
              response[3U + id_len];
  if (plain_len == 0 ||
      plain_len > SE_FIDO_RESIDENT_CREDENTIAL_PLAINTEXT_MAX_LEN ||
      id_len != (uint16_t)(plain_len + 32U) ||
      response_len != (uint16_t)(2U + id_len + 2U + plain_len) ||
      read_context->credential_capacity < id_len ||
      read_context->plaintext_capacity < plain_len) {
    return secfalse;
  }
  memcpy(read_context->credential_id, response + 2, id_len);
  memcpy(read_context->plaintext, response + 2U + id_len + 2U, plain_len);
  *read_context->credential_id_len = id_len;
  *read_context->plaintext_len = plain_len;
  return sectrue;
}

secbool se_fido_resident_read(uint8_t index, uint8_t *credential_id,
                              uint16_t *credential_id_len, uint8_t *plaintext,
                              uint16_t *plaintext_len) {
  uint16_t credential_capacity =
      credential_id_len != NULL ? *credential_id_len : 0;
  uint16_t plaintext_capacity = plaintext_len != NULL ? *plaintext_len : 0;
  se_fido_resident_read_context_t read_context = {
      credential_id, credential_capacity, credential_id_len, plaintext,
      plaintext_capacity, plaintext_len};
  secbool result = secfalse;

  if (credential_id_len != NULL) {
    *credential_id_len = 0;
  }
  if (plaintext_len != NULL) {
    *plaintext_len = 0;
  }
  if (credential_id != NULL) {
    memzero(credential_id, credential_capacity);
  }
  if (plaintext != NULL) {
    memzero(plaintext, plaintext_capacity);
  }
  if (index >= SE_FIDO_RESIDENT_SLOT_COUNT || credential_id == NULL ||
      credential_id_len == NULL || plaintext == NULL || plaintext_len == NULL ||
      !se_prepare_fido_seed_ready() || !se_fido_resident_api_is_supported()) {
    goto cleanup;
  }
  if (se_secure_exchange_with_response(
          SE_INS_FIDO, 0x00, SE_FIDO_RESIDENT_READ, &index, sizeof(index),
          NULL, NULL, NULL, se_fido_resident_read_response,
          &read_context) != SE_SECURE_OK) {
    goto cleanup;
  }
  result = sectrue;

cleanup:
  if (result != sectrue) {
    if (credential_id != NULL) {
      memzero(credential_id, credential_capacity);
    }
    if (plaintext != NULL) {
      memzero(plaintext, plaintext_capacity);
    }
  }
  return result;
}

typedef struct {
  bool resident;
  uint16_t plaintext_len;
  uint8_t *credential_id;
  uint16_t credential_capacity;
  uint16_t *credential_id_len;
  uint8_t *slot_index;
  uint8_t *action;
} se_fido_credential_create_context_t;

static secbool se_fido_credential_create_response(const uint8_t *response,
                                                  uint16_t response_len,
                                                  void *context) {
  se_fido_credential_create_context_t *create_context = context;
  uint16_t id_len;
  uint8_t slot_index;
  uint8_t action;

  if (create_context == NULL || response == NULL ||
      response_len < 2U + SE_FIDO_CREDENTIAL_ID_MIN_LEN + 2U) {
    return secfalse;
  }
  id_len = ((uint16_t)response[0] << 8) | response[1];
  if (id_len < SE_FIDO_CREDENTIAL_ID_MIN_LEN ||
      id_len > SE_FIDO_CREDENTIAL_ID_MAX_LEN ||
      id_len != (uint16_t)(create_context->plaintext_len + 32U) ||
      response_len != (uint16_t)(2U + id_len + 2U) ||
      create_context->credential_capacity < id_len) {
    return secfalse;
  }
  slot_index = response[2U + id_len];
  action = response[3U + id_len];
  if ((!create_context->resident &&
       (action != SE_FIDO_CREDENTIAL_ACTION_NOT_STORED ||
        slot_index != SE_FIDO_RESIDENT_SLOT_NONE)) ||
      (create_context->resident &&
       ((action != SE_FIDO_CREDENTIAL_ACTION_CREATED &&
         action != SE_FIDO_CREDENTIAL_ACTION_REPLACED) ||
        slot_index >= SE_FIDO_RESIDENT_SLOT_COUNT))) {
    return secfalse;
  }
  memcpy(create_context->credential_id, response + 2, id_len);
  *create_context->credential_id_len = id_len;
  *create_context->slot_index = slot_index;
  *create_context->action = action;
  return sectrue;
}

secbool se_fido_credential_create(bool resident, const uint8_t *plaintext,
                                  uint16_t plaintext_len,
                                  uint8_t *credential_id,
                                  uint16_t *credential_id_len,
                                  uint8_t *slot_index, uint8_t *action) {
  uint16_t credential_capacity =
      credential_id_len != NULL ? *credential_id_len : 0;
  uint16_t plaintext_limit = resident
                                 ? SE_FIDO_RESIDENT_CREDENTIAL_PLAINTEXT_MAX_LEN
                                 : SE_FIDO_CREDENTIAL_PLAINTEXT_MAX_LEN;
  uint8_t request[1 + SE_FIDO_CREDENTIAL_PLAINTEXT_MAX_LEN] = {0};
  secbool result = secfalse;
  se_fido_credential_create_context_t create_context = {
      resident, plaintext_len, credential_id, credential_capacity,
      credential_id_len, slot_index, action};

  if (credential_id_len != NULL) {
    *credential_id_len = 0;
  }
  if (credential_id != NULL) {
    memzero(credential_id, credential_capacity);
  }
  if (slot_index != NULL) {
    *slot_index = 0;
  }
  if (action != NULL) {
    *action = 0;
  }
  if (plaintext == NULL || plaintext_len == 0 || plaintext_len > plaintext_limit ||
      credential_id == NULL || credential_id_len == NULL || slot_index == NULL ||
      action == NULL || !se_prepare_fido_seed_ready() ||
      !se_fido_resident_api_is_supported()) {
    goto cleanup;
  }
  request[0] = resident ? 1U : 0U;
  memcpy(request + 1, plaintext, plaintext_len);
  if (se_secure_exchange_with_response(
          SE_INS_FIDO, 0x00, SE_FIDO_CREDENTIAL_CREATE, request,
          (uint16_t)(plaintext_len + 1U), NULL, NULL, NULL,
          se_fido_credential_create_response, &create_context) !=
      SE_SECURE_OK) {
    goto cleanup;
  }
  result = sectrue;

cleanup:
  if (result != sectrue) {
    if (credential_id != NULL) {
      memzero(credential_id, credential_capacity);
    }
    if (slot_index != NULL) {
      *slot_index = 0;
    }
    if (action != NULL) {
      *action = 0;
    }
  }
  memzero(request, sizeof(request));
  return result;
}

secbool se_fido_credential_validate(const uint8_t *rp_id_hash,
                                    const uint8_t *credential_id,
                                    uint16_t credential_id_len,
                                    uint8_t *plaintext,
                                    uint16_t *plaintext_len) {
  uint16_t plaintext_capacity = plaintext_len != NULL ? *plaintext_len : 0;
  uint16_t response_len = plaintext_capacity;
  uint16_t request_len = 1;
  uint8_t request[1 + 32 + SE_FIDO_CREDENTIAL_ID_MAX_LEN] = {0};
  secbool result = secfalse;

  if (plaintext_len != NULL) {
    *plaintext_len = 0;
  }
  if (plaintext != NULL) {
    memzero(plaintext, plaintext_capacity);
  }
  if (credential_id == NULL || plaintext == NULL || plaintext_len == NULL ||
      credential_id_len < SE_FIDO_CREDENTIAL_ID_MIN_LEN ||
      credential_id_len > SE_FIDO_CREDENTIAL_ID_MAX_LEN ||
      plaintext_capacity < SE_FIDO_CREDENTIAL_PLAINTEXT_MAX_LEN ||
      !se_prepare_fido_seed_ready() || !se_fido_resident_api_is_supported()) {
    goto cleanup;
  }
  request[0] = rp_id_hash != NULL ? 1U : 0U;
  if (rp_id_hash != NULL) {
    memcpy(request + request_len, rp_id_hash, 32);
    request_len += 32;
  }
  memcpy(request + request_len, credential_id, credential_id_len);
  request_len += credential_id_len;
  if (se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_CREDENTIAL_VALIDATE,
                         request, request_len, plaintext, &response_len,
                         NULL) != SE_SECURE_OK ||
      response_len == 0 ||
      response_len > SE_FIDO_CREDENTIAL_PLAINTEXT_MAX_LEN) {
    goto cleanup;
  }
  *plaintext_len = response_len;
  result = sectrue;

cleanup:
  if (result != sectrue && plaintext != NULL) {
    memzero(plaintext, plaintext_capacity);
  }
  memzero(request, sizeof(request));
  return result;
}

secbool se_fido_resident_delete(uint8_t index) {
  uint16_t response_len = 0;

  if (index >= SE_FIDO_RESIDENT_SLOT_COUNT || !se_prepare_fido_seed_ready() ||
      !se_fido_resident_api_is_supported()) {
    return secfalse;
  }
  return se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_RESIDENT_DELETE,
                            &index, sizeof(index), NULL, &response_len,
                            NULL) == SE_SECURE_OK && response_len == 0
             ? sectrue
             : secfalse;
}

secbool se_fido_resident_clear(void) {
  uint16_t response_len = 0;

  if (!se_prepare_fido_seed_ready() || !se_fido_resident_api_is_supported()) {
    return secfalse;
  }
  return se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_RESIDENT_CLEAR, NULL,
                            0, NULL, &response_len, NULL) == SE_SECURE_OK &&
                 response_len == 0
             ? sectrue
             : secfalse;
}

secbool se_fido_resident_import(const uint8_t *credential_id,
                                uint16_t credential_id_len,
                                uint8_t *slot_index, uint8_t *action) {
  uint8_t response[2] = {0};
  uint16_t response_len = sizeof(response);
  secbool result = secfalse;

  if (slot_index != NULL) {
    *slot_index = 0;
  }
  if (action != NULL) {
    *action = 0;
  }
  if (credential_id == NULL || slot_index == NULL || action == NULL ||
      credential_id_len < SE_FIDO_CREDENTIAL_ID_MIN_LEN ||
      credential_id_len > SE_FIDO_RESIDENT_CREDENTIAL_ID_MAX_LEN ||
      !se_prepare_fido_seed_ready() || !se_fido_resident_api_is_supported()) {
    goto cleanup;
  }
  if (se_secure_exchange(SE_INS_FIDO, 0x00, SE_FIDO_RESIDENT_IMPORT,
                         credential_id, credential_id_len, response,
                         &response_len, NULL) != SE_SECURE_OK ||
      response_len != sizeof(response) ||
      response[0] >= SE_FIDO_RESIDENT_SLOT_COUNT ||
      (response[1] != SE_FIDO_CREDENTIAL_ACTION_CREATED &&
       response[1] != SE_FIDO_CREDENTIAL_ACTION_REPLACED)) {
    goto cleanup;
  }
  *slot_index = response[0];
  *action = response[1];
  result = sectrue;

cleanup:
  if (result != sectrue) {
    if (slot_index != NULL) {
      *slot_index = 0;
    }
    if (action != NULL) {
      *action = 0;
    }
  }
  memzero(response, sizeof(response));
  return result;
}

secbool se_fido_hmac_secret(const uint8_t *credential_id,
                            uint16_t credential_id_len, const uint8_t *salt,
                            uint16_t salt_len, uint8_t *output) {
  uint8_t request[2 + SE_FIDO_CREDENTIAL_ID_MAX_LEN + 1 + 64] = {0};
  uint8_t response[64] = {0};
  uint16_t response_len = sizeof(response);
  secbool result = secfalse;

  if (salt_len != 32U && salt_len != 64U) {
    goto cleanup;
  }
  if (output != NULL) {
    memzero(output, salt_len);
  }
  if (credential_id == NULL || salt == NULL || output == NULL ||
      credential_id_len < SE_FIDO_CREDENTIAL_ID_MIN_LEN ||
      credential_id_len > SE_FIDO_CREDENTIAL_ID_MAX_LEN) {
    goto cleanup;
  }
  if (!se_prepare_fido_seed_ready()) goto cleanup;
  request[0] = (uint8_t)(credential_id_len >> 8);
  request[1] = (uint8_t)credential_id_len;
  memcpy(request + 2, credential_id, credential_id_len);
  request[2 + credential_id_len] = (uint8_t)salt_len;
  memcpy(request + 3 + credential_id_len, salt, salt_len);
  response_len = salt_len;
  se_secure_result_t exchange = se_secure_exchange(
      SE_INS_FIDO, 0x00, SE_FIDO_HMAC_SECRET, request,
      3 + credential_id_len + salt_len, response, &response_len, NULL);
  if (exchange != SE_SECURE_OK || response_len != salt_len) {
    goto cleanup;
  }
  memcpy(output, response, response_len);
  result = sectrue;

cleanup:
  memzero(request, sizeof(request));
  memzero(response, sizeof(response));
  return result;
}

bool check_se_fido_seed(void (*callback)(void)) {
  uint8_t percent = 0;

  if (se_fido_seed_ready_hint) {
    return true;
  }
  se_long_operation_keepalive = callback;
  secbool result = se_gen_root_node(&percent);
  se_long_operation_keepalive = NULL;
  return result == sectrue && percent == 100;
}

bool se_fido_seed_is_ready(void) {
  return se_secure_channel.valid && se_fido_seed_ready_hint;
}

pin_result_t se_get_pin_result_type(void) { return g_last_pin_result; }

secbool se_set_pin_passphrase(const char *pin, const char *passphrase_pin,
                              const char *passphrase, bool *override) {
  size_t pin_len = 0;
  size_t passphrase_pin_len = 0;
  size_t passphrase_len = 0;

  if (override) {
    *override = false;
  }

  if (!se_get_string_length(pin, 50, &pin_len) || pin_len == 0) {
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }
  if (!se_get_string_length(passphrase_pin, 50, &passphrase_pin_len) ||
      passphrase_pin_len < 6) {
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }
  if (!se_get_string_length(passphrase, 50, &passphrase_len) ||
      passphrase_len == 0) {
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }

  uint8_t
      buf[2 * 50 + 50 + 3];  // 2 * PIN_MAX_LENGTH + PASSPHRASE_MAX_LENGTH + 3
  uint8_t resp[2] = {PIN_SUCCESS, 0};
  uint16_t resp_len = sizeof(resp);
  uint32_t offset = 0;

  buf[offset++] = (uint8_t)pin_len;
  memcpy(buf + offset, pin, pin_len);
  offset += pin_len;
  buf[offset++] = (uint8_t)passphrase_pin_len;
  memcpy(buf + offset, passphrase_pin, passphrase_pin_len);
  offset += passphrase_pin_len;
  buf[offset++] = (uint8_t)passphrase_len;
  memcpy(buf + offset, passphrase, passphrase_len);
  offset += passphrase_len;

  secbool transmit_result =
      se_transmit_mac(SE_INS_PIN, 0x00, 0x09, buf, offset, resp, &resp_len);
  memzero(buf, sizeof(buf));
  if (!transmit_result || resp_len > sizeof(resp)) {
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }
  if (resp_len != 0 && resp[0] != PIN_SUCCESS) {
    g_last_pin_result = (pin_result_t)resp[0];
    return secfalse;
  }

  if (resp_len == sizeof(resp)) {
    if (override) {
      *override = resp[1] == 0x55;
    }
  } else {
    resp_len = 1;
    if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x0D, NULL, 0, resp, &resp_len) ||
        resp_len != 1) {
      g_last_pin_result = PIN_FAILED;
      return secfalse;
    }
    if (override) {
      *override = resp[0] == 0x55;
    }
  }

  g_last_pin_result = PIN_SUCCESS;
  return sectrue;
}

secbool se_delete_pin_passphrase(const char *passphrase_pin, bool *current) {
  uint8_t pin_buff[64] = {0};
  uint8_t recv_buf[2] = {0};
  uint16_t recv_len = sizeof(recv_buf);
  size_t passphrase_pin_len = 0;

  if (!se_get_string_length(passphrase_pin, 50, &passphrase_pin_len)) {
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }

  pin_buff[0] = (uint8_t)passphrase_pin_len;
  memcpy(pin_buff + 1, passphrase_pin, passphrase_pin_len);

  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x0A, pin_buff, pin_buff[0] + 1,
                       recv_buf, &recv_len) ||
      recv_len == 0 || recv_len > sizeof(recv_buf)) {
    memzero(pin_buff, sizeof(pin_buff));
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }

  memzero(pin_buff, sizeof(pin_buff));

  g_last_pin_result = (pin_result_t)recv_buf[0];
  if (current) {
    *current = recv_len == sizeof(recv_buf) && recv_buf[1] == 0x55;
  }

  return (g_last_pin_result == PIN_SUCCESS) ? sectrue : secfalse;
}

secbool se_get_pin_passphrase_space(uint8_t *space) {
  uint8_t response = 0;
  uint16_t resp_len = sizeof(response);
  if (space == NULL) {
    return secfalse;
  }
  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x0C, NULL, 0, &response, &resp_len) ||
      resp_len != sizeof(response)) {
    *space = 0;
    return secfalse;
  }
  *space = response;
  return sectrue;
}

secbool se_check_passphrase_btc_test_address(const char *address) {
  uint8_t addr_buff[128] = {0};
  uint8_t result_buf[1] = {0};
  uint16_t recv_len = sizeof(result_buf);
  size_t address_len = 0;

  if (!se_get_string_length(address, 64, &address_len)) {
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }

  addr_buff[0] = (uint8_t)address_len;
  memcpy(addr_buff + 1, address, address_len);

  if (!se_transmit_mac(SE_INS_PIN, 0x00, 0x0B, addr_buff, addr_buff[0] + 1,
                       result_buf, &recv_len) ||
      recv_len != sizeof(result_buf)) {
    memzero(addr_buff, sizeof(addr_buff));
    return secfalse;
  }

  memzero(addr_buff, sizeof(addr_buff));
  return result_buf[0] == 0x55 ? sectrue : secfalse;
}

secbool se_change_pin_passphrase(const char *old_pin, const char *new_pin) {
  uint8_t buf[128];
  uint8_t resp[1];
  uint16_t resp_len = 1;
  size_t old_pin_len = 0;
  size_t new_pin_len = 0;

  if (!se_get_string_length(old_pin, MAX_PIN_LEN, &old_pin_len) ||
      !se_get_string_length(new_pin, MAX_PIN_LEN, &new_pin_len) ||
      old_pin_len < 6 || new_pin_len < 6) {
    return secfalse;
  }

  buf[0] = (uint8_t)old_pin_len;
  memcpy(buf + 1, old_pin, old_pin_len);
  buf[1 + old_pin_len] = (uint8_t)new_pin_len;
  memcpy(buf + 1 + old_pin_len + 1, new_pin, new_pin_len);

  secbool transmit_result = se_transmit_mac(
      SE_INS_PIN, 0x00, 0x0E, buf,
      (uint16_t)(1U + old_pin_len + 1U + new_pin_len), resp, &resp_len);
  memzero(buf, sizeof(buf));
  if (!transmit_result || resp_len != sizeof(resp)) {
    g_last_pin_result = PIN_FAILED;
    return secfalse;
  }

  g_last_pin_result = (pin_result_t)resp[0];
  return (g_last_pin_result == PIN_SUCCESS) ? sectrue : secfalse;
}

#endif
#endif
