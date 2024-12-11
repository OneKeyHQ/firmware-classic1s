// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cose_key.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "resident_credential.h"

#include "../config.h"
#include "../crypto.h"
#include "../gettext.h"
#include "../i18n/keys.h"
#include "../layout2.h"
#include "../protect.h"
#include "../se_chip.h"
#include "../usb.h"
#include "aes/aes.h"
#include "buttons.h"
#include "chacha20poly1305/rfc7539.h"
#include "ctap_hid.h"
#include "hmac.h"
#include "nist256p1.h"
#include "rand.h"
#include "util.h"

const uint8_t CTAP_AAGUID[16] =
    "\x69\xe7\xc3\x6f\xf2\xf6\x9e\x0d\x07\xa6\xbc\xc2\x43\x26\x2e\x6b";

const uint8_t device_cert[] =
    "\x30\x82\x02\x65\x30\x82\x02\x0C\xA0\x03\x02\x01\x02\x02\x08\x2F\x1F\xAB"
    "\x58\x0B\xEB\xE5\xF0\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02\x30"
    "\x81\x97\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x43\x4E\x31\x10\x30"
    "\x0E\x06\x03\x55\x04\x08\x13\x07\x42\x45\x49\x4A\x49\x4E\x47\x31\x10\x30"
    "\x0E\x06\x03\x55\x04\x07\x13\x07\x48\x41\x49\x44\x49\x41\x4E\x31\x1F\x30"
    "\x1D\x06\x03\x55\x04\x0A\x13\x16\x4F\x4E\x45\x4B\x45\x59\x20\x47\x4C\x4F"
    "\x42\x41\x4C\x20\x43\x4F\x2E\x2C\x20\x4C\x54\x44\x31\x0F\x30\x0D\x06\x03"
    "\x55\x04\x0B\x13\x06\x4F\x4E\x45\x4B\x45\x59\x31\x14\x30\x12\x06\x03\x55"
    "\x04\x03\x13\x0B\x4F\x4E\x45\x4B\x45\x59\x20\x52\x4F\x4F\x54\x31\x1C\x30"
    "\x1A\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x0D\x64\x65\x76\x40"
    "\x6F\x6E\x65\x6B\x65\x79\x2E\x73\x6F\x30\x1E\x17\x0D\x32\x34\x31\x30\x31"
    "\x38\x30\x32\x30\x37\x30\x30\x5A\x17\x0D\x32\x39\x31\x30\x31\x38\x30\x32"
    "\x30\x37\x30\x30\x5A\x30\x81\xAA\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13"
    "\x02\x43\x4E\x31\x10\x30\x0E\x06\x03\x55\x04\x08\x13\x07\x42\x45\x49\x4A"
    "\x49\x4E\x47\x31\x10\x30\x0E\x06\x03\x55\x04\x07\x13\x07\x48\x41\x49\x44"
    "\x49\x41\x4E\x31\x1F\x30\x1D\x06\x03\x55\x04\x0A\x13\x16\x4F\x4E\x45\x4B"
    "\x45\x59\x20\x47\x4C\x4F\x42\x41\x4C\x20\x43\x4F\x2E\x2C\x20\x4C\x54\x44"
    "\x31\x22\x30\x20\x06\x03\x55\x04\x0B\x13\x19\x41\x75\x74\x68\x65\x6E\x74"
    "\x69\x63\x61\x74\x6F\x72\x20\x41\x74\x74\x65\x73\x74\x61\x74\x69\x6F\x6E"
    "\x31\x14\x30\x12\x06\x03\x55\x04\x03\x13\x0B\x4F\x4E\x45\x4B\x45\x59\x20"
    "\x46\x49\x44\x4F\x31\x1C\x30\x1A\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09"
    "\x01\x16\x0D\x64\x65\x76\x40\x6F\x6E\x65\x6B\x65\x79\x2E\x73\x6F\x30\x59"
    "\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D"
    "\x03\x01\x07\x03\x42\x00\x04\x20\xC4\xC2\xCA\x28\x36\x66\xB2\xD7\xA0\x7C"
    "\x25\xB7\x2C\x5F\xC3\xAC\xFE\xB4\x9C\x64\xB0\x27\xC1\x84\xA3\xEA\x10\xE8"
    "\xD0\x3D\x48\xA4\xA4\x12\x6C\x3D\xBC\xC6\x1F\x9F\x54\xDA\xB5\xDE\x30\x85"
    "\xB7\x30\x9F\x28\x2A\xC7\x63\xAF\x6C\x0B\xF2\xFA\xA2\x33\x88\x0F\x75\xA3"
    "\x2D\x30\x2B\x30\x09\x06\x03\x55\x1D\x13\x04\x02\x30\x00\x30\x1E\x06\x09"
    "\x60\x86\x48\x01\x86\xF8\x42\x01\x0D\x04\x11\x16\x0F\x78\x63\x61\x20\x63"
    "\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x30\x0A\x06\x08\x2A\x86\x48\xCE"
    "\x3D\x04\x03\x02\x03\x47\x00\x30\x44\x02\x20\x2F\x73\x6A\x80\xBC\x4F\x38"
    "\x0D\xDE\x21\xC1\x35\x40\x59\x09\x8E\x4C\x81\x9D\x3E\xA9\x6A\x51\x2F\xB3"
    "\x54\xEE\xEF\x5B\x84\xA5\xF9\x02\x20\x04\xD8\x37\x35\x88\x76\xED\x71\x02"
    "\x84\x82\x6E\x26\x3A\xB8\x8F\x82\xA4\xF8\xD4\x2E\x15\x94\xB6\xE2\x7E\xDD"
    "\xC3\x7D\xE1\xA5\x63";

uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
static uint8_t KEY_AGREEMENT_PUB[65];
static uint8_t KEY_AGREEMENT_PRIV[32];

// static void ctap_reset_key_agreement();

struct _getAssertionState getAssertionState;

uint8_t ctap_get_info(CborEncoder *cbor_encoder) {
  int ret;
  CborEncoder array;
  CborEncoder map;
  CborEncoder options;
  CborEncoder pins;

  ret = cbor_encoder_create_map(cbor_encoder, &map, 6);
  check_ret(ret);
  {
    ret = cbor_encode_uint(&map, RESP_versions);  //  versions key
    check_ret(ret);
    {
      ret = cbor_encoder_create_array(&map, &array, 2);
      check_ret(ret);
      {
        ret = cbor_encode_text_stringz(&array, "U2F_V2");
        check_ret(ret);
        ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
        check_ret(ret);
      }
      ret = cbor_encoder_close_container(&map, &array);
      check_ret(ret);
    }

    ret = cbor_encode_uint(&map, RESP_extensions);
    check_ret(ret);
    {
      ret = cbor_encoder_create_array(&map, &array, 1);
      check_ret(ret);
      {
        ret = cbor_encode_text_stringz(&array, "hmac-secret");
        check_ret(ret);
      }
      ret = cbor_encoder_close_container(&map, &array);
      check_ret(ret);
    }

    ret = cbor_encode_uint(&map, RESP_aaguid);
    check_ret(ret);
    {
      ret = cbor_encode_byte_string(&map, CTAP_AAGUID, 16);
      check_ret(ret);
    }

    ret = cbor_encode_uint(&map, RESP_options);
    check_ret(ret);
    {
      ret = cbor_encoder_create_map(&map, &options, 3);
      check_ret(ret);
      {
        ret = cbor_encode_text_string(&options, "rk", 2);
        check_ret(ret);
        {
          ret = cbor_encode_boolean(&options,
                                    1);  // Capable of storing keys locally
          check_ret(ret);
        }

        ret = cbor_encode_text_string(&options, "up", 2);
        check_ret(ret);
        {
          ret = cbor_encode_boolean(&options,
                                    1);  // Capable of testing user presence
          check_ret(ret);
        }

        ret = cbor_encode_text_string(&options, "uv", 2);
        check_ret(ret);
        {
          ret = cbor_encode_boolean(&options, 1);
          check_ret(ret);
        }
      }
      ret = cbor_encoder_close_container(&map, &options);
      check_ret(ret);
    }

    ret = cbor_encode_uint(&map, RESP_maxMsgSize);
    check_ret(ret);
    {
      ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
      check_ret(ret);
    }

    ret = cbor_encode_uint(&map, RESP_pinProtocols);
    check_ret(ret);
    {
      ret = cbor_encoder_create_array(&map, &pins, 1);
      check_ret(ret);
      {
        ret = cbor_encode_int(&pins, 1);
        check_ret(ret);
      }
      ret = cbor_encoder_close_container(&map, &pins);
      check_ret(ret);
    }
  }
  ret = cbor_encoder_close_container(cbor_encoder, &map);
  check_ret(ret);

  return CTAP1_ERR_SUCCESS;
}

static int ctap_add_cose_key(CborEncoder *cose_key, uint8_t *x, uint8_t *y,
                             uint8_t credtype, int32_t algtype) {
  int ret;
  CborEncoder map;

  if (credtype != PUB_KEY_CRED_PUB_KEY) {
    ctap_printf("Error, pubkey credential type not supported\n");
    return -1;
  }

  ret = cbor_encoder_create_map(cose_key, &map,
                                algtype != COSE_ALG_EDDSA ? 5 : 4);
  check_ret(ret);

  {
    ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
    check_ret(ret);
    ret = cbor_encode_int(
        &map, algtype != COSE_ALG_EDDSA ? COSE_KEY_KTY_EC2 : COSE_KEY_KTY_OKP);
    check_ret(ret);
  }

  {
    ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
    check_ret(ret);
    ret = cbor_encode_int(&map, algtype);
    check_ret(ret);
  }

  {
    ret = cbor_encode_int(&map, COSE_KEY_LABEL_CRV);
    check_ret(ret);
    ret =
        cbor_encode_int(&map, algtype != COSE_ALG_EDDSA ? COSE_KEY_CRV_P256
                                                        : COSE_KEY_CRV_ED25519);
    check_ret(ret);
  }

  {
    ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
    check_ret(ret);
    ret = cbor_encode_byte_string(&map, x, 32);
    check_ret(ret);
  }

  if (algtype != COSE_ALG_EDDSA) {
    ret = cbor_encode_int(&map, COSE_KEY_LABEL_Y);
    check_ret(ret);
    ret = cbor_encode_byte_string(&map, y, 32);
    check_ret(ret);
  }

  ret = cbor_encoder_close_container(cose_key, &map);
  check_ret(ret);

  return 0;
}

static int ctap_get_credrandom(uint8_t *cred_id, uint32_t cred_id_len,
                               uint8_t *credrandom) {
  Slip21Node node;
  const uint8_t *path[] = {(uint8_t *)"SLIP-0022", (uint8_t *)CRED_ID_VERSION,
                           (uint8_t *)"Encryption key"};
  const uint8_t path_len[3] = {9, CRED_ID_VERSION_SIZE, 14};

  se_slip21_fido_node(node.data);

  for (size_t i = 0; i < 3; i++) {
    slip21_derive_path(&node, path[i], path_len[i]);
  }

  slip21_derive_path(&node, cred_id, cred_id_len);

  memcpy(credrandom, slip21_key(&node), 32);

  return 0;
}

static void ctap_reset_key_agreement(void) {
  static bool initialized = false;
  if (initialized) {
    return;
  }
  random_buffer(KEY_AGREEMENT_PRIV, sizeof(KEY_AGREEMENT_PRIV));
  ecdsa_get_public_key65(&nist256p1, KEY_AGREEMENT_PRIV, KEY_AGREEMENT_PUB);
  initialized = true;
}

static int ctap_make_extensions(CTAP_extensions *ext, uint8_t *cred_id,
                                uint32_t cred_id_len, uint8_t *ext_encoder_buf,
                                unsigned int *ext_encoder_buf_size) {
  CborEncoder extensions;
  int ret;
  uint8_t extensions_used = 0;
  uint8_t hmac_secret_output_is_valid = 0;
  uint8_t hmac_secret_requested_is_valid = 0;
  uint8_t cred_protect_is_valid = 0;
  uint8_t hmac_secret_output[64];
  uint8_t shared_secret[65];
  uint8_t hmac[32];
  uint8_t credRandom[32];
  uint8_t saltEnc[64], salt[64];

  uint8_t pubkey[65];

  pubkey[0] = 0x04;
  memcpy(pubkey + 1, &ext->hmac_secret.keyAgreement.pubkey.x, 32);
  memcpy(pubkey + 33, &ext->hmac_secret.keyAgreement.pubkey.y, 32);

  if (ext->hmac_secret_present == EXT_HMAC_SECRET_PARSED) {
    memcpy(saltEnc, ext->hmac_secret.saltEnc, sizeof(saltEnc));

    ctap_reset_key_agreement();

    ecdh_multiply(&nist256p1, KEY_AGREEMENT_PRIV, pubkey, shared_secret);

    sha256_Raw(shared_secret + 1, 32, shared_secret);

    HMAC_SHA256_CTX ctx256;

    hmac_sha256_Init(&ctx256, shared_secret, 32);
    hmac_sha256_Update(&ctx256, saltEnc, ext->hmac_secret.saltLen);
    hmac_sha256_Final(&ctx256, hmac);

    if (memcmp(ext->hmac_secret.saltAuth, hmac, 16) == 0) {
      ctap_printf("saltAuth is valid\r\n");
    } else {
      ctap_printf("saltAuth is invalid\r\n");
      return CTAP2_ERR_EXTENSION_FIRST;
    }

    // Generate credRandom
    ctap_get_credrandom(cred_id, cred_id_len, credRandom);

    // Decrypt saltEnc
    aes_decrypt_ctx dec_ctx = {0};
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    aes_decrypt_key256(shared_secret, &dec_ctx);
    aes_cbc_decrypt(saltEnc, salt, ext->hmac_secret.saltLen, iv, &dec_ctx);

    // Generate outputs
    hmac_sha256_Init(&ctx256, credRandom, 32);
    hmac_sha256_Update(&ctx256, salt, ext->hmac_secret.saltLen);
    hmac_sha256_Final(&ctx256, hmac_secret_output);

    if (ext->hmac_secret.saltLen == 64) {
      hmac_sha256_Init(&ctx256, credRandom, 32);
      hmac_sha256_Update(&ctx256, salt + 32, 32);
      hmac_sha256_Final(&ctx256, hmac_secret_output + 32);
    }

    // Encrypt for final output
    aes_encrypt_ctx enc_ctx = {0};
    memset(iv, 0, sizeof(iv));
    aes_encrypt_key256(shared_secret, &enc_ctx);
    aes_cbc_encrypt(hmac_secret_output, hmac_secret_output,
                    ext->hmac_secret.saltLen, iv, &enc_ctx);

    extensions_used += 1;
    hmac_secret_output_is_valid = 1;
  } else if (ext->hmac_secret_present == EXT_HMAC_SECRET_REQUESTED) {
    extensions_used += 1;
    hmac_secret_requested_is_valid = 1;
  }
  if (ext->cred_protect != EXT_CRED_PROTECT_INVALID) {
    if (ext->cred_protect == EXT_CRED_PROTECT_OPTIONAL ||
        ext->cred_protect == EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID ||
        ext->cred_protect == EXT_CRED_PROTECT_REQUIRED) {
      extensions_used += 1;
      cred_protect_is_valid = 1;
    }
  }

  if (extensions_used > 0) {
    // output
    cbor_encoder_init(&extensions, ext_encoder_buf, *ext_encoder_buf_size, 0);
    {
      CborEncoder extension_output_map;
      ret = cbor_encoder_create_map(&extensions, &extension_output_map,
                                    extensions_used);
      check_ret(ret);
      if (hmac_secret_output_is_valid) {
        {
          ret = cbor_encode_text_stringz(&extension_output_map, "hmac-secret");
          check_ret(ret);

          ret =
              cbor_encode_byte_string(&extension_output_map, hmac_secret_output,
                                      ext->hmac_secret.saltLen);
          check_ret(ret);
        }
      }
      if (cred_protect_is_valid) {
        {
          ret = cbor_encode_text_stringz(&extension_output_map, "credProtect");
          check_ret(ret);

          ret = cbor_encode_int(&extension_output_map, ext->cred_protect);
          check_ret(ret);
        }
      }
      if (hmac_secret_requested_is_valid) {
        {
          ret = cbor_encode_text_stringz(&extension_output_map, "hmac-secret");
          check_ret(ret);

          ret = cbor_encode_boolean(&extension_output_map, 1);
          check_ret(ret);
        }
      }

      ret = cbor_encoder_close_container(&extensions, &extension_output_map);
      check_ret(ret);
    }
    *ext_encoder_buf_size =
        cbor_encoder_get_buffer_size(&extensions, ext_encoder_buf);

  } else {
    *ext_encoder_buf_size = 0;
  }

  return 0;
}

static int ctap_generate_credential_id(CTAP_makeCredential mc, uint32_t counter,
                                       uint8_t *cred_id,
                                       uint16_t *cred_id_len) {
  CborEncoder credential_id;
  uint8_t credential_id_buf[CRED_ID_MAX_LEN];

  uint8_t element_count = 0;

  if (strlen(mc.rp.id) > 0) {
    element_count++;
  }

  if (strlen(mc.rp.name) > 0) {
    element_count++;
  }

  if (mc.credInfo.user.id_size > 0) {
    element_count++;
  }

  if (strlen(mc.credInfo.user.name) > 0) {
    element_count++;
  }

  if (strlen(mc.credInfo.user.displayName) > 0) {
    element_count++;
  }

  // creation_time
  element_count++;

  if (mc.extensions.hmac_secret_present == EXT_HMAC_SECRET_REQUESTED) {
    element_count++;
  }

  // use sign count
  element_count++;

  // algorithm,curve

  CborEncoder map;

  cbor_encoder_init(&credential_id, credential_id_buf,
                    sizeof(credential_id_buf), 0);

  int ret = cbor_encoder_create_map(&credential_id, &map, element_count);
  check_ret(ret);
  {
    if (strlen(mc.rp.id) > 0) {
      ret = cbor_encode_uint(&map, CRED_ID_RP_ID);
      check_ret(ret);
      ret = cbor_encode_text_stringz(&map, mc.rp.id);
      check_ret(ret);
    }

    if (strlen(mc.rp.name) > 0) {
      ret = cbor_encode_uint(&map, CRED_ID_RP_NAME);
      check_ret(ret);
      ret = cbor_encode_text_stringz(&map, mc.rp.name);
      check_ret(ret);
    }

    if (mc.credInfo.user.id_size > 0) {
      ret = cbor_encode_uint(&map, CRED_ID_USER_ID);
      check_ret(ret);
      ret = cbor_encode_byte_string(&map, mc.credInfo.user.id,
                                    mc.credInfo.user.id_size);
      check_ret(ret);
    }

    if (strlen(mc.credInfo.user.name) > 0) {
      ret = cbor_encode_uint(&map, CRED_ID_USER_NAME);
      check_ret(ret);
      ret = cbor_encode_text_stringz(&map, mc.credInfo.user.name);
      check_ret(ret);
    }

    if (strlen(mc.credInfo.user.displayName) > 0) {
      ret = cbor_encode_uint(&map, CRED_ID_USER_DISPLAY_NAME);
      check_ret(ret);
      ret = cbor_encode_text_stringz(&map, mc.credInfo.user.displayName);
      check_ret(ret);
    }

    ret = cbor_encode_uint(&map, CRED_ID_CREATION_TIME);
    check_ret(ret);
    ret = cbor_encode_uint(&map, counter);
    check_ret(ret);

    if (mc.extensions.hmac_secret_present == EXT_HMAC_SECRET_REQUESTED) {
      ret = cbor_encode_uint(&map, CRED_ID_HMAC_SECRET);
      check_ret(ret);
      ret = cbor_encode_boolean(&map, 1);
      check_ret(ret);
    }

    ret = cbor_encode_uint(&map, CRED_ID_SIGN_COUNT);
    check_ret(ret);
    ret = cbor_encode_boolean(&map, 1);
    check_ret(ret);

    ret = cbor_encoder_close_container(&credential_id, &map);
    check_ret(ret);
  }
  uint16_t credential_id_len =
      cbor_encoder_get_buffer_size(&credential_id, credential_id_buf);

  // version + iv + ciphertext + tag
  if (*cred_id_len < credential_id_len + 32) {
    ctap_printf("credential_id_len too small\n");
    return CTAP1_ERR_OTHER;
  }

  ctap_printf("credential_id_len: %d\n", credential_id_len);
  dump_hex1(TAG_GREEN, credential_id_buf, credential_id_len);

  Slip21Node node;
  const uint8_t *path[] = {(uint8_t *)"SLIP-0022", (uint8_t *)CRED_ID_VERSION,
                           (uint8_t *)"Encryption key"};
  const uint8_t path_len[3] = {9, CRED_ID_VERSION_SIZE, 14};

  se_slip21_fido_node(node.data);

  ctap_printf("root node.data:\n");
  dump_hex1(TAG_GREEN, node.data, sizeof(node.data));

  for (size_t i = 0; i < 3; i++) {
    slip21_derive_path(&node, path[i], path_len[i]);
  }

  ctap_printf("derived node.data:\n");
  dump_hex1(TAG_GREEN, node.data, sizeof(node.data));

  uint8_t key[32], iv[12], tag[16], rp_id_hash[32];
  memcpy(key, slip21_key(&node), 32);
  random_buffer(iv, 12);

  chacha20poly1305_ctx ctx = {0};

  sha256_Raw((uint8_t *)mc.rp.id, mc.rp.size, rp_id_hash);

  rfc7539_init(&ctx, key, iv);
  rfc7539_auth(&ctx, rp_id_hash, sizeof(rp_id_hash));

  memcpy(cred_id, CRED_ID_VERSION, 4);
  memcpy(cred_id + 4, iv, 12);

  chacha20poly1305_encrypt(&ctx, credential_id_buf, cred_id + 16,
                           credential_id_len);
  rfc7539_finish(&ctx, sizeof(rp_id_hash), credential_id_len, tag);

  memcpy(cred_id + 16 + credential_id_len, tag, 16);

  *cred_id_len = credential_id_len + 16 + 16;

  ctap_printf("cred_id:");
  dump_hex1(TAG_GREEN, cred_id, *cred_id_len);
  return CTAP1_ERR_SUCCESS;
}

static int ctap_derive_credential_pubkey(uint8_t type, uint8_t *cred_id,
                                         uint16_t cred_id_len,
                                         uint8_t *pubkey) {
  HDNode node;

  uint32_t path[9] = {0};
  uint8_t path_len = 0;

  if (type == PUB_KEY_CRED_CTAP1) {
    path[0] = U2F_KEY_PATH;
    for (int i = 0; i < 8; i++) {
      path[i + 1] = cred_id[i * 4] | cred_id[i * 4 + 1] << 8 |
                    cred_id[i * 4 + 2] << 16 | cred_id[i * 4 + 3] << 24;
    }
    path_len = 9;

  } else if (type == PUB_KEY_CRED_PUB_KEY) {
    path[0] = PATH_HARDENED | 10022;

    path[1] = (cred_id[0] << 24) | (cred_id[1] << 16) | (cred_id[2] << 8) |
              cred_id[3];
    path[1] |= PATH_HARDENED;

    for (int i = 0; i < 4; i++) {
      path[2 + i] = (cred_id[cred_id_len - 16 + (i * 4)] << 24) |
                    (cred_id[cred_id_len - 15 + (i * 4)] << 16) |
                    (cred_id[cred_id_len - 14 + (i * 4)] << 8) |
                    cred_id[cred_id_len - 13 + (i * 4)];
      path[2 + i] |= PATH_HARDENED;
    }
    path_len = 6;
  }

  // ctap_printf("path values:\n");
  // for (int i = 0; i < path_len; i++) {
  //   ctap_printf("path[%d]: %04x\n", i, path[i]);
  // }

  if (!se_derive_fido_keys(&node, "nist256p1", path, path_len, NULL)) {
    return CTAP1_ERR_OTHER;
  }
  if (pubkey != NULL) {
    ecdsa_uncompress_pubkey(&nist256p1, node.public_key, pubkey);
  }
  return CTAP1_ERR_SUCCESS;
}

#define COSE_KEY_BUF_SIZE 80

static int ctap_make_auth_data(CTAP_makeCredential mc, uint32_t counter,
                               uint8_t *cred_id, uint16_t cred_id_len,
                               uint8_t *pubkey, uint8_t *auth_data_buf,
                               uint32_t *auth_data_len) {
  CTAP_authData *authData = (CTAP_authData *)auth_data_buf;

  if (sizeof(CTAP_authData) + cred_id_len + COSE_KEY_BUF_SIZE >
      *auth_data_len) {
    ctap_printf("auth data buffer too small\n");
    return CTAP2_ERR_PROCESSING;
  }

  sha256_Raw((uint8_t *)mc.rp.id, mc.rp.size, authData->head.rpIdHash);

  authData->head.flags =
      AUTH_DATA_FLAG_UP | AUTH_DATA_FLAG_UV | AUTH_DATA_FLAG_AT;

  authData->head.signCount = counter;

  memcpy(authData->attest.aaguid, CTAP_AAGUID, sizeof(CTAP_AAGUID));
  authData->attest.credLenL = cred_id_len & 0x00FF;
  authData->attest.credLenH = (cred_id_len & 0xFF00) >> 8;
  memcpy(auth_data_buf + sizeof(CTAP_authData), cred_id, cred_id_len);

  CborEncoder cose_key;
  uint8_t *cose_key_buf;

  cose_key_buf = auth_data_buf + sizeof(CTAP_authData) + cred_id_len;

  cbor_encoder_init(&cose_key, cose_key_buf,
                    *auth_data_len - sizeof(CTAP_authData) - cred_id_len, 0);

  int ret = ctap_add_cose_key(&cose_key, pubkey + 1, pubkey + 33,
                              mc.credInfo.publicKeyCredentialType,
                              mc.credInfo.COSEAlgorithmIdentifier);
  check_ret(ret);

  uint16_t cose_key_len = cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);

  ctap_printf("cose_key_len: %d\n", cose_key_len);
  dump_hex1(NULL, auth_data_buf + sizeof(CTAP_authData) + cred_id_len,
            cose_key_len);

  // extensions
  unsigned int ext_encoder_buf_size =
      *auth_data_len - sizeof(CTAP_authData) - cred_id_len - cose_key_len;
  uint8_t *ext_encoder_buf =
      auth_data_buf + sizeof(CTAP_authData) + cred_id_len + cose_key_len;

  ret = ctap_make_extensions(&mc.extensions, NULL, 0, ext_encoder_buf,
                             &ext_encoder_buf_size);
  check_retr(ret);
  if (ext_encoder_buf_size) {
    authData->head.flags |= AUTH_DATA_FLAG_ED;
  }

  *auth_data_len =
      sizeof(CTAP_authData) + cred_id_len + cose_key_len + ext_encoder_buf_size;

  return 0;
}

/**
 *
 * @param in_sigbuf IN location to deposit signature (must be 64 bytes)
 * @param out_sigder OUT location to deposit der signature (must be 72 bytes)
 * @return length of der signature
 * // FIXME add tests for maximum and minimum length of the input and output
 */
int ctap_encode_der_sig(const uint8_t *const in_sigbuf,
                        uint8_t *const out_sigder) {
  // Need to caress into dumb der format ..
  uint8_t i;
  uint8_t lead_s = 0;  // leading zeros
  uint8_t lead_r = 0;
  for (i = 0; i < 32; i++) {
    if (in_sigbuf[i] == 0) {
      lead_r++;
    } else {
      break;
    }
  }

  for (i = 0; i < 32; i++) {
    if (in_sigbuf[i + 32] == 0) {
      lead_s++;
    } else {
      break;
    }
  }

  int8_t pad_s = ((in_sigbuf[32 + lead_s] & 0x80) == 0x80);
  int8_t pad_r = ((in_sigbuf[0 + lead_r] & 0x80) == 0x80);

  memset(out_sigder, 0, 72);
  out_sigder[0] = 0x30;
  out_sigder[1] = 0x44 + pad_s + pad_r - lead_s - lead_r;

  // R ingredient
  out_sigder[2] = 0x02;
  out_sigder[3 + pad_r] = 0;
  out_sigder[3] = 0x20 + pad_r - lead_r;
  memmove(out_sigder + 4 + pad_r, in_sigbuf + lead_r, 32u - lead_r);

  // S ingredient
  out_sigder[4 + 32 + pad_r - lead_r] = 0x02;
  out_sigder[5 + 32 + pad_r + pad_s - lead_r] = 0;
  out_sigder[5 + 32 + pad_r - lead_r] = 0x20 + pad_s - lead_s;
  memmove(out_sigder + 6 + 32 + pad_r + pad_s - lead_r,
          in_sigbuf + 32u + lead_s, 32u - lead_s);

  return 0x46 + pad_s + pad_r - lead_r - lead_s;
}

// require load_key prior to this
// @data data to hash before signature, MUST have room to append
// clientDataHash for ED25519
// @clientDataHash for signature
// @tmp buffer for hash.  (can be same as data if data >= 32 bytes)
// @sigbuf OUT location to deposit signature (must be 64 bytes)
// @sigder OUT location to deposit der signature (must be 72 bytes)
// @return length of der signature
int ctap_calculate_signature(uint8_t *data, int datalen,
                             uint8_t *clientDataHash, uint8_t *sigbuf,
                             uint8_t *sigder, int32_t alg) {
  // calculate attestation sig
  if (alg == COSE_ALG_EDDSA) {
    // crypto_ed25519_sign(data, datalen, clientDataHash,
    // CLIENT_DATA_HASH_SIZE,
    //                     sigder);  // not DER, just plain binary!
    return 0;
  } else {
    SHA256_CTX ctx = {0};
    uint8_t hash[32];

    sha256_Init(&ctx);
    sha256_Update(&ctx, data, datalen);
    sha256_Update(&ctx, clientDataHash, CLIENT_DATA_HASH_SIZE);
    sha256_Final(&ctx, hash);

    if (!se_fido_att_sign_digest(hash, sigbuf)) {
      return 0;
    }
    return ctap_encode_der_sig(sigbuf, sigder);
  }
  return 0;
}

uint8_t ctap_add_attest_statement(CborEncoder *map, uint8_t *sigder, int len) {
  int ret;

  CborEncoder stmtmap;
  CborEncoder x5carr;

  ret = cbor_encode_int(map, RESP_attStmt);
  check_ret(ret);
  ret = cbor_encoder_create_map(map, &stmtmap, 3);
  check_ret(ret);
  {
    ret = cbor_encode_text_stringz(&stmtmap, "alg");
    check_ret(ret);
    ret = cbor_encode_int(&stmtmap, COSE_ALG_ES256);
    check_ret(ret);
  }
  {
    ret = cbor_encode_text_stringz(&stmtmap, "sig");
    check_ret(ret);
    ret = cbor_encode_byte_string(&stmtmap, sigder, len);
    check_ret(ret);
  }
  {
    ret = cbor_encode_text_stringz(&stmtmap, "x5c");
    check_ret(ret);
    ret = cbor_encoder_create_array(&stmtmap, &x5carr, 1);
    check_ret(ret);
    {
      ret = cbor_encode_byte_string(&x5carr, device_cert,
                                    sizeof(device_cert) - 1);
      check_ret(ret);
      ret = cbor_encoder_close_container(&stmtmap, &x5carr);
      check_ret(ret);
    }
  }

  ret = cbor_encoder_close_container(map, &stmtmap);
  check_ret(ret);
  return 0;
}

// Return 1 if credential belongs to this token
int ctap_authenticate_credential_data(const uint8_t *rp_id_hash,
                                      CTAP_credentialDescriptor *desc) {
  uint8_t key[32], iv[12], tag[16], id_tag[16];

  uint8_t cred_id_decrypted[512];

  static Slip21Node node;
  static bool node_initialized = false;

  ctap_printf("ctap_authenticate_credential len %d, type %d:",
              desc->cred_id_len, desc->type);
  dump_hex1(NULL, desc->cred_id, desc->cred_id_len);

  if (desc->type == PUB_KEY_CRED_UNKNOWN) {
    return 0;
  }

  if ((desc->cred_id_len > CTAP2_KEY_HANDLE_SIZE_MIN) &&
      (memcmp(desc->cred_id, CRED_ID_VERSION, CRED_ID_VERSION_SIZE) == 0)) {
    if (!node_initialized) {
      const uint8_t *path[] = {(uint8_t *)"SLIP-0022",
                               (uint8_t *)CRED_ID_VERSION,
                               (uint8_t *)"Encryption key"};
      const uint8_t path_len[3] = {9, CRED_ID_VERSION_SIZE, 14};

      se_slip21_fido_node(node.data);
      for (size_t i = 0; i < 3; i++) {
        slip21_derive_path(&node, path[i], path_len[i]);
      }
      node_initialized = true;
    }

    chacha20poly1305_ctx ctx = {0};

    memcpy(key, slip21_key(&node), 32);
    memcpy(iv, desc->cred_id + 4, 12);
    memcpy(tag, desc->cred_id + desc->cred_id_len - 16, 16);

    rfc7539_init(&ctx, key, iv);
    rfc7539_auth(&ctx, rp_id_hash, 32);

    chacha20poly1305_decrypt(&ctx, desc->cred_id + 16, cred_id_decrypted,
                             desc->cred_id_len - 32);
    rfc7539_finish(&ctx, 32, desc->cred_id_len - 32, id_tag);

    if (memcmp(tag, id_tag, 16) == 0) {
      ctap_parse_credential_id(&desc->credential, cred_id_decrypted,
                               desc->cred_id_len - 32);
      desc->type = PUB_KEY_CRED_PUB_KEY;
      return 1;
    }
    return 0;
  }
  if (desc->cred_id_len == CTAP1_KEY_HANDLE_SIZE) {
    ctap_printf("CTAP1 key handle\n");
    if (se_u2f_validate_handle(rp_id_hash, desc->cred_id)) {
      desc->type = PUB_KEY_CRED_CTAP1;
      return 1;
    }
  }

  return 0;
}

int ctap_authenticate_credential(struct rpId *rp,
                                 CTAP_credentialDescriptor *desc) {
  uint8_t rp_id_hash[32];
  sha256_Raw((uint8_t *)rp->id, rp->size, rp_id_hash);
  return ctap_authenticate_credential_data(rp_id_hash, desc);
}

static char *get_account_name(CTAP_userEntity *user) {
  static char id_string[USER_ID_MAX_SIZE * 2 + 1];
  if (strlen(user->name) > 0) {
    return user->name;
  }
  if (strlen(user->displayName) > 0) {
    return user->displayName;
  }
  if (user->id_size > 0) {
    data2hex(user->id, user->id_size, id_string);
    return id_string;
  }
  return NULL;
}

uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *request,
                             int length) {
  CTAP_makeCredential MC;

  int ret;

  ctap_printf("makeCredential request:\n");
  dump_hex1(TAG_GREEN, request, length);

  ret = ctap_parse_make_credential(&MC, encoder, request, length);

  if (ret != 0) {
    ctap_printf("error, parse_make_credential failed\n");
    return ret;
  }

  if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask) {
    ctap_printf(
        "error, required parameter(s) for makeCredential are missing\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }

  if (MC.up == 1 || MC.up == 0) {
    return CTAP2_ERR_INVALID_OPTION;
  }

  if (MC.pinAuthPresent) {
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  // if (MC.credInfo.rk) {
  //   return CTAP2_ERR_UNSUPPORTED_OPTION;
  // }

  if (MC.credInfo.COSEAlgorithmIdentifier != COSE_ALG_ES256) {
    return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
  }

  CTAP_credentialDescriptor excl_cred = {0};
  for (size_t i = 0; i < MC.excludeListSize; i++) {
    memset(&excl_cred, 0, sizeof(excl_cred));
    ret = parse_credential_descriptor(&MC.excludeList, &excl_cred);
    if (ret == CTAP2_ERR_INVALID_CBOR_TYPE) {
      continue;
    }
    check_retr(ret);

    if (ctap_authenticate_credential(&MC.rp, &excl_cred)) {
      return CTAP2_ERR_CREDENTIAL_EXCLUDED;
    }

    ret = cbor_value_advance(&MC.excludeList);
    check_ret(ret);
  }

  char *account_name = get_account_name(&MC.credInfo.user);

  layoutDialogCenterAdapterV2("FIDO2 Make Credential", NULL, NULL,
                              &bmp_bottom_right_confirm, NULL, NULL, MC.rp.id,
                              account_name, NULL, NULL, NULL);

  uint32_t start_time = svc_timer_ms();
  while (1) {
    usbPoll();
    buttonUpdate();

    if (button.YesUp) {
      break;
    } else if (button.NoUp) {
      return CTAP2_ERR_OPERATION_DENIED;
    }
    // 60 seconds timeout
    if (svc_timer_ms() - start_time > timer1s * 60) {
      return CTAP2_ERR_OPERATION_DENIED;
    }
  }

  ctap_printf("FIDO2 Make Credential\n");
  uint32_t creation_time = config_nextU2FCounter();
  if (creation_time == 0) {
    // skip the first counter value
    creation_time = config_nextU2FCounter();
  }

  uint8_t cred_id_buf[CRED_ID_MAX_LEN];
  uint16_t cred_id_len = sizeof(cred_id_buf);

  if (ctap_generate_credential_id(MC, creation_time, cred_id_buf,
                                  &cred_id_len) != CTAP1_ERR_SUCCESS) {
    return CTAP1_ERR_OTHER;
  }

  uint8_t pubkey[65];
  if (ctap_derive_credential_pubkey(PUB_KEY_CRED_PUB_KEY, cred_id_buf,
                                    cred_id_len, pubkey) != CTAP1_ERR_SUCCESS) {
    return CTAP1_ERR_OTHER;
  }

  ctap_printf("pubkey:\n");
  dump_hex1(NULL, pubkey, 65);

  CborEncoder map;
  ret = cbor_encoder_create_map(encoder, &map, 3);
  check_ret(ret);

  {
    ret = cbor_encode_int(&map, RESP_fmt);
    check_ret(ret);
    ret = cbor_encode_text_stringz(&map, "packed");
    check_ret(ret);
  }

  uint8_t auth_data_buf[1024];
  uint32_t auth_data_len = sizeof(auth_data_buf);
  ret = ctap_make_auth_data(MC, creation_time, cred_id_buf, cred_id_len, pubkey,
                            auth_data_buf, &auth_data_len);
  check_retr(ret);

  {
    ret = cbor_encode_int(&map, RESP_authData);
    check_ret(ret);
    ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_len);
    check_ret(ret);
  }

  uint8_t sigbuf[64];
  uint8_t sigder[72];

  int sigder_sz =
      ctap_calculate_signature(auth_data_buf, auth_data_len, MC.clientDataHash,
                               sigbuf, sigder, COSE_ALG_ES256);
  ctap_printf("der sig [%d]: ", sigder_sz);
  dump_hex1(NULL, sigder, sigder_sz);

  ret = ctap_add_attest_statement(&map, sigder, sigder_sz);
  check_retr(ret);

  ret = cbor_encoder_close_container(encoder, &map);
  check_ret(ret);

  if (MC.credInfo.rk) {
    uint8_t rp_id_hash[32];
    sha256_Raw((uint8_t *)MC.rp.id, MC.rp.size, rp_id_hash);
    if (!resident_credential_store(rp_id_hash, MC.credInfo.user.id, cred_id_buf,
                                   cred_id_len)) {
      return CTAP1_ERR_OTHER;
    }
  }
  return CTAP1_ERR_SUCCESS;
}

/*static int pick_first_authentic_credential(CTAP_getAssertion * GA)*/
/*{*/
/*int i;*/
/*for (i = 0; i < GA->credLen; i++)*/
/*{*/
/*if (GA->creds[i].credential.enc.count != 0)*/
/*{*/
/*return i;*/
/*}*/
/*}*/
/*return -1;*/
/*}*/

static uint8_t ctap_add_credential_descriptor(CborEncoder *map,
                                              uint8_t *cred_id,
                                              uint32_t cred_id_len) {
  CborEncoder desc;

  int ret = cbor_encoder_create_map(map, &desc, 2);
  check_ret(ret);

  {
    ret = cbor_encode_text_string(&desc, "id", 2);
    check_ret(ret);

    ret = cbor_encode_byte_string(&desc, cred_id, cred_id_len);
    check_ret(ret);
  }

  {
    ret = cbor_encode_text_string(&desc, "type", 4);
    check_ret(ret);

    ret = cbor_encode_text_string(&desc, "public-key", 10);
    check_ret(ret);
  }

  ret = cbor_encoder_close_container(map, &desc);
  check_ret(ret);

  return 0;
}
uint8_t ctap_add_user_entity(CborEncoder *map, CTAP_userEntity *user) {
  CborEncoder entity;
  int ret;
  int map_size = 1;

  ret = cbor_encoder_create_map(map, &entity, map_size);
  check_ret(ret);

  ret = cbor_encode_text_string(&entity, "id", 2);
  check_ret(ret);

  ret = cbor_encode_byte_string(&entity, user->id, user->id_size);
  check_ret(ret);

  ret = cbor_encoder_close_container(map, &entity);
  check_ret(ret);

  return 0;
}

static int cred_cmp_func(const void *_a, const void *_b) {
  CTAP_credentialDescriptor *a = (CTAP_credentialDescriptor *)_a;
  CTAP_credentialDescriptor *b = (CTAP_credentialDescriptor *)_b;
  return a->credential.creation_time - b->credential.creation_time;
}

// @return the number of valid credentials
// sorts the credentials.  Most recent creds will be first, invalid ones last.
int ctap_filter_invalid_credentials(CTAP_getAssertion *GA) {
  unsigned int i;
  int count = 0;

  if (GA->credLen) {
    for (i = 0; i < (unsigned int)GA->credLen; i++) {
      if (!ctap_authenticate_credential(&GA->rp, &GA->creds[i])) {
        ctap_printf("CRED is invalid\n");
        // invalidate the credential, sort it to the end
        GA->creds[i].credential.creation_time = 0;

      } else {
        count++;
      }
    }
    GA->credLen = count;
  } else {
    uint8_t rp_id_hash[32];
    sha256_Raw((uint8_t *)GA->rp.id, GA->rp.size, rp_id_hash);
    count = resident_credential_find_by_rp_id_hash(rp_id_hash, GA->creds,
                                                   ALLOW_LIST_MAX_SIZE);
    ctap_printf("find %d resident credentials\n", count);
    GA->credLen = count;
  }
  ctap_printf("qsort length: %d\n", GA->credLen);
  qsort(GA->creds, GA->credLen, sizeof(CTAP_credentialDescriptor),
        cred_cmp_func);
  return count;
}
static int8_t save_credential_list(uint8_t *clientDataHash,
                                   CTAP_credentialDescriptor *creds,
                                   uint32_t count,
                                   CTAP_extensions *extensions) {
  if (count) {
    if (count > ALLOW_LIST_MAX_SIZE - 1) {
      ctap_printf("ALLOW_LIST_MAX_SIZE Exceeded\n");
      return CTAP2_ERR_TOO_MANY_ELEMENTS;
    }

    memmove(getAssertionState.clientDataHash, clientDataHash,
            CLIENT_DATA_HASH_SIZE);
    memmove(getAssertionState.creds, creds,
            sizeof(CTAP_credentialDescriptor) * (count));
    memmove(&getAssertionState.extensions, extensions, sizeof(CTAP_extensions));
  }
  getAssertionState.count = count;
  getAssertionState.index = 0;
  ctap_printf("saved %d credentials\n", count);
  return 0;
}

// static CTAP_credentialDescriptor *pop_credential() {
//   if (getAssertionState.count > 0 &&
//       getAssertionState.index < getAssertionState.count) {
//     return &getAssertionState.creds[getAssertionState.index++];
//   } else {
//     return NULL;
//   }
// }

int ctap_calculate_assertion_signature(uint8_t *data, int datalen,
                                       uint8_t *clientDataHash, uint8_t *sigbuf,
                                       uint8_t *sigder, int32_t alg) {
  // calculate attestation sig
  if (alg == COSE_ALG_EDDSA) {
    // crypto_ed25519_sign(data, datalen, clientDataHash,
    // CLIENT_DATA_HASH_SIZE,
    //                     sigder);  // not DER, just plain binary!
    return 0;
  } else {
    SHA256_CTX ctx = {0};
    uint8_t hash[32];

    sha256_Init(&ctx);
    sha256_Update(&ctx, data, datalen);
    sha256_Update(&ctx, clientDataHash, CLIENT_DATA_HASH_SIZE);
    sha256_Final(&ctx, hash);

    if (!se_fido_hdnode_sign_digest(hash, sigbuf)) {
      return 0;
    }
    return ctap_encode_der_sig(sigbuf, sigder);
  }
  return 0;
}

// adds 2 to map, or 3 if add_user is true
uint8_t ctap_end_get_assertion(bool is_resident_credential, bool user_present,
                               CborEncoder *map,
                               CTAP_credentialDescriptor *cred,
                               uint8_t *auth_data_buf,
                               unsigned int auth_data_buf_sz,
                               uint8_t *clientDataHash) {
  int ret;
  uint8_t sigbuf[64];
  uint8_t sigder[72];
  int sigder_sz;

  ret = cbor_encode_int(map, RESP_credential);
  check_ret(ret);

  ret = ctap_add_credential_descriptor(map, cred->cred_id,
                                       cred->cred_id_len);  // 1
  check_retr(ret);

  ret = cbor_encode_int(map, RESP_authData);  // 2
  check_ret(ret);
  ret = cbor_encode_byte_string(map, auth_data_buf, auth_data_buf_sz);
  check_ret(ret);

  if (ctap_derive_credential_pubkey(cred->type, cred->cred_id,
                                    cred->cred_id_len,
                                    NULL) != CTAP1_ERR_SUCCESS) {
    return CTAP1_ERR_OTHER;
  }
  sigder_sz = ctap_calculate_assertion_signature(
      auth_data_buf, auth_data_buf_sz, clientDataHash, sigbuf, sigder,
      COSE_ALG_ES256);

  ctap_printf("sigder_sz = %d\n", sigder_sz);

  ret = cbor_encode_int(map, RESP_signature);  // 3
  check_ret(ret);
  ret = cbor_encode_byte_string(map, sigder, sigder_sz);
  check_ret(ret);

  if (is_resident_credential && cred->credential.user.id_size && user_present) {
    ctap_printf("adding user details to output\r\n");

    ret = cbor_encode_int(map, RESP_publicKeyCredentialUserEntity);
    check_ret(ret);

    ret = ctap_add_user_entity(map, &cred->credential.user);  // 4
    check_retr(ret);
  }

  return 0;
}
#if 0
uint8_t ctap_get_next_assertion(CborEncoder *encoder) {
  int ret;
  CborEncoder map;

  CTAP_credentialDescriptor *cred = pop_credential();

  if (cred == NULL) {
    return CTAP2_ERR_NOT_ALLOWED;
  }

  auth_data_update_count(&getAssertionState.buf.authData);
  memmove(getAssertionState.buf.authData.rpIdHash, cred->credential.id.rpIdHash,
          32);

  if (cred->credential.user.id_size) {
    ctap_printf("adding user info to assertion response\r\n");
    ret = cbor_encoder_create_map(encoder, &map, 4);
  } else {
    ctap_printf("NOT adding user info to assertion response\r\n");
    ret = cbor_encoder_create_map(encoder, &map, 3);
  }

  check_ret(ret);

  // if only one account for this RP, null out the user details
  if (!getAssertionState.user_verified) {
    ctap_printf("Not verified, nulling out user details on response\r\n");
    memset(cred->credential.user.name, 0, USER_NAME_LIMIT);
  }

  unsigned int ext_encoder_buf_size = sizeof(getAssertionState.buf.extensions);
  ret = ctap_make_extensions(&getAssertionState.extensions,
                             getAssertionState.buf.extensions,
                             &ext_encoder_buf_size);

  if (ret == 0) {
    if (ext_encoder_buf_size) {
      getAssertionState.buf.authData.flags |= (1 << 7);
    } else {
      getAssertionState.buf.authData.flags &= ~(1 << 7);
    }
  }

  ret = ctap_end_get_assertion(
      &map, cred, (uint8_t *)&getAssertionState.buf.authData,
      sizeof(CTAP_authDataHeader) + ext_encoder_buf_size,
      getAssertionState.clientDataHash);

  check_retr(ret);

  ret = cbor_encoder_close_container(encoder, &map);
  check_ret(ret);

  return 0;
}

uint8_t ctap_cred_metadata(CborEncoder *encoder) {
  CborEncoder map;
  int ret = cbor_encoder_create_map(encoder, &map, 2);
  check_ret(ret);
  ret = cbor_encode_int(&map, 1);
  check_ret(ret);
  ret = cbor_encode_int(&map, STATE.rk_stored);
  check_ret(ret);
  ret = cbor_encode_int(&map, 2);
  check_ret(ret);
  int remaining_rks = ctap_rk_size() - STATE.rk_stored;
  ret = cbor_encode_int(&map, remaining_rks);
  check_ret(ret);
  ret = cbor_encoder_close_container(encoder, &map);
  check_ret(ret);
  return 0;
}

uint8_t ctap_cred_rp(CborEncoder *encoder, int rk_ind, int rp_count) {
  CTAP_residentKey rk;
  ctap_load_rk(rk_ind, &rk);

  CborEncoder map;
  size_t map_size = rp_count > 0 ? 3 : 2;
  int ret = cbor_encoder_create_map(encoder, &map, map_size);
  check_ret(ret);
  ret = cbor_encode_int(&map, 3);
  check_ret(ret);
  {
    CborEncoder rp;
    ret = cbor_encoder_create_map(&map, &rp, 2);
    check_ret(ret);
    ret = cbor_encode_text_stringz(&rp, "id");
    check_ret(ret);
    if (rk.rpIdSize <= sizeof(rk.rpId)) {
      ret = cbor_encode_text_string(&rp, (const char *)rk.rpId, rk.rpIdSize);
    } else {
      ret = cbor_encode_text_string(&rp, "", 0);
    }
    check_ret(ret);
    ret = cbor_encode_text_stringz(&rp, "name");
    check_ret(ret);
    ret = cbor_encode_text_stringz(&rp, (const char *)rk.user.name);
    check_ret(ret);
    ret = cbor_encoder_close_container(&map, &rp);
    check_ret(ret);
  }
  ret = cbor_encode_int(&map, 4);
  check_ret(ret);
  cbor_encode_byte_string(&map, rk.id.rpIdHash, 32);
  check_ret(ret);
  if (rp_count > 0) {
    ret = cbor_encode_int(&map, 5);
    check_ret(ret);
    ret = cbor_encode_int(&map, rp_count);
    check_ret(ret);
  }
  ret = cbor_encoder_close_container(encoder, &map);
  check_ret(ret);
  return 0;
}

uint8_t ctap_cred_rk(CborEncoder *encoder, int rk_ind, int rk_count) {
  CTAP_residentKey rk;
  ctap_load_rk(rk_ind, &rk);

  uint32_t cred_protect = read_metadata_from_masked_credential(&rk.id);
  if (cred_protect == 0 || cred_protect > 3) {
    // Take default value of userVerificationOptional
    cred_protect = EXT_CRED_PROTECT_OPTIONAL;
  }

  int32_t cose_alg = read_cose_alg_from_masked_credential(&rk.id);

  CborEncoder map;
  size_t map_size = rk_count > 0 ? 5 : 4;
  int ret = cbor_encoder_create_map(encoder, &map, map_size);
  check_ret(ret);

  ret = cbor_encode_int(&map, 6);
  check_ret(ret);
  {
    ret = ctap_add_user_entity(&map, &rk.user, 1);
    check_ret(ret);
  }

  ret = cbor_encode_int(&map, 7);
  check_ret(ret);
  {
    ret = ctap_add_credential_descriptor(&map, (struct Credential *)&rk,
                                         PUB_KEY_CRED_PUB_KEY);
    check_ret(ret);
  }

  ret = cbor_encode_int(&map, 8);
  check_ret(ret);
  {
    ctap_generate_cose_key(&map, (uint8_t *)&rk.id, sizeof(CredentialId),
                           PUB_KEY_CRED_PUB_KEY, cose_alg);
  }

  if (rk_count > 0) {
    ret = cbor_encode_int(&map, 9);
    check_ret(ret);
    ret = cbor_encode_int(&map, rk_count);
    check_ret(ret);
  }

  ret = cbor_encode_int(&map, 0x0A);
  check_ret(ret);
  ret = cbor_encode_int(&map, cred_protect);
  check_ret(ret);

  ret = cbor_encoder_close_container(encoder, &map);
  check_ret(ret);
  return 0;
}

uint8_t ctap_cred_mgmt_pinauth(CTAP_credMgmt *CM) {
  if (CM->cmd != CM_cmdMetadata && CM->cmd != CM_cmdRPBegin &&
      CM->cmd != CM_cmdRKBegin && CM->cmd != CM_cmdRKDelete) {
    // pinAuth is not required for other commands
    return 0;
  }

  int8_t ret = verify_pin_auth_ex(CM->pinAuth, (uint8_t *)&CM->hashed,
                                  CM->subCommandParamsCborSize + 1);

  if (ret == CTAP2_ERR_PIN_AUTH_INVALID) {
    ctap_decrement_pin_attempts();
    if (ctap_device_boot_locked()) {
      return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }
    return CTAP2_ERR_PIN_AUTH_INVALID;
  } else {
    ctap_reset_pin_attempts();
  }

  return ret;
}

static int credentialId_to_rk_index(CredentialId *credId) {
  unsigned int i;
  CTAP_residentKey rk;

  for (i = 0; i < ctap_rk_size(); i++) {
    ctap_load_rk(i, &rk);
    if (ctap_rk_is_valid(&rk)) {
      if (memcmp(&rk.id, credId, sizeof(CredentialId)) == 0) {
        return i;
      }
    }
  }

  return -1;
}

// Load the next valid resident key of a different rpIdHash
static int scan_for_next_rp(int index) {
  CTAP_residentKey rk;
  uint8_t nextRpIdHash[32];

  if (index == -1) {
    ctap_load_rk(0, &rk);
    if (ctap_rk_is_valid(&rk)) {
      return 0;
    } else {
      index = 0;
    }
  }

  int occurs_previously;
  do {
    occurs_previously = 0;

    index++;
    if ((unsigned int)index >= ctap_rk_size()) {
      return -1;
    }

    ctap_load_rk(index, &rk);
    memmove(nextRpIdHash, rk.id.rpIdHash, 32);

    if (!ctap_rk_is_valid(&rk)) {
      occurs_previously = 1;
      continue;
    } else {
    }

    // Check if we have scanned the rpIdHash before.
    int i;
    for (i = 0; i < index; i++) {
      ctap_load_rk(i, &rk);
      if (memcmp(rk.id.rpIdHash, nextRpIdHash, 32) == 0) {
        occurs_previously = 1;
        break;
      }
    }

  } while (occurs_previously);

  return index;
}

// Load the next valid resident key of the same rpIdHash
static int scan_for_next_rk(int index, uint8_t *initialRpIdHash) {
  CTAP_residentKey rk;
  uint8_t lastRpIdHash[32];

  if (initialRpIdHash != NULL) {
    memmove(lastRpIdHash, initialRpIdHash, 32);
    index = -1;
  } else {
    ctap_load_rk(index, &rk);
    memmove(lastRpIdHash, rk.id.rpIdHash, 32);
  }

  do {
    index++;
    if ((unsigned int)index >= ctap_rk_size()) {
      return -1;
    }
    ctap_load_rk(index, &rk);
  } while (memcmp(rk.id.rpIdHash, lastRpIdHash, 32) != 0);

  return index;
}

uint8_t ctap_cred_mgmt(CborEncoder *encoder, uint8_t *request, int length) {
  CTAP_credMgmt CM;
  int i = 0;

  // RP / RK pointers
  static int curr_rp_ind = 0;
  static int curr_rk_ind = 0;

  // flags that authenticate whether *Begin was before *Next
  static bool rp_auth = false;
  static bool rk_auth = false;

  int rp_count = 0;
  int rk_count = 0;

  int ret = ctap_parse_cred_mgmt(&CM, request, length);
  if (ret != 0) {
    ctap_printf("error, ctap_parse_cred_mgmt failed\n");
    return ret;
  }
  ret = ctap_cred_mgmt_pinauth(&CM);
  check_retr(ret);
  if (STATE.rk_stored == 0 && CM.cmd != CM_cmdMetadata) {
    ctap_printf("No resident keys\n");
    return 0;
  }
  if (CM.cmd == CM_cmdRPBegin) {
    curr_rk_ind = -1;
    rp_auth = true;
    rk_auth = false;
    curr_rp_ind = scan_for_next_rp(-1);

    // Count total unique RP's
    while (curr_rp_ind >= 0) {
      curr_rp_ind = scan_for_next_rp(curr_rp_ind);
      rp_count++;
    }

    // Reset scan
    curr_rp_ind = scan_for_next_rp(-1);

    printf1(TAG_MC, "RP Begin @%d.  %d total.\n", curr_rp_ind, rp_count);
  } else if (CM.cmd == CM_cmdRKBegin) {
    curr_rk_ind = scan_for_next_rk(0, CM.subCommandParams.rpIdHash);
    rk_auth = true;

    // Count total RK's associated to RP
    while (curr_rk_ind >= 0) {
      curr_rk_ind = scan_for_next_rk(curr_rk_ind, NULL);
      rk_count++;
    }

    // Reset scan
    curr_rk_ind = scan_for_next_rk(0, CM.subCommandParams.rpIdHash);
    printf1(TAG_MC, "Cred Begin @%d.  %d total.\n", curr_rk_ind, rk_count);
  } else if (CM.cmd != CM_cmdRKNext && CM.cmd != CM_cmdRPNext) {
    rk_auth = false;
    rp_auth = false;
    curr_rk_ind = -1;
    curr_rp_ind = -1;
  }

  switch (CM.cmd) {
    case CM_cmdMetadata:
      printf1(TAG_CM, "CM_cmdMetadata\n");
      ret = ctap_cred_metadata(encoder);
      check_ret(ret);
      break;
    case CM_cmdRPBegin:
    case CM_cmdRPNext:
      printf1(TAG_CM, "Get RP %d\n", curr_rp_ind);
      if (curr_rp_ind < 0 || !rp_auth) {
        rp_auth = false;
        rk_auth = false;
        return CTAP2_ERR_NO_CREDENTIALS;
      }

      ret = ctap_cred_rp(encoder, curr_rp_ind, rp_count);
      check_ret(ret);
      curr_rp_ind = scan_for_next_rp(curr_rp_ind);

      break;
    case CM_cmdRKBegin:
    case CM_cmdRKNext:
      printf1(TAG_CM, "Get Cred %d\n", curr_rk_ind);
      if (curr_rk_ind < 0 || !rk_auth) {
        rp_auth = false;
        rk_auth = false;
        return CTAP2_ERR_NO_CREDENTIALS;
      }

      ret = ctap_cred_rk(encoder, curr_rk_ind, rk_count);
      check_ret(ret);

      curr_rk_ind = scan_for_next_rk(curr_rk_ind, NULL);

      break;
    case CM_cmdRKDelete:
      printf1(TAG_CM, "CM_cmdRKDelete\n");
      i = credentialId_to_rk_index(
          &CM.subCommandParams.credentialDescriptor.credential.id);
      if (i >= 0) {
        ctap_delete_rk(i);
        ctap_decrement_rk_store();
        printf1(TAG_CM, "Deleted rk %d\n", i);
      } else {
        printf1(TAG_CM, "No Rk by given credId\n");
        return CTAP2_ERR_NO_CREDENTIALS;
      }
      break;
    default:
      ctap_printf("error, invalid credMgmt cmd: 0x%02x\n", CM.cmd);
      return CTAP1_ERR_INVALID_COMMAND;
  }
  return 0;
}
#endif

static int ctap_get_assertion_auth_header(
    CTAP_getAssertion *ga, uint32_t counter,
    CTAP_authDataHeader *auth_data_header) {
  sha256_Raw((uint8_t *)ga->rp.id, ga->rp.size, auth_data_header->rpIdHash);

  if (ga->up) {
    auth_data_header->flags |= AUTH_DATA_FLAG_UP;
  }

  if (ga->uv) {
    auth_data_header->flags |= AUTH_DATA_FLAG_UV;
  }

  // Convert counter to big-endian
  auth_data_header->signCount =
      ((counter & 0xFF) << 24) | ((counter & 0xFF00) << 8) |
      ((counter & 0xFF0000) >> 8) | ((counter & 0xFF000000) >> 24);

  return 0;
}
uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *request, int length) {
  CTAP_getAssertion GA;
  bool is_resident_credential = false;

  int ret = ctap_parse_get_assertion(&GA, request, length);

  if (ret != 0) {
    ctap_printf("error, parse_get_assertion failed\n");
    return ret;
  }

  if (GA.pinAuthPresent) {
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  if (GA.pinAuthEmpty) {
  }

  if (!GA.rp.size || !GA.clientDataHashPresent) {
    return CTAP2_ERR_MISSING_PARAMETER;
  }
  CborEncoder map;

  int map_size = 3;

  ctap_printf("ALLOW_LIST has %d creds\n", GA.credLen);
  if (GA.credLen == 0) {
    is_resident_credential = true;
  }
  int validCredCount = ctap_filter_invalid_credentials(&GA);

  if (validCredCount == 0) {
    ctap_printf("Error, no authentic credential\n");
    return CTAP2_ERR_NO_CREDENTIALS;
  } else if (validCredCount > 1) {
    map_size += 1;
  }

  if (is_resident_credential && GA.up) {
    map_size += 1;
  }

  ctap_printf("USER ID SIZE: %d\r\n", GA.creds[0].credential.user.id_size);

  if (GA.extensions.hmac_secret_present == EXT_HMAC_SECRET_PARSED) {
    ctap_printf("hmac-secret is present\r\n");
  }

  ret = cbor_encoder_create_map(encoder, &map, map_size);
  check_ret(ret);

  ctap_printf("resulting order of creds:\n");
  int j;
  for (j = 0; j < GA.credLen; j++) {
    ctap_printf("CRED ID (# %d)\n", GA.creds[j].credential.creation_time);
  }

  CTAP_credentialDescriptor *cred = &GA.creds[0];

  if (GA.up || GA.uv) {
    const char *appname = NULL;
    uint8_t rp_id_hash[32];
    if (cred->type == PUB_KEY_CRED_CTAP1) {
      sha256_Raw((uint8_t *)GA.rp.id, GA.rp.size, rp_id_hash);
      getReadableAppId(rp_id_hash, &appname);
      layoutDialogAdapterEx(_(T__U2F_AUTHENTICATE), NULL, NULL,
                            &bmp_bottom_right_arrow, NULL, NULL,
                            _(I__APP_NAME_COLON), appname, NULL, NULL);
    } else {
      char *account_name = get_account_name(&cred->credential.user);
      layoutDialogCenterAdapterV2(
          "FIDO2 Get Assertion", NULL, NULL, &bmp_bottom_right_confirm, NULL,
          NULL, cred->credential.rp.id, account_name, NULL, NULL, NULL);
    }
    uint32_t start_time = svc_timer_ms();
    while (1) {
      usbPoll();
      buttonUpdate();

      if (button.YesUp) {
        getAssertionState.user_verified = true;
        break;
      } else if (button.NoUp) {
        return CTAP2_ERR_OPERATION_DENIED;
      }
      // 60 seconds timeout
      if (svc_timer_ms() - start_time > timer1s * 60) {
        return CTAP2_ERR_OPERATION_DENIED;
      }
    }
  }

  uint32_t auth_data_buf_sz = sizeof(CTAP_authDataHeader);

  uint32_t counter = config_nextU2FCounter();
  ret = ctap_get_assertion_auth_header(&GA, counter,
                                       &getAssertionState.buf.authData);
  check_retr(ret);

  unsigned int ext_encoder_buf_size = sizeof(getAssertionState.buf.extensions);

  ret = ctap_make_extensions(&GA.extensions, cred->cred_id, cred->cred_id_len,
                             getAssertionState.buf.extensions,
                             &ext_encoder_buf_size);
  check_retr(ret);
  if (ext_encoder_buf_size) {
    getAssertionState.buf.authData.flags |= AUTH_DATA_FLAG_ED;
    auth_data_buf_sz += ext_encoder_buf_size;
  }

  ret = ctap_end_get_assertion(is_resident_credential, GA.up, &map, cred,
                               (uint8_t *)&getAssertionState.buf,
                               auth_data_buf_sz, GA.clientDataHash);
  check_retr(ret);

  if (validCredCount > 1) {
    ret = cbor_encode_int(&map, RESP_numberOfCredentials);  // 5
    check_ret(ret);
    ret = cbor_encode_int(&map, validCredCount);
    check_ret(ret);
  }

  ret = cbor_encoder_close_container(encoder, &map);
  check_ret(ret);

  ret = save_credential_list(GA.clientDataHash,
                             GA.creds + 1 /* skip first credential*/,
                             validCredCount - 1, &GA.extensions);
  check_retr(ret);

  return 0;
}

// Return how many trailing zeros in a buffer
static int trailing_zeros(uint8_t *buf, int indx) {
  int c = 0;
  while (0 == buf[indx] && indx) {
    indx--;
    c++;
  }
  return c;
}

uint8_t ctap_update_pin_if_verified(uint8_t *pinEnc, int len,
                                    uint8_t *platform_pubkey, uint8_t *pinAuth,
                                    uint8_t *pinHashEnc) {
  uint8_t hmac[32];
  int ret;

  //    Validate incoming data packet len
  if (len < 64) {
    return CTAP1_ERR_OTHER;
  }

  uint8_t pubkey[65], shared_secret[65];

  pubkey[0] = 0x04;
  memcpy(pubkey + 1, platform_pubkey, 64);

  //    calculate shared_secret
  ecdh_multiply(&nist256p1, KEY_AGREEMENT_PRIV, pubkey, shared_secret);
  sha256_Raw(shared_secret + 1, 32, shared_secret);

  HMAC_SHA256_CTX ctx256;

  hmac_sha256_Init(&ctx256, shared_secret, 32);
  hmac_sha256_Update(&ctx256, pinEnc, len);
  if (pinHashEnc != NULL) {
    hmac_sha256_Update(&ctx256, pinHashEnc, 16);
  }
  hmac_sha256_Final(&ctx256, hmac);

  if (memcmp(hmac, pinAuth, 16) != 0) {
    ctap_printf("pinAuth failed for update pin\n");
    dump_hex1(TAG_ERR, hmac, 16);
    dump_hex1(TAG_ERR, pinAuth, 16);
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  //     decrypt new PIN with shared secret
  aes_decrypt_ctx dec_ctx = {0};
  uint8_t iv[16];
  memset(iv, 0, sizeof(iv));
  aes_decrypt_key256(shared_secret, &dec_ctx);

  while ((len & 0xf) != 0)  // round up to nearest  AES block size multiple
  {
    len++;
  }

  aes_cbc_decrypt(pinEnc, pinEnc, len, iv, &dec_ctx);

  //      validate new PIN (length)

  ret = trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
  ret = NEW_PIN_ENC_MIN_SIZE - ret;

  if (ret < NEW_PIN_MIN_SIZE || ret >= NEW_PIN_MAX_SIZE) {
    ctap_printf("new PIN is too short or too long [%d bytes]\n", ret);
    return CTAP2_ERR_PIN_POLICY_VIOLATION;
  } else {
    ctap_printf("new pin: %s [%d bytes]\n", pinEnc, ret);
    dump_hex1(TAG_CP, pinEnc, ret);
  }

  return 0;
}

uint8_t ctap_add_pin_if_verified(uint8_t *pinTokenEnc, uint8_t *platform_pubkey,
                                 uint8_t *pinHashEnc) {
  uint8_t pubkey[65], shared_secret[65];

  pubkey[0] = 0x04;
  memcpy(pubkey + 1, platform_pubkey, 64);

  ecdh_multiply(&nist256p1, KEY_AGREEMENT_PRIV, pubkey, shared_secret);
  sha256_Raw(shared_secret + 1, 32, shared_secret);

  aes_decrypt_ctx dec_ctx = {0};
  uint8_t iv[16];
  memset(iv, 0, sizeof(iv));

  aes_decrypt_key256(shared_secret, &dec_ctx);
  aes_cbc_decrypt(pinHashEnc, pinHashEnc, 16, iv, &dec_ctx);

  ctap_printf("pinHashEnc: ");
  dump_hex1(TAG_ERR, pinHashEnc, 16);

  random_buffer(PIN_TOKEN, PIN_TOKEN_SIZE);
  memmove(pinTokenEnc, PIN_TOKEN, PIN_TOKEN_SIZE);
  aes_encrypt_ctx enc_ctx = {0};
  memset(iv, 0, sizeof(iv));
  aes_encrypt_key256(shared_secret, &enc_ctx);
  aes_cbc_encrypt(pinTokenEnc, pinTokenEnc, PIN_TOKEN_SIZE, iv, &enc_ctx);

  return 0;
}

uint8_t ctap_client_pin(CborEncoder *encoder, uint8_t *request, int length) {
  CTAP_clientPin CP;
  CborEncoder map;
  uint8_t pinTokenEnc[PIN_TOKEN_SIZE];
  int ret = ctap_parse_client_pin(&CP, request, length);

  if (ret != 0) {
    ctap_printf("error, parse_client_pin failed\n");
    return ret;
  }

  ctap_printf("CP.subCommand = %d\n", CP.subCommand);

  if (CP.subCommand != CP_cmdGetKeyAgreement) {
    return CTAP2_ERR_UNSUPPORTED_OPTION;
  }

  if (CP.pinProtocol != 1) {
    return CTAP1_ERR_OTHER;
  }
  int num_map = 0;
  switch (CP.subCommand) {
    case CP_cmdSetPin:
      if (!CP.newPinEncSize || !CP.pinAuthPresent || !CP.keyAgreementPresent) {
        return CTAP2_ERR_MISSING_PARAMETER;
      }
      ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize,
                                        (uint8_t *)&CP.keyAgreement.pubkey,
                                        CP.pinAuth, NULL);
      check_retr(ret);
      break;
    case CP_cmdGetPinToken:
      num_map++;
      ret = cbor_encoder_create_map(encoder, &map, num_map);
      check_ret(ret);

      ctap_printf("CP_cmdGetPinToken\n");
      if (CP.keyAgreementPresent == 0 || CP.pinHashEncPresent == 0) {
        ctap_printf(
            "Error, missing keyAgreement or pinHashEnc for cmdGetPin\n");
        return CTAP2_ERR_MISSING_PARAMETER;
      }
      ret = cbor_encode_int(&map, RESP_pinToken);
      check_ret(ret);
      ret = ctap_add_pin_if_verified(
          pinTokenEnc, (uint8_t *)&CP.keyAgreement.pubkey, CP.pinHashEnc);
      check_retr(ret);

      ret = cbor_encode_byte_string(&map, pinTokenEnc, PIN_TOKEN_SIZE);
      check_ret(ret);

      break;
    case CP_cmdGetKeyAgreement:
      ctap_printf("CP_cmdGetKeyAgreement\n");
      num_map++;

      ctap_reset_key_agreement();
      ret = cbor_encoder_create_map(encoder, &map, num_map);
      check_ret(ret);

      ret = cbor_encode_int(&map, RESP_keyAgreement);
      check_ret(ret);

      ret =
          ctap_add_cose_key(&map, KEY_AGREEMENT_PUB + 1, KEY_AGREEMENT_PUB + 33,
                            PUB_KEY_CRED_PUB_KEY, COSE_ALG_ECDH_ES_HKDF_256);
      check_retr(ret);
      break;
    default:
      return CTAP1_ERR_INVALID_COMMAND;
  }

  if (num_map || CP.getRetries) {
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
  }

  return 0;
}
