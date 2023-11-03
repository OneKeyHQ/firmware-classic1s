/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <libopencm3/stm32/flash.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
// #include <cstdint>

#include "bip32.h"
#include "ble.h"
#include "buttons.h"
#include "cardano.h"
#include "common.h"
#include "config.h"

#include "bip39.h"
#include "firmware/algo/parser_txdef.h"
#include "font.h"
#include "fsm.h"
#include "gettext.h"
#include "hmac.h"
#include "layout2.h"
#include "memory.h"
#include "memzero.h"
#include "mi2c.h"
#include "protect.h"
#include "rng.h"
#include "se_chip.h"
#include "secbool.h"
#include "usb.h"
#include "util.h"

#ifndef offsetof
#define offsetof(type, member) ((uint32_t) & ((type *)0)->member)
#endif

typedef enum {
  LANG_EN_US,
  LANG_ZH_CN,
} LANG_TYPE;

typedef struct {
  STORAGE_UINT32(version);
  STORAGE_BYTES(uuid, UUID_SIZE)
  STORAGE_BOOL(passphrase_protection)
  STORAGE_STRING(language, MAX_LANGUAGE_LEN + 1)
  STORAGE_STRING(label, MAX_LABEL_LEN + 1)
  STORAGE_BYTES(homescreen, HOMESCREEN_SIZE)
  STORAGE_UINT32(auto_lock_delay_ms)
  STORAGE_UINT32(sleep_delay_ms)
  STORAGE_UINT32(coin_function_switch)
  STORAGE_BOOL(trezor_comp_mode)
  STORAGE_BOOL(usb_lock)
  STORAGE_BOOL(input_direction)
} PubConfig __attribute__((aligned(1)));

typedef struct {
  STORAGE_BOOL(imported)
  STORAGE_UINT32(flags)
  STORAGE_BOOL(unfinished_backup)
  STORAGE_BOOL(no_backup)
} PriConfig __attribute__((aligned(1)));

#define KEY_VERSION offsetof(PubConfig, version)
#define KEY_UUID offsetof(PubConfig, uuid)
#define KEY_PASSPHRASE_PROTECTION offsetof(PubConfig, passphrase_protection)
#define KEY_LANGUAGE offsetof(PubConfig, language)
#define KEY_LABEL offsetof(PubConfig, label)
#define KEY_HOMESCREEN offsetof(PubConfig, homescreen)
#define KEY_AUTO_LOCK_DELAY_MS offsetof(PubConfig, auto_lock_delay_ms)
#define KEY_SLEEP_DELAY_MS offsetof(PubConfig, sleep_delay_ms)
#define KEY_COIN_FUNCTION_SWITCH offsetof(PubConfig, coin_function_switch)
#define KEY_TREZOR_COMP_MODE offsetof(PubConfig, trezor_comp_mode)
#define KEY_USB_LOCK offsetof(PubConfig, usb_lock)
#define KEY_INPUT_DIRECTION offsetof(PubConfig, input_direction)

#define PRIVATE_KEY 1 << 31

#if EMULATOR
#define KEY_IMPORTED (uint32_t)(offsetof(PriConfig, imported) | PRIVATE_KEY)
#define KEY_FLAGS (uint32_t)(offsetof(PriConfig, flags) | PRIVATE_KEY)
#define KEY_UNFINISHED_BACKUP \
  (uint32_t)(offsetof(PriConfig, unfinished_backup) | PRIVATE_KEY)
#define KEY_NO_BACKUP (uint32_t)(offsetof(PriConfig, no_backup) | PRIVATE_KEY)
#else
#define KEY_IMPORTED offsetof(PriConfig, imported) | PRIVATE_KEY
#define KEY_FLAGS offsetof(PriConfig, flags) | PRIVATE_KEY
#define KEY_UNFINISHED_BACKUP \
  offsetof(PriConfig, unfinished_backup) | PRIVATE_KEY
#define KEY_NO_BACKUP offsetof(PriConfig, no_backup) | PRIVATE_KEY
#endif

static uint32_t config_uuid[UUID_SIZE / sizeof(uint32_t)];
_Static_assert(sizeof(config_uuid) == UUID_SIZE, "config_uuid has wrong size");

static char config_language[MAX_LANGUAGE_LEN];
_Static_assert(sizeof(config_language) == MAX_LANGUAGE_LEN,
               "config_language has wrong size");

char config_uuid_str[2 * UUID_SIZE + 1] = {0};
static uint8_t g_ucHomeScreen[HOMESCREEN_SIZE];
volatile secbool g_bHomeGetFlg = secfalse;

/* Current u2f offset, i.e. u2f counter is
 * storage.u2f_counter + config_u2f_offset.
 * This corresponds to the number of cleared bits in the U2FAREA.
 */

#if !EMULATOR
#define autoLockDelayMsDefault (5 * 60 * 1000U)  // 5 minutes
#else
#define autoLockDelayMsDefault (10 * 60 * 1000U)  // 10 minutes
#endif
#define sleepDelayMsDefault (5 * 60 * 1000U)  // 5 minutes

static secbool autoLockDelayMsCached = secfalse;
static secbool sleepDelayMsCached = secfalse;
static uint32_t autoLockDelayMs = autoLockDelayMsDefault;
static uint32_t autoSleepDelayMs = sleepDelayMsDefault;

#if DEBUG_LINK
static SafetyCheckLevel safetyCheckLevel = SafetyCheckLevel_Strict;
#else
static SafetyCheckLevel safetyCheckLevel = SafetyCheckLevel_PromptAlways;
#endif

static const uint32_t CONFIG_VERSION = 11;

static const uint8_t FALSE_BYTE = '\x00';
static const uint8_t TRUE_BYTE = '\x01';

static bool derive_cardano = 0;

static secbool usb_lock = secfalse;

#define CHECK_CONFIG_OP(cond)     \
  do {                            \
    if (!(cond)) return secfalse; \
  } while (0)

static secbool config_get(const uint32_t id, void *v, uint16_t l) {
  bool pri = id & (1 << 31);
  secbool (*reader)(uint16_t, void *, uint16_t) =
      pri ? se_get_private_region : se_get_public_region;

  uint8_t has;
  // read has_xxx flag
  CHECK_CONFIG_OP(reader(id, &has, 1));
  if (has != TRUE_BYTE) return secfalse;
  CHECK_CONFIG_OP(reader(id + 1, v, l));
  return sectrue;
}

static secbool config_set(const uint32_t id, const void *v, uint16_t l) {
  bool pri = id & (1 << 31);
  secbool (*writer)(uint16_t, const void *, uint16_t) =
      pri ? se_set_private_region : se_set_public_region;

  CHECK_CONFIG_OP(writer(id + 1, v, l));
  // set has_xxx flag
  CHECK_CONFIG_OP(writer(id, &TRUE_BYTE, 1));
  return sectrue;
}

static secbool config_get_bool(const uint32_t id, bool *value) {
  uint8_t v;
  *value = false;
  CHECK_CONFIG_OP(config_get(id, &v, sizeof(bool)));
  *value = v == TRUE_BYTE;
  return sectrue;
}

static secbool config_set_bool(const uint32_t id, bool value) {
  return config_set(id, value ? &TRUE_BYTE : &FALSE_BYTE, 1);
}

static secbool config_get_bytes(const uint32_t id, uint8_t *dest,
                                uint16_t *real_size) {
  bool pri = id & (1 << 31);
  secbool (*reader)(uint16_t, void *, uint16_t) =
      pri ? se_get_private_region : se_get_public_region;
  uint8_t has;
  // read has_xxx flag
  CHECK_CONFIG_OP(reader(id, &has, 1));
  if (has != TRUE_BYTE) return secfalse;
  uint32_t size = 0;
  // size|bytes
  CHECK_CONFIG_OP(reader(id + 1, &size, sizeof(size)));
  CHECK_CONFIG_OP(reader(id + 1 + sizeof(uint32_t), dest, size));
  if (real_size) *real_size = size;
  return sectrue;
}

static secbool config_set_bytes(const uint32_t id, const uint8_t *bytes,
                                uint16_t len) {
  // if (len > id) return secfalse;

  bool pri = id & (1 << 31);
  secbool (*writer)(uint16_t, const void *, uint16_t) =
      pri ? se_set_private_region : se_set_public_region;
  // set has_xxx flag
  CHECK_CONFIG_OP(writer(id, &TRUE_BYTE, 1));
  uint32_t size = len;
  // size|bytes
  CHECK_CONFIG_OP(writer(id + 1, &size, sizeof(size)));
  CHECK_CONFIG_OP(writer(id + 1 + sizeof(uint32_t), bytes, len));
  return sectrue;
}

static secbool config_delete_key(const uint32_t id) {
  bool pri = id & (1 << 31);
  secbool (*writer)(uint16_t, const void *, uint16_t) =
      pri ? se_set_private_region : se_set_public_region;
  // clear has_xxx flag
  CHECK_CONFIG_OP(writer(id, &FALSE_BYTE, 1));
  return sectrue;
}

static secbool config_get_string(const uint32_t id, char *dest,
                                 uint16_t *real_size) {
  return config_get(id, dest, *real_size);
}

static secbool config_get_uint32(const uint32_t id, uint32_t *value) {
  *value = 0;
  CHECK_CONFIG_OP(config_get(id, value, sizeof(uint32_t)));
  return sectrue;
}
static secbool config_set_uint32(const uint32_t id, uint32_t value) {
  return config_set(id, &value, sizeof(value));
}

void config_init(void) {
  char oldTiny = usbTiny(1);

#if !EMULATOR
  ensure(se_sync_session_key(), "se sync session key failed");
#endif

  se_set_ui_callback(&layoutProgressAdapter);

  memzero(HW_ENTROPY_DATA, sizeof(HW_ENTROPY_DATA));
  config_getHomescreen(g_ucHomeScreen, HOMESCREEN_SIZE);
  config_getLanguage(config_language, sizeof(config_language));

  // If UUID is not set, then the config is uninitialized.
  if (sectrue != config_get_bytes(KEY_UUID, (uint8_t *)config_uuid, NULL)) {
    random_buffer((uint8_t *)config_uuid, sizeof(config_uuid));
    config_set_bytes(KEY_UUID, (uint8_t *)config_uuid, sizeof(config_uuid));
    config_set_uint32(KEY_VERSION, CONFIG_VERSION);
  }
  data2hex((const uint8_t *)config_uuid, sizeof(config_uuid), config_uuid_str);

  usbTiny(oldTiny);
}

void config_lockDevice(void) { se_clearSecsta(); }

void config_setLabel(const char *label) {
  if (label == NULL || label[0] == '\0') {
    config_delete_key(KEY_LABEL);
  } else {
    config_set(KEY_LABEL, label,
               strnlen(label, MAX_LABEL_LEN) + 1);  // append '\0'
  }
}

void config_setLanguage(const char *lang) {
  if (lang == NULL) {
    return;
  }
  for (uint8_t i = 0; i < langs_len; i++) {
    if (strcmp(lang, i18n_lang_keys[i]) == 0) {
      ui_language = i;
      config_set(KEY_LANGUAGE, lang,
                 strnlen(lang, MAX_LANGUAGE_LEN) + 1);  // append '\0'
      font_set(ui_language ? "dingmao_9x9" : "english");
      break;
    }
  }
}

void config_setPassphraseProtection(bool passphrase_protection) {
  config_set_bool(KEY_PASSPHRASE_PROTECTION, passphrase_protection);
}

bool config_getPassphraseProtection(bool *passphrase_protection) {
  return config_get_bool(KEY_PASSPHRASE_PROTECTION, passphrase_protection);
}

void config_setHomescreen(const uint8_t *data, uint32_t size) {
  g_bHomeGetFlg = secfalse;

  if (data != NULL && size == HOMESCREEN_SIZE) {
    config_set_bytes(KEY_HOMESCREEN, data, size);
  } else {
    config_delete_key(KEY_HOMESCREEN);
  }
}

// mode : SE_WRFLG_GENSEED or SE_WRFLG_GENMINISECRET;
// bool config_genSessionSeed(uint8_t mode) {
bool config_genSessionSeed(void) {
  char passphrase[MAX_PASSPHRASE_LEN + 1] = {0};
  uint8_t status = 0;
  if (!se_get_session_seed_state(&status)) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Session state error");
    return false;
  }

  if (derive_cardano) {
    if (status & 0x40) return true;
  } else {
    if (status & 0x80) return true;
  }

  if (!protectPassphrase(passphrase)) {
    memzero(passphrase, sizeof(passphrase));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Passphrase dismissed");
    return false;
  }
  // TODO. if passphrase is null it would special choose
  if (passphrase[0] == 0) {
  } else {  // passphrase is used - confirm on the display
    layoutDialogCenterAdapterV2(
        _(T__ACCESS_HIDDEN_WALLET), NULL, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__NEXT_SCREEN_WILL_SHOW_THE_ENTERED_PASSPHRASE));
    if (!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
      memzero(passphrase, sizeof(passphrase));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Passphrase dismissed");
      layoutHome();
      return false;
    }
    layoutShowPassphrase(passphrase);
    if (!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
      memzero(passphrase, sizeof(passphrase));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Passphrase dismissed");
      layoutHome();
      return false;
    }
  }

  char oldTiny = usbTiny(1);

  if (!(status & 0x80)) {
    if (!se_gen_session_seed(passphrase, false)) return false;
  }
  if (derive_cardano && !(status & 0x40)) {
    if (!se_gen_session_seed(passphrase, true)) return false;
  }

  memzero(passphrase, sizeof(passphrase));
  usbTiny(oldTiny);
  return true;
}

bool config_getLabel(char *dest, uint16_t dest_size) {
  if (secfalse == config_get_string(KEY_LABEL, dest, &dest_size)) {
    memcpy(dest, "OneKey Classic", 15 /*strlen("OneKey Classic") + 1*/);
  } else {
    int len = strlen(dest);
    if (0 == len) {
      memcpy(dest, "OneKey Classic", 15);
    }
  }
  return true;
}

bool config_getLanguage(char *dest, uint16_t dest_size) {
  if (sectrue == config_get_string(KEY_LANGUAGE, dest, &dest_size)) {
    for (uint8_t i = 0; i < langs_len; i++) {
      if (strcmp(dest, i18n_lang_keys[i]) == 0) {
        ui_language = i;
        break;
      }
    }
  } else {
    ui_language = 0;
    strcpy(dest, i18n_lang_keys[0]);
  }
  font_set(ui_language ? "dingmao_9x9" : "english");

  return true;
}

bool config_getHomescreen(uint8_t *dest, uint16_t dest_size) {
  if (secfalse == g_bHomeGetFlg) {
    memzero(g_ucHomeScreen, sizeof(g_ucHomeScreen));
    uint16_t realSize = 0xff;
    if (!config_get_bytes(KEY_HOMESCREEN, g_ucHomeScreen, &realSize)) {
      return false;
    }
  }
  if (dest_size != HOMESCREEN_SIZE) return false;
  memcpy(dest, g_ucHomeScreen, HOMESCREEN_SIZE);
  g_bHomeGetFlg = sectrue;
  return true;
}

bool config_setMnemonic(const char *mnemonic, bool import) {
  if (mnemonic == NULL) {
    return false;
  }
  (void)import;
  if (!se_set_mnemonic((void *)mnemonic, strnlen(mnemonic, MAX_MNEMONIC_LEN))) {
    return false;
  }
#if DEBUG_LINK
  config_setDebugMnemonicBytes(mnemonic);
#endif
  return true;
}

bool config_getMnemonic(char *dest, uint16_t dest_size) {
  return sectrue == se_exportMnemonic(dest, dest_size);
}

bool config_setPin(const char *pin) { return sectrue == se_setPin(pin); }

/* Unlock device/verify PIN.  The pin must be
 * a null-terminated string with at most 9 characters.
 */
bool config_verifyPin(const char *pin) { return sectrue == se_verifyPin(pin); }

bool config_hasPin(void) { return sectrue == se_hasPin(); }

bool config_changePin(const char *old_pin, const char *new_pin) {
  bool ret;
  if (config_hasPin()) {
    ret = se_changePin(old_pin, new_pin);
  } else {
    ret = config_setPin(new_pin);
  }
#if DEBUG_LINK
  if (ret) {
    if (new_pin[0] != '\0') {
      config_setDebugPin(new_pin);
    } else {
      config_setDebugPin(NULL);
    }
  }
#endif
  return ret;
}

uint8_t *session_startSession(const uint8_t *received_session_id) {
  static uint8_t act_session_id[32];

  if (received_session_id == NULL) {
    // se create session
    bool ret = se_sessionStart(act_session_id);
    if (ret) {  // se open session
      if (!se_sessionOpen(act_session_id)) {
        // session open failed
        memzero(act_session_id, sizeof(act_session_id));
      }
    } else {
      memzero(act_session_id, sizeof(act_session_id));
    }
  } else {
    // se open session
    bool ret = se_sessionOpen((uint8_t *)received_session_id);
    if (ret) {
      memcpy(act_session_id, received_session_id, sizeof(act_session_id));
    } else {  // session open failed
      memzero(act_session_id, sizeof(act_session_id));
    }
  }

  return act_session_id;
}

void session_endCurrentSession(void) {
  // se close session
  se_sessionClose();
}

bool session_isUnlocked(void) {
  return sectrue == se_getSecsta() ? true : false;
}

void session_clear(bool lock) {
  se_sessionClear();

  if (lock) {
    config_lockDevice();
  }
}

bool config_isInitialized(void) { return se_isInitialized(); }

bool config_getImported(bool *imported) {
  return config_get_bool(KEY_IMPORTED, imported);
}

void config_setImported(bool imported) {
  config_set_bool(KEY_IMPORTED, imported);
}

bool config_containsMnemonic(const char *mnemonic) {
  return se_containsMnemonic(mnemonic);
}

bool config_getNeedsBackup(bool *needs_backup) {
  return sectrue == se_get_needs_backup(needs_backup);
}

void config_setNeedsBackup(bool needs_backup) {
  se_set_needs_backup(needs_backup);
}

bool config_getUnfinishedBackup(bool *unfinished_backup) {
  return sectrue == config_get_bool(KEY_UNFINISHED_BACKUP, unfinished_backup);
}

void config_setUnfinishedBackup(bool unfinished_backup) {
  config_set_bool(KEY_UNFINISHED_BACKUP, unfinished_backup);
}

bool config_getNoBackup(bool *no_backup) {
  return sectrue == config_get_bool(KEY_NO_BACKUP, no_backup);
}

void config_setNoBackup(void) { config_set_bool(KEY_NO_BACKUP, true); }

void config_applyFlags(uint32_t flags) {
  uint32_t old_flags = 0;
  config_get_uint32(KEY_FLAGS, &old_flags);
  flags |= old_flags;
  if (flags == old_flags) {
    return;  // no new flags
  }
  config_set_uint32(KEY_FLAGS, flags);
}

bool config_getFlags(uint32_t *flags) {
  return sectrue == config_get_uint32(KEY_FLAGS, flags);
}

uint32_t config_nextU2FCounter(void) {
  uint32_t u2fcounter = 0;
  se_get_u2f_counter(&u2fcounter);
  return u2fcounter;
}

void config_setU2FCounter(uint32_t u2fcounter) {
  se_set_u2f_counter(u2fcounter);
}

uint32_t config_getAutoLockDelayMs(void) {
  if (sectrue == autoLockDelayMsCached) {
    return autoLockDelayMs;
  }
  // #if EMULATOR
  //   if (sectrue != storage_is_unlocked()) {
  //     return autoLockDelayMsDefault;
  //   }
  // #endif
  if (sectrue != config_get_uint32(KEY_AUTO_LOCK_DELAY_MS, &autoLockDelayMs)) {
    autoLockDelayMs = autoLockDelayMsDefault;
  }
  if (autoLockDelayMs) {
    autoLockDelayMs = MAX(autoLockDelayMs, MIN_AUTOLOCK_DELAY_MS);
  }
  autoLockDelayMsCached = sectrue;
  return autoLockDelayMs;
}

void config_setAutoLockDelayMs(uint32_t auto_lock_delay_ms) {
  if (auto_lock_delay_ms != 0)
    auto_lock_delay_ms = MAX(auto_lock_delay_ms, MIN_AUTOLOCK_DELAY_MS);
  if (sectrue ==
      config_set_uint32(KEY_AUTO_LOCK_DELAY_MS, auto_lock_delay_ms)) {
    autoLockDelayMs = auto_lock_delay_ms;
    autoLockDelayMsCached = sectrue;
  }
}

SafetyCheckLevel config_getSafetyCheckLevel(void) { return safetyCheckLevel; }

void config_setSafetyCheckLevel(SafetyCheckLevel safety_check_level) {
  safetyCheckLevel = safety_check_level;
}

uint32_t config_getSleepDelayMs(void) {
  if (sectrue == sleepDelayMsCached) {
    return autoSleepDelayMs;
  }

  if (sectrue != config_get_uint32(KEY_SLEEP_DELAY_MS, &autoSleepDelayMs)) {
    autoSleepDelayMs = sleepDelayMsDefault;
  }
  sleepDelayMsCached = sectrue;
  return autoSleepDelayMs;
}

void config_setSleepDelayMs(uint32_t auto_sleep_ms) {
  if (auto_sleep_ms != 0)
    auto_sleep_ms = MAX(auto_sleep_ms, MIN_AUTOLOCK_DELAY_MS);

  if (sectrue == config_set_uint32(KEY_SLEEP_DELAY_MS, auto_sleep_ms)) {
    autoSleepDelayMs = auto_sleep_ms;
    sleepDelayMsCached = sectrue;
  }
}

void config_wipe(void) {
  se_reset_storage();
  char oldTiny = usbTiny(1);
  usbTiny(oldTiny);
  random_buffer((uint8_t *)config_uuid, sizeof(config_uuid));
  data2hex((const uint8_t *)config_uuid, sizeof(config_uuid), config_uuid_str);
  autoLockDelayMsCached = secfalse;
#if DEBUG_LINK
  safetyCheckLevel = SafetyCheckLevel_Strict;
#else
  safetyCheckLevel = SafetyCheckLevel_PromptAlways;
#endif
  config_set_bytes(KEY_UUID, (uint8_t *)config_uuid, sizeof(config_uuid));
  config_set_uint32(KEY_VERSION, CONFIG_VERSION);
  session_clear(false);
  fsm_abortWorkflows();
  fsm_clearCosiNonce();
  config_getLanguage(config_language, sizeof(config_language));

  change_ble_sta(BLE_ADV_ON);
}

void config_setBleTrans(bool mode) {
  ble_set_switch(mode);
  change_ble_sta(mode);
}

void config_setWhetherUseSE(bool flag) {
  (void)flag;
  return;
}

bool config_getWhetherUseSE(void) { return true; }

ExportType config_setSeedsExportFlag(ExportType flag) { return flag; }

bool config_getMessageSE(BixinMessageSE_inputmessage_t *input_msg,
                         BixinOutMessageSE_outmessage_t *get_msg) {
  if (false == bMI2CDRV_SendData(input_msg->bytes, input_msg->size)) {
    return false;
  }
  get_msg->size = 1024;
  if (false == bMI2CDRV_ReceiveData(get_msg->bytes, &get_msg->size)) {
    return false;
  }
  get_msg->bytes[get_msg->size] = '\0';
  return true;
}

void config_setIsBixinAPP(void) { g_bIsBixinAPP = true; }

uint32_t config_getPinFails(void) { return se_pinFailedCounter(); }

bool config_getCoinSwitch(CoinSwitch loc) {
  uint32_t coin_switch = 0;
  if (sectrue == config_get_uint32(KEY_COIN_FUNCTION_SWITCH, &coin_switch)) {
    if (coin_switch & loc) {
      return true;
    }
  }
  return false;
}

void config_setCoinSwitch(CoinSwitch loc, bool flag) {
  uint32_t coin_switch = 0;
  config_get_uint32(KEY_COIN_FUNCTION_SWITCH, &coin_switch);
  if (flag) {
    coin_switch |= loc;
  } else {
    coin_switch &= ~loc;
  }
  config_set_uint32(KEY_COIN_FUNCTION_SWITCH, coin_switch);
}

bool config_hasTrezorCompMode(void) {
  bool mode = false;
  return sectrue == config_get_bool(KEY_TREZOR_COMP_MODE, &mode);
}

void config_setTrezorCompMode(bool trezor_comp_mode) {
  config_set_bool(KEY_TREZOR_COMP_MODE, trezor_comp_mode);
}

bool config_getTrezorCompMode(bool *trezor_comp_mode) {
  return sectrue == config_get_bool(KEY_TREZOR_COMP_MODE, trezor_comp_mode);
}

static AuthorizeCoinJoin auth = {0};
const AuthorizeCoinJoin *config_getCoinJoinAuthorization(void) {
  uint8_t resp[128] = {0};
  uint32_t len = 128;
  bool rv = se_authorization_get_data(resp, &len);
  if (rv && len == sizeof(AuthorizeCoinJoin)) {
    memcpy(&auth, resp, sizeof(AuthorizeCoinJoin));
    return &auth;
  }
  return NULL;
}
bool config_setCoinJoinAuthorization(const AuthorizeCoinJoin *authorization) {
  if (authorization == NULL) {
    se_authorization_clear();
    return true;
  } else {
    return se_authorization_set(MessageType_MessageType_AuthorizeCoinJoin,
                                (const uint8_t *)authorization,
                                sizeof(AuthorizeCoinJoin));
  }
}

MessageType config_getAuthorizationType(void) {
  uint32_t type = 0;
  se_authorization_get_type(&type);
  return type;
}

bool config_hasWipeCode(void) { return se_hasWipeCode(); }

bool config_changeWipeCode(const char *pin, const char *wipe_code) {
  char oldTiny = usbTiny(1);
  bool ret = se_changeWipeCode(pin, wipe_code);
  usbTiny(oldTiny);
  return ret;
}

bool config_unlock(const char *pin) {
  bool ret = config_verifyPin(pin);
  if (!ret) {
    // check wipe code
    if (0x6f80 == se_lasterror()) {
      error_shutdown("You have entered the", "wipe code. All private",
                     "data has been erased.", NULL);
    }
  }
  return ret;
}

bool config_getDeriveCardano(void) {
  uint8_t status = 0;
  if (se_get_session_seed_state(&status)) {
    return status & 0x40;
  }
  return false;
}

void config_setDeriveCardano(bool on) { derive_cardano = on; }

bool config_hasUsblock(void) {
  bool mode = false;
  return sectrue == config_get_bool(KEY_USB_LOCK, &mode);
}

void config_setUsblock(bool lock) {
  config_set_bool(KEY_USB_LOCK, lock);
  usb_lock = lock;
}

bool config_getUsblock(bool *lock, bool mode) {
  if (!mode) {
    *lock = usb_lock;
    return true;
  }
  return sectrue == config_get_bool(KEY_USB_LOCK, lock);
}

void config_setInputDirection(bool d) {
  config_set_bool(KEY_INPUT_DIRECTION, d);
}

bool config_getInputDirection(bool *d) {
  return sectrue == config_get_bool(KEY_INPUT_DIRECTION, d);
}

#if DEBUG_LINK

void config_loadDevice(const LoadDevice *msg) {
  session_clear(false);
  config_set_bool(offsetof(PriConfig, imported), true);
  config_setPassphraseProtection(msg->has_passphrase_protection &&
                                 msg->passphrase_protection);

  if (msg->has_pin) {
    config_changePin("", msg->pin);
  }

  if (msg->mnemonics_count) {
    config_setMnemonic(msg->mnemonics[0], true);
  }

  if (msg->has_language) {
    config_setLanguage(msg->language);
  }

  config_setLabel(msg->has_label ? msg->label : "");

  if (msg->has_u2f_counter) {
    config_setU2FCounter(msg->u2f_counter);
  }

  if (msg->has_needs_backup) {
    config_setNeedsBackup(msg->needs_backup);
  }

  if (msg->has_no_backup && msg->no_backup) {
    config_setNoBackup();
  }
}

static char debug_link_pin[51] = {0};
bool config_setDebugPin(const char *pin) {
  if (pin != NULL) {
    strcpy(debug_link_pin, pin);
  } else {
    memzero(debug_link_pin, sizeof(debug_link_pin));
  }

  return true;
}
bool config_getPin(char *dest, uint16_t dest_size) {
  (void)dest_size;
  if (strlen(debug_link_pin) == 0) {
    return false;
  }
  strcpy(dest, debug_link_pin);
  return true;
}
static char debug_link_mnemonic[241] = {0};
bool config_setDebugMnemonicBytes(const char *mnemonic) {
  strcpy(debug_link_mnemonic, mnemonic);
  return true;
}

bool config_getMnemonicBytes(uint8_t *dest, uint16_t *real_size) {
  if (strlen(debug_link_mnemonic) == 0) {
    return false;
  }
  strcpy((char *)dest, debug_link_mnemonic);
  *real_size = strlen(debug_link_mnemonic);
  return true;
}

#endif