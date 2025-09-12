/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2018 Pavol Rusnak <stick@satoshilabs.com>
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
#include <stdbool.h>
#include "base58.h"
#include "firmware/config.h"
#include "flash.h"
#include "hasher.h"
#include "menu_list.h"
#include "mi2c.h"
#include "protect.h"
#include "se_chip.h"
#include "storage.h"

extern char bootloader_version[8];

static bool g_client_contains_attach = false;

bool get_features(Features *resp) {
  char *se_version = NULL;
  char *se_build_id = NULL;
  char *se_hash = NULL;
  char *serial = NULL;
  resp->has_fw_vendor = true;
  resp->has_vendor = true;
#if EMULATOR
  strlcpy(resp->fw_vendor, "EMULATOR", sizeof(resp->fw_vendor));
  strlcpy(resp->vendor, "onekey.so", sizeof(resp->vendor));
#else
  const image_header *hdr =
      (const image_header *)FLASH_PTR(FLASH_FWHEADER_START);
  // No signature verification needed, unofficial firmware cannot be started
  strlcpy(resp->fw_vendor, "OneKey", sizeof(resp->fw_vendor));
  bool trezor_comp_mode = false;
  config_getTrezorCompMode(&trezor_comp_mode);
  if (trezor_comp_mode) {
    strlcpy(resp->vendor, "trezor.io", sizeof(resp->vendor));
  } else {
    strlcpy(resp->vendor, "onekey.so", sizeof(resp->vendor));
  }
#endif
  resp->major_version = VERSION_MAJOR;
  resp->minor_version = VERSION_MINOR;
  resp->patch_version = VERSION_PATCH;
  resp->has_device_id = true;
  strlcpy(resp->device_id, config_uuid_str, sizeof(resp->device_id));
  resp->has_pin_protection = true;
  resp->pin_protection = config_hasPin();
  resp->has_passphrase_protection = true;
  config_getPassphraseProtection(&(resp->passphrase_protection));

  uint8_t pin_space_check = 0;
  bool attach_user_status = false;
  if (se_get_pin_passphrase_space(&pin_space_check)) {
    attach_user_status = (pin_space_check < 30);
  } else {
  }

  resp->has_attach_to_pin_user = true;
  resp->attach_to_pin_user = attach_user_status;

  resp->has_unlocked_attach_pin = true;
  resp->unlocked_attach_pin = is_passphrase_pin_enabled;
#ifdef SCM_REVISION
  int len = sizeof(SCM_REVISION) - 1;
  resp->has_revision = true;
  memcpy(resp->revision.bytes, SCM_REVISION, len);
  resp->revision.size = len;
#endif
  resp->has_onekey_boot_hash = true;
  resp->onekey_boot_hash.size =
      memory_bootloader_hash(resp->onekey_boot_hash.bytes);

  resp->has_language =
      config_getLanguage(resp->language, sizeof(resp->language));
  resp->has_label = config_getLabel(resp->label, sizeof(resp->label));
  resp->has_initialized = true;
  resp->initialized = config_isInitialized();
  resp->has_imported = config_getImported(&(resp->imported));
  resp->has_unlocked = true;
  resp->unlocked = session_isUnlocked();
  resp->has_needs_backup = true;
  resp->needs_backup = false;
  resp->has_unfinished_backup = true;
  resp->unfinished_backup = false;
  resp->has_no_backup = true;
  resp->no_backup = false;
  resp->has_flags = config_getFlags(&(resp->flags));
  resp->has_model = true;
  strlcpy(resp->model, "1", sizeof(resp->model));
  resp->has_safety_checks = true;
  resp->safety_checks = config_getSafetyCheckLevel();
  resp->has_busy = true;
  resp->busy = (system_millis_busy_deadline > timer_ms());
  if (session_isUnlocked()) {
    resp->has_wipe_code_protection = true;
    resp->wipe_code_protection = config_hasWipeCode();
    resp->has_auto_lock_delay_ms = true;
    resp->auto_lock_delay_ms = config_getAutoLockDelayMs();
  }

#if BITCOIN_ONLY
  resp->capabilities_count = 3;
  resp->capabilities[0] = Capability_Capability_Bitcoin;
  resp->capabilities[1] = Capability_Capability_Crypto;
  resp->capabilities[2] = Capability_Capability_AttachToPin;
#else
  resp->capabilities_count = 9;
  resp->capabilities[0] = Capability_Capability_Bitcoin;
  resp->capabilities[1] = Capability_Capability_Bitcoin_like;
  resp->capabilities[2] = Capability_Capability_Crypto;
  resp->capabilities[3] = Capability_Capability_Ethereum;
  resp->capabilities[4] = Capability_Capability_NEM;
  resp->capabilities[5] = Capability_Capability_Stellar;
  resp->capabilities[6] = Capability_Capability_U2F;
  resp->capabilities[7] = Capability_Capability_AttachToPin;
  resp->capabilities[8] = Capability_Capability_EthereumTypedData;
#endif
  if (ble_name_state()) {
    char *ble_name = ble_get_name();
    if (ble_name) {
      resp->has_ble_name = true;
      strlcpy(resp->ble_name, ble_name, sizeof(resp->ble_name));
      resp->has_onekey_ble_name = true;
      strlcpy(resp->onekey_ble_name, ble_name, sizeof(resp->onekey_ble_name));
    }
  }
  if (ble_ver_state()) {
    char *ble_ver = ble_get_ver();
    if (ble_ver) {
      resp->has_ble_ver = true;
      strlcpy(resp->ble_ver, ble_ver, sizeof(resp->ble_ver));
      resp->has_onekey_ble_version = true;
      strlcpy(resp->onekey_ble_version, ble_ver,
              sizeof(resp->onekey_ble_version));
    }
  }
  if (ble_switch_state()) {
    resp->has_ble_enable = true;
    resp->ble_enable = ble_get_switch();
  }
  if (ble_build_id_state()) {
    resp->has_onekey_ble_build_id = true;
    strlcpy(resp->onekey_ble_build_id, ble_get_build_id(),
            sizeof(resp->onekey_ble_build_id));
  }
  if (ble_hash_state()) {
    resp->has_onekey_ble_hash = true;
    memcpy(resp->onekey_ble_hash.bytes, ble_get_hash(), 32);
    resp->onekey_ble_hash.size = 32;
  }

  resp->has_onekey_device_type = true;
  resp->onekey_device_type =
      ble_hw_ver_is_pure() ? OneKeyDeviceType_PURE : OneKeyDeviceType_CLASSIC1S;
  resp->has_onekey_se_type = true;
  resp->onekey_se_type = OneKeySeType_THD89;
  resp->has_se_enable = true;
  resp->se_enable = config_getWhetherUseSE();
  se_version = se_get_version();
  if (se_version) {
    resp->has_se_ver = true;
    memcpy(resp->se_ver, se_version, strlen(se_version));
    resp->has_onekey_se_version = true;
    memcpy(resp->onekey_se_version, se_version, strlen(se_version));
  }
  se_build_id = se_get_build_id();
  if (se_build_id) {
    resp->has_onekey_se_build_id = true;
    memcpy(resp->onekey_se_build_id, se_build_id, strlen(se_build_id));
  }
  se_hash = se_get_hash();
  if (se_hash) {
    resp->has_onekey_se_hash = true;
    memcpy(resp->onekey_se_hash.bytes, se_hash, 32);
    resp->onekey_se_hash.size = 32;
  }

  resp->has_onekey_version = true;
  strlcpy(resp->onekey_version, ONEKEY_VERSION, sizeof(resp->onekey_version));
  resp->has_onekey_firmware_version = true;
  strlcpy(resp->onekey_firmware_version, ONEKEY_VERSION,
          sizeof(resp->onekey_firmware_version));
  if (se_get_sn(&serial)) {
    if ((uint8_t)serial[0] == 0xff && (uint8_t)serial[1] == 0xff) {
      resp->has_onekey_serial = false;
      resp->has_onekey_serial_no = false;
    } else {
      resp->has_onekey_serial = true;
      resp->has_onekey_serial_no = true;
      strlcpy(resp->onekey_serial, serial, sizeof(resp->onekey_serial));
      strlcpy(resp->onekey_serial_no, serial, sizeof(resp->onekey_serial_no));
    }
  }
#ifdef BUILD_ID
#define BUILD_ID_LEN sizeof(BUILD_ID) - 1
  _Static_assert(BUILD_ID_LEN >= 7, "build_id_len is less than 7");
  _Static_assert(sizeof(resp->onekey_firmware_build_id) >= 7,
                 "buffer is too small");
  resp->has_onekey_firmware_build_id = true;
  const char *full_build_id = BUILD_ID;
  strlcpy(resp->onekey_firmware_build_id, full_build_id + (BUILD_ID_LEN - 7),
          7);
#endif
#if !EMULATOR
  resp->has_onekey_boot_version = true;
  strlcpy(resp->onekey_boot_version, bootloader_version,
          sizeof(resp->bootloader_version));
  resp->has_onekey_firmware_hash = true;
  memcpy(resp->onekey_firmware_hash.bytes, get_firmware_hash(hdr), 32);
  resp->onekey_firmware_hash.size = 32;
#endif

  resp->has_coin_switch = true;
  resp->coin_switch |=
      config_getCoinSwitch(COIN_SWITCH_ETH_EIP712) ? COIN_SWITCH_ETH_EIP712 : 0;
  resp->coin_switch |=
      config_getCoinSwitch(COIN_SWITCH_SOLANA) ? COIN_SWITCH_SOLANA : 0;

#if !EMULATOR
  if (battery_cap != 0xff) {
    resp->has_battery_level = true;
    resp->battery_level = battery_cap;
  }
#endif
  resp->has_product = true;
  strlcpy(resp->product, ble_hw_ver_is_pure() ? "pure" : "classic1s",
          sizeof(resp->product));

  resp->has_attach_to_pin_user = true;
  uint8_t space_available = 0;
  if (se_get_pin_passphrase_space(&space_available)) {
    resp->attach_to_pin_user = (space_available < 30);
  } else {
    resp->attach_to_pin_user = false;
  }

  if (session_isUnlocked() && is_passphrase_pin_enabled &&
      !g_client_contains_attach) {
    resp->passphrase_protection = false;
  }

  if (session_isUnlocked()) {
    resp->has_unlocked_attach_pin = true;
    resp->unlocked_attach_pin = is_passphrase_pin_enabled;
  }

  return resp;
}

void fsm_msgInitialize(const Initialize *msg) {
  fsm_abortWorkflows();
  uint8_t *session_id = NULL;
  static uint8_t g_cached_session_id[32] = {0};
  static bool g_session_cached = false;
  if (msg && msg->has_is_contains_attach) {
    g_client_contains_attach = msg->is_contains_attach;
  } else {
    g_client_contains_attach = false;
  }
  if (!se_session_is_open()) {
    g_session_cached = false;
    for (int i = 0; i < 32; i++) g_cached_session_id[i] = 0;
  }
  bool has_attach = false;
  if (msg && msg->has_is_contains_attach && msg->is_contains_attach) {
    has_attach = true;
  }

  bool ps_valid = false;
  if (msg && msg->has_passphrase_state && msg->passphrase_state[0]) {
    uint8_t addr_raw[MAX_ADDR_RAW_SIZE] = {0};
    int decode_len = base58_decode_check(msg->passphrase_state, HASHER_SHA2D,
                                         addr_raw, MAX_ADDR_RAW_SIZE);
    if (decode_len > 0 && decode_len <= MAX_ADDR_RAW_SIZE) {
      uint8_t prefix = addr_raw[0];
      if (prefix == 0x6F || prefix == 0xC4) {
        ps_valid = true;
      }
    }
  }

  const uint8_t *provided_sid =
      (msg && msg->has_session_id && msg->session_id.size == 32)
          ? msg->session_id.bytes
          : NULL;

  if (msg && msg->has_passphrase_state && msg->passphrase_state[0]) {
    if (!ps_valid) {
      ps_valid = (se_check_passphrase_btc_test_address(msg->passphrase_state) ==
                  sectrue);
    }
  }

  if (ps_valid) {
    if (session_isUnlocked() && !is_passphrase_pin_enabled) {
      session_id = provided_sid ? session_startSession(provided_sid)
                                : session_startSession(NULL);
    } else if (provided_sid && g_session_cached &&
               memcmp(provided_sid, g_cached_session_id, 32) == 0) {
      session_id = session_startSession(provided_sid);
    } else {
      session_id = session_startSession(NULL);
    }
  } else if (has_attach && provided_sid &&
             (!msg->has_passphrase_state || !msg->passphrase_state[0])) {
    session_id = session_startSession(NULL);
  } else if (session_isUnlocked() && is_passphrase_pin_enabled) {
    session_id = session_startSession(NULL);
  } else {
    if (provided_sid) {
      session_id = session_startSession(provided_sid);
    } else {
      session_id = session_startSession(NULL);
    }
  }

  if (msg && msg->has_derive_cardano && msg->derive_cardano) {
    uint8_t seed_state = 0;
    if (se_get_session_seed_state(&seed_state)) {
      bool btc_seed = (seed_state & 0x80) != 0;
      bool ada_seed = (seed_state & 0x40) != 0;
      if (btc_seed && !ada_seed) {
        session_endCurrentSession();
        session_id = session_startSession(NULL);
      }
    } else {
    }
    config_setDeriveCardano(true);
  } else {
    config_setDeriveCardano(false);
  }

  RESP_INIT(Features);
  get_features(resp);

  resp->has_session_id = true;
  memcpy(resp->session_id.bytes, session_id, sizeof(resp->session_id.bytes));
  resp->session_id.size = sizeof(resp->session_id.bytes);

  if (session_id) {
    memcpy(g_cached_session_id, session_id, 32);
    g_session_cached = true;
  }

  layoutHome();
  msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgGetFeatures(const GetFeatures *msg) {
  (void)msg;
  RESP_INIT(Features);
  get_features(resp);
  msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgPing(const Ping *msg) {
  RESP_INIT(Success);

  if (msg->has_button_protection && msg->button_protection) {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_question, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, __("Do you really want to"),
        __("answer to ping"), NULL, NULL, NULL);

    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (msg->has_message) {
    resp->has_message = true;
    memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
  }
  msg_write(MessageType_MessageType_Success, resp);
  layoutHome();
}

void fsm_msgChangePin(const ChangePin *msg) {
  // CHECK_INITIALIZED
  if (!config_isInitialized()) {
    fsm_sendFailure(FailureType_Failure_NotInitialized, NULL);
    return;
  }

  bool removal = msg->has_remove && msg->remove;
  bool button_confirm = true;
  if (removal) {
    if (config_hasPin()) {
      layoutDialogCenterAdapterV2(
          NULL, &bmp_icon_warning, &bmp_bottom_left_close,
          &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
          _(C__ARE_YOU_SURE_TO_DISABLE_PIN_PROTECTION_EXCLAM));
    } else {
      fsm_sendSuccess("PIN removed");
      return;
    }
  } else {
    if (config_hasPin()) {
      layoutDialogCenterAdapterV2(
          NULL, &bmp_icon_warning, &bmp_bottom_left_close,
          &bmp_bottom_right_confirm, NULL, NULL, __("Do you really want to"),
          __("change current PIN?"), NULL, NULL, NULL);
    } else {
      if (g_bIsBixinAPP) {
        button_confirm = false;
      } else {
        layoutDialogCenterAdapterV2(
            NULL, &bmp_icon_warning, &bmp_bottom_left_close,
            &bmp_bottom_right_confirm, NULL, NULL, __("Do you really want to"),
            __("set new PIN?"), NULL, NULL, NULL);
      }
    }
  }
  if (button_confirm &&
      !protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  if (protectChangePin(removal)) {
    i2c_set_wait(false);
    if (removal) {
      fsm_sendSuccess("PIN removed");
    } else {
      fsm_sendSuccess("PIN changed");
    }
  }

  layoutHome();
}

void fsm_msgChangeWipeCode(const ChangeWipeCode *msg) {
  CHECK_INITIALIZED
  if (g_bIsBixinAPP) {
    CHECK_PIN
  }

  bool removal = msg->has_remove && msg->remove;
  bool has_wipe_code = config_hasWipeCode();

  if (removal) {
    // Note that if storage is locked, then config_hasWipeCode() returns false.
    if (has_wipe_code || !session_isUnlocked()) {
      layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, NULL,
                        __("Do you really want to"), __("disable wipe code"),
                        __("protection?"), NULL, NULL);
    } else {
      fsm_sendSuccess("Wipe code removed");
      return;
    }
  } else {
    if (has_wipe_code) {
      layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"), NULL,
                        NULL, __("Do you really want to"),
                        __("change the current"), __("wipe code?"), NULL, NULL);
    } else {
      layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"), NULL,
                        NULL, __("Do you really want to"),
                        __("set a new wipe code?"), NULL, NULL, NULL);
    }
  }
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (protectChangeWipeCode(removal)) {
    if (removal) {
      fsm_sendSuccess("Wipe code removed");
    } else if (has_wipe_code) {
      fsm_sendSuccess("Wipe code changed");
    } else {
      fsm_sendSuccess("Wipe code set");
    }
  }

  layoutHome();
}

void fsm_msgWipeDevice(const WipeDevice *msg) {
  (void)msg;
#if DEBUG_LINK
  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"), NULL,
                    __("Do you really want to"), __("wipe the device?"), NULL,
                    __("All data will be lost."), NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_WipeDevice, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  config_wipe();
  // the following does not work on Mac anyway :-/ Linux/Windows are fine, so it
  // is not needed usbReconnect(); // force re-enumeration because of the serial
  // number change
  fsm_sendSuccess("Device wiped");
  layoutHome();
#else
  uint8_t key = KEY_NULL;

#if !DEBUG_LINK
  if (!layoutEraseDevice()) {
    i2c_set_wait(false);
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  if (!protectPinOnDevice(false, true)) {
    i2c_set_wait(false);
    fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
    layoutHome();
    return;
  }
#endif
  layoutDialogAdapterEx(
      _(T__ERASE_DEVICE), &bmp_bottom_left_delete, __("Back"),
      &bmp_bottom_right_confirm, __("Reset "),
      _(C__ARE_YOU_SURE_TO_RESET_THIS_DEVICE_THIS_ACTION_CANNOT_BE_UNDO), NULL,
      NULL, NULL, NULL);
  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    i2c_set_wait(false);
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  uint8_t ui_language_bak = ui_language;

  config_wipe();
  if (ui_language_bak) {
    ui_language = ui_language_bak;
  }
  layoutDialogAdapterEx(_(C__RESET_COMPLETE_EXCLAM), NULL, NULL,
                        &bmp_bottom_right_confirm, _(B__RESET),
                        _(C__DEVICE_RESET_COMPLETE_RESTART_NOW_EXCLAM), NULL,
                        NULL, NULL, NULL);
  protectWaitKey(0, 0);

  // the following does not work on Mac anyway :-/ Linux/Windows are fine, so it
  // is not needed usbReconnect(); // force re-enumeration because of the serial
  // number change
  i2c_set_wait(false);
  fsm_sendSuccess("Device wiped");
  layoutHome();
#if !EMULATOR && !DEBUG_LINK
  // svc_system_reset();
  reset_to_firmware();
#endif
#endif
}

void fsm_msgGetEntropy(const GetEntropy *msg) {
  CHECK_PIN

#if !DEBUG_RNG
  layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                              &bmp_bottom_right_confirm, NULL, NULL,
                              "Do you really want to", "send entropy?", NULL,
                              NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
#endif
  RESP_INIT(Entropy);
  int len = msg->size;
  if (len > 1024) {
    len = 1024;
  }
  resp->entropy.size = len;
#if EMULATOR
  random_buffer(resp->entropy.bytes, len);
#else
  if (!se_random_encrypted(resp->entropy.bytes, len)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to generate entropy");
    layoutHome();
    return;
  }
#endif
  msg_write(MessageType_MessageType_Entropy, resp);
  layoutHome();
}

#if DEBUG_LINK

void fsm_msgLoadDevice(const LoadDevice *msg) {
  CHECK_PIN

  CHECK_NOT_INITIALIZED

  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("I take the risk"),
                    NULL, __("Loading private seed"), __("is not recommended."),
                    __("Continue only if you"), __("know what you are"),
                    __("doing!"), NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->mnemonics_count && !(msg->has_skip_checksum && msg->skip_checksum)) {
    if (!mnemonic_check(msg->mnemonics[0])) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Mnemonic with wrong checksum provided");
      layoutHome();
      return;
    }
  }

  config_loadDevice(msg);
  fsm_sendSuccess("Device loaded");
  layoutHome();
}

#endif

void fsm_msgResetDevice(const ResetDevice *msg) {
  fsm_sendFailure(FailureType_Failure_DataError, "unsupport");
  return;
  // CHECK_PIN
  CHECK_NOT_INITIALIZED

  CHECK_PARAM(!msg->has_strength || msg->strength == 128 ||
                  msg->strength == 192 || msg->strength == 256,
              "Invalid seed strength");

  reset_init(msg->has_display_random && msg->display_random,
             msg->has_strength ? msg->strength : 128,
             msg->has_passphrase_protection && msg->passphrase_protection,
             msg->has_pin_protection && msg->pin_protection,
             msg->has_language ? msg->language : 0,
             msg->has_label ? msg->label : 0,
             msg->has_u2f_counter ? msg->u2f_counter : 0,
             msg->has_skip_backup ? msg->skip_backup : false,
             msg->has_no_backup ? msg->no_backup : false);
}

void fsm_msgEntropyAck(const EntropyAck *msg) {
  reset_entropy(msg->entropy.bytes, msg->entropy.size);
}

void fsm_msgBackupDevice(const BackupDevice *msg) {
  (void)msg;

  CHECK_INITIALIZED

  CHECK_PIN_UNCACHED

  bool needs_backup = false;
  config_getNeedsBackup(&needs_backup);
  if (!needs_backup) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Seed already backed up");
    return;
  }

  char mnemonic[MAX_MNEMONIC_LEN + 1];
  if (config_getMnemonic(mnemonic, sizeof(mnemonic))) {
    reset_backup(true, mnemonic);
  }
  memzero(mnemonic, sizeof(mnemonic));
}

void fsm_msgCancel(const Cancel *msg) {
  (void)msg;
  fsm_abortWorkflows();
  fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
}

void fsm_msgLockDevice(const LockDevice *msg) {
  (void)msg;
  // Clear all sessions and lock the device
  session_clear(true);
  menu_default();
  layoutHome();
  fsm_sendSuccess("Session cleared");
}

bool fsm_getLang(const ApplySettings *msg) {
  if (!strcmp(msg->language, "zh-CN") || !strcmp(msg->language, "chinese"))
    return true;
  else
    return false;
}

void fsm_msgEndSession(const EndSession *msg) {
  (void)msg;
  session_endCurrentSession();
  fsm_sendSuccess("Session ended");
}

#if 0
static int countlines(char *text) {
  int lines=0;
  while (*text) {
    if ((uint8_t)*text < 0x80) {
      if (*text == '\n') lines++;
      text++;
    } else {
      text += HZ_CODE_LEN;
    }
  }
  return lines+1;
}
#endif

void fsm_msgApplySettings(const ApplySettings *msg) {
  CHECK_PARAM(!msg->has_passphrase_always_on_device,
              "This firmware is incapable of passphrase entry on the device.");

  CHECK_PARAM(msg->has_label || msg->has_language || msg->has_use_passphrase ||
                  msg->has_homescreen || msg->has_auto_lock_delay_ms ||
                  msg->has_safety_checks || msg->has_use_ble ||
                  msg->has_is_bixinapp,
              "No setting provided");

  if (!msg->has_is_bixinapp) CHECK_PIN

  if (msg->has_is_bixinapp) {
    if (msg->has_label || msg->has_language || msg->has_use_passphrase ||
        msg->has_homescreen || msg->has_auto_lock_delay_ms ||
        msg->has_use_ble) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "you should set bixin_app flag only");
      layoutHome();
      return;
    }
  }

  if (msg->has_label) {
    char label[72] = {0};
    snprintf(label, 72, "%s", _(C__CHANGE_THE_LABEL_TO_QUOTE_STR));
    bracket_replace(label, msg->label);
    layoutDialogCenterAdapterV2(_(T__CHANGE_LABEL), NULL,
                                &bmp_bottom_left_close,
                                &bmp_bottom_right_confirm, NULL, NULL,
                                (const char *)label, NULL, NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if (msg->has_language) {
    layoutDialogCenterAdapterV2(
        _(M__LANGUAGE), NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm,
        NULL, NULL, __("Do you really want to"), __("change language to"),
        (fsm_getLang(msg) ? "中文" : "English"), "?", NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if (msg->has_use_passphrase) {
    if (msg->use_passphrase) {
      layoutDialogCenterAdapterV2(
          NULL, &bmp_icon_warning, &bmp_bottom_left_close,
          &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
          _(C__DO_YOU_WANT_TO_ENABLE_PASSPHRASE_ENCRYPTION));
    } else {
      // Disabling passphrase - check if attach to pin is being used
      uint8_t space_available = 0;
      bool attach_to_pin_used = false;
      if (se_get_pin_passphrase_space(&space_available)) {
        attach_to_pin_used = (space_available < 30);
      }

      if (attach_to_pin_used) {
        layoutDialogCenterAdapterV2(
            NULL, &bmp_icon_warning, &bmp_bottom_left_close,
            &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
            _(C__DISABLE_PASSPHRASE_HIDDEN_WALLET_PIN_WILL_NOT_UNLOCK_YOUR_DEVICE));
      } else {
        layoutDialogCenterAdapterV2(
            NULL, &bmp_icon_warning, &bmp_bottom_left_close,
            &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
            _(C__DO_YOU_WANT_TO_DISABLE_PASSPHRASE_ENCRYPTION));
      }
    }
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if (msg->has_homescreen) {
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_confirm, NULL, NULL, NULL,
                                NULL, NULL, NULL,
                                _(C__DO_YOU_WANT_TO_CHANGE_THE_HOMESCREEN));
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (msg->has_auto_lock_delay_ms) {
    if (msg->auto_lock_delay_ms < MIN_AUTOLOCK_DELAY_MS) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Auto-lock delay too short");
      layoutHome();
      return;
    }
    if (msg->auto_lock_delay_ms > MAX_AUTOLOCK_DELAY_MS) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Auto-lock delay too long");
      layoutHome();
      return;
    }
    layoutConfirmAutoLockDelay(msg->auto_lock_delay_ms);

    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if ((msg->has_fastpay_pin) || (msg->has_fastpay_confirm) ||
      (msg->has_fastpay_money_limit) || (msg->has_fastpay_times)) {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        __("Do you really want to \nchange fastpay settings?"));
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if (msg->has_use_ble) {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, __("Do you really want to"),
        __("change bluetooth"), __("status always?"), NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if ((msg->has_use_se) && (config_isInitialized())) {
    fsm_sendSuccess("Can't change se setting after device initialized");
    layoutHome();
    return;
  }
  if (msg->has_safety_checks) {
    if (msg->safety_checks == SafetyCheckLevel_Strict ||
        msg->safety_checks == SafetyCheckLevel_PromptTemporarily) {
      if (!layoutConfirmSafetyChecks(msg->safety_checks, true)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Unsupported safety-checks setting");
      layoutHome();
      return;
    }
  }

  if (msg->has_label) {
    config_setLabel(msg->label);
    i2c_set_wait(false);
  }
  if (msg->has_language) {
    config_setLanguage(msg->language);
  }
  if (msg->has_use_passphrase) {
    config_setPassphraseProtection(msg->use_passphrase);
    if (!msg->use_passphrase && is_passphrase_pin_enabled) {
      session_clear(true);
    }
  }
  if (msg->has_homescreen) {
    config_setHomescreen(msg->homescreen.bytes, msg->homescreen.size);
  }
  if (msg->has_auto_lock_delay_ms) {
    config_setSleepDelayMs(msg->auto_lock_delay_ms);
    menu_autolock_added_custom();
  }
  if (msg->has_use_ble) {
    config_setBleTrans(msg->use_ble);
  }
  if (msg->has_is_bixinapp) {
    config_setIsBixinAPP();
  }
  if (msg->has_safety_checks) {
    config_setSafetyCheckLevel(msg->safety_checks);
  }
  fsm_sendSuccess("Settings applied");
  layoutHome();
#if !EMULATOR
  if (msg->has_homescreen) {
    layoutStatusLogoEx(true);
  }
#endif
}

void fsm_msgApplyFlags(const ApplyFlags *msg) {
  CHECK_PIN

  config_applyFlags(msg->flags);
  fsm_sendSuccess("Flags applied");
}

void fsm_msgRecoveryDevice(const RecoveryDevice *msg) {
  fsm_sendFailure(FailureType_Failure_DataError, "unsupport");
  return;
  // CHECK_PIN_UNCACHED

  const bool dry_run = msg->has_dry_run ? msg->dry_run : false;
  if (!dry_run) {
    CHECK_NOT_INITIALIZED
  } else {
    CHECK_INITIALIZED
    CHECK_PARAM(!msg->has_passphrase_protection && !msg->has_pin_protection &&
                    !msg->has_language && !msg->has_label &&
                    !msg->has_u2f_counter,
                "Forbidden field set in dry-run")
  }

  CHECK_PARAM(!msg->has_word_count || msg->word_count == 12 ||
                  msg->word_count == 18 || msg->word_count == 24,
              "Invalid word count");

  recovery_init(msg->has_word_count ? msg->word_count : 12,
                msg->has_passphrase_protection && msg->passphrase_protection,
                msg->has_pin_protection && msg->pin_protection,
                msg->has_language ? msg->language : 0,
                msg->has_label ? msg->label : 0,
                msg->has_enforce_wordlist && msg->enforce_wordlist,
                msg->has_type ? msg->type : 0,
                msg->has_u2f_counter ? msg->u2f_counter : 0, dry_run);
}

void fsm_msgWordAck(const WordAck *msg) {
  CHECK_UNLOCKED

  recovery_word(msg->word);
}

void fsm_msgSetU2FCounter(const SetU2FCounter *msg) {
  CHECK_PIN

  layoutDialogCenterAdapterV2(NULL, &bmp_icon_question, &bmp_bottom_left_close,
                              &bmp_bottom_right_confirm, NULL, NULL,
                              __("Do you want to set"), __("the U2F counter?"),
                              NULL, NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  config_setU2FCounter(msg->u2f_counter);
  fsm_sendSuccess("U2F counter set");
  layoutHome();
}

void fsm_msgGetNextU2FCounter() {
  CHECK_PIN

  layoutDialogCenterAdapterV2(NULL, &bmp_icon_question, &bmp_bottom_left_close,
                              &bmp_bottom_right_confirm, NULL, NULL,
                              __("Do you want to"), __("increase and retrieve"),
                              __("the U2F counter?"), NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  uint32_t counter = config_nextU2FCounter();

  RESP_INIT(NextU2FCounter);
  resp->u2f_counter = counter;
  msg_write(MessageType_MessageType_NextU2FCounter, resp);
  layoutHome();
}

static void progress_callback(uint32_t iter, uint32_t total) {
  layoutProgressAdapter(_(C__PLEASE_WAIT), 1000 * iter / total);
}

void fsm_msgGetFirmwareHash(const GetFirmwareHash *msg) {
  RESP_INIT(FirmwareHash);
  layoutProgressSwipe(_(C__PLEASE_WAIT), 0);
  if (memory_firmware_hash(msg->challenge.bytes, msg->challenge.size,
                           progress_callback, resp->hash.bytes) != 0) {
    fsm_sendFailure(FailureType_Failure_FirmwareError, NULL);
    return;
  }

  resp->hash.size = sizeof(resp->hash.bytes);
  msg_write(MessageType_MessageType_FirmwareHash, resp);
  layoutHome();
}

void fsm_msgSetBusy(const SetBusy *msg) {
  if (msg->has_expiry_ms) {
    system_millis_busy_deadline = timer_ms() + msg->expiry_ms;
  } else {
    system_millis_busy_deadline = 0;
  }
  fsm_sendSuccess(NULL);
  layoutHome();
  return;
}

void fsm_msgBixinReboot(const BixinReboot *msg) {
  (void)msg;

#if !EMULATOR
  if (sys_usbState() == false && battery_cap < 2) {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, NULL, &bmp_bottom_right_confirm, NULL, NULL,
        NULL, NULL, NULL, NULL,
        _(C__LOW_BATTERY_EXCLAM_CHARGE_TO_25_PERCENTS_BEFORE_UPDATING_THE_BOOTLOADER));
    while (1) {
      uint8_t key = keyScan();
      if (key == KEY_CONFIRM) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
      if (sys_usbState() == true) {
        break;
      }
    }
  }
#endif

  layoutDialogCenterAdapterV2(
      NULL, &bmp_icon_warning, &bmp_bottom_left_close,
      &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__DO_YOU_WANT_TO_RESTART_DEVICE_IN_UPDATE_MODE));
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  CHECK_PIN_UNCACHED
  fsm_sendSuccess("reboot start");
  usbFlush(500);  // send response before reboot
#if !EMULATOR
  usbDisconnect();
  svc_reboot_to_bootloader();
#endif
}

void fsm_msgBixinMessageSE(const BixinMessageSE *msg) {
  RESP_INIT(BixinOutMessageSE);
  if (false == config_getMessageSE(
                   (BixinMessageSE_inputmessage_t *)(&msg->inputmessage),
                   (BixinOutMessageSE_outmessage_t *)(&resp->outmessage))) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage, NULL);
    layoutHome();
    return;
  }
  resp->has_outmessage = true;
  layoutHome();
  return;
}

void fsm_msgBixinVerifyDeviceRequest(const BixinVerifyDeviceRequest *msg) {
  if (config_hasPin()) {
    CHECK_PIN
  }
#if EMULATOR
  fsm_sendFailure(FailureType_Failure_UnexpectedMessage, NULL);
  layoutHome();
  return;
#else
  layoutDialogCenterAdapterV2(
      _(T__AUTHENTICITY_CHECK), NULL, &bmp_bottom_left_close,
      &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__CHECK_THIS_DEVICE_WITH_ONEKEY_SECURE_SERVER));
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  RESP_INIT(BixinVerifyDeviceAck);
  resp->cert.size = 512;
  resp->signature.size = 64;
  se_read_certificate(resp->cert.bytes,
                      &resp->cert.size);  // read certificate from SE

  if (!se_sign_message_feitian((uint8_t *)msg->data.bytes, msg->data.size,
                               resp->signature.bytes)) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage, NULL);
    layoutHome();
    return;
  }
  msg_write(MessageType_MessageType_BixinVerifyDeviceAck, resp);
  layoutHome();
#endif
  return;
}

void fsm_msgGetPassphraseState(const GetPassphraseState *msg) {
  (void)msg;

  RESP_INIT(PassphraseState);

  if (!config_isInitialized()) {
    fsm_sendFailure(FailureType_Failure_NotInitialized, NULL);
    return;
  }
  CHECK_PIN

  uint8_t *session_id = NULL;
  if (session_isUnlocked() && !se_session_is_open()) {
    session_id = session_startSession(NULL);
  }

  uint32_t address_n[5] = {PATH_HARDENED | 44, PATH_HARDENED | 1,
                           PATH_HARDENED | 0, 0, 0};
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, address_n, 5, NULL);

  if (!node && !session_isUnlocked()) {
    layoutHome();
    return;
  }
  if (!node) {
    strlcpy(resp->passphrase_state, "Error: Failed to derive key",
            sizeof(resp->passphrase_state));
  } else {
    if (hdnode_fill_public_key(node) != 0) {
      strlcpy(resp->passphrase_state, "Error: Failed to derive public key",
              sizeof(resp->passphrase_state));
    } else {
      const CoinInfo *coin = coinByName("Testnet");
      if (!coin) {
        strlcpy(resp->passphrase_state, "Error: Bitcoin Testnet not found",
                sizeof(resp->passphrase_state));
      } else {
        char address[MAX_ADDR_SIZE];
        if (!compute_address(coin, InputScriptType_SPENDADDRESS, node, false,
                             NULL, address)) {
          strlcpy(resp->passphrase_state, "Error: Failed to compute address",
                  sizeof(resp->passphrase_state));
        } else {
          strlcpy(resp->passphrase_state, address,
                  sizeof(resp->passphrase_state));
        }
      }
    }
  }

  if (session_id) {
    resp->has_session_id = true;
    memcpy(resp->session_id.bytes, session_id, 32);
    resp->session_id.size = 32;
  }

  uint8_t space_check = 0;
  (void)space_check;
  (void)se_get_pin_passphrase_space;
  resp->has_unlocked_attach_pin = true;
  resp->unlocked_attach_pin = is_passphrase_pin_enabled;

  msg_write(MessageType_MessageType_PassphraseState, resp);
  layoutHome();
}

void fsm_msgUnLockDevice(const UnLockDevice *msg) {
  (void)msg;

  RESP_INIT(UnLockDeviceResponse);
  bool is_unlocked = session_isUnlocked();

  if (!is_unlocked) {
    CHECK_PIN
    is_unlocked = session_isUnlocked();
  }

  resp->has_unlocked = true;
  resp->unlocked = is_unlocked;

  if (is_unlocked) {
    resp->has_unlocked_attach_pin = true;
    resp->unlocked_attach_pin = is_passphrase_pin_enabled;
  }

  resp->has_passphrase_protection = true;
  bool passphrase_protection = false;
  config_getPassphraseProtection(&passphrase_protection);
  resp->passphrase_protection = passphrase_protection;

  msg_write(MessageType_MessageType_UnLockDeviceResponse, resp);
  layoutHome();
}
