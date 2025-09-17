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

#include "protect.h"
#include <stdint.h>
#include <sys/types.h>
#include "buttons.h"
#include "common.h"
#include "config.h"
#include "debug.h"
#include "font.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memory.h"
#include "memzero.h"
#include "menu_list.h"
#include "messages.h"
#include "messages.pb.h"
#include "oled.h"
#include "oled_text.h"
#include "pinmatrix.h"
#include "prompt.h"
#include "rng.h"
#include "se_chip.h"
#include "si2c.h"
#include "sys.h"
#include "usb.h"
#include "util.h"

extern void drawScrollbar(int pages, int index);

#define MAX_WRONG_PINS 15

bool protectAbortedByCancel = false;
bool protectAbortedBySleep = false;
// allow the app to connect to the device when in the tutorial page
bool protectAbortedByInitializeOnboarding = false;
bool protectAbortedByInitialize = false;
bool protectAbortedByTimeout = false;
bool exitBlindSignByInitialize = false;
bool protectAbortedByFIDO = false;
extern bool msg_command_inprogress;

bool is_passphrase_pin_enabled = false;

static uint8_t device_sleep_state = SLEEP_NONE;

#define goto_check(label)       \
  if (layoutLast == layoutHome) \
    return false;               \
  else                          \
    goto label;

bool protectButton(ButtonRequestType type, bool confirm_only) {
  ButtonRequest resp = {0};
  bool result = false;
  bool acked = true;
  bool timeout_flag = true;
#if DEBUG_LINK
  bool debug_decided = false;
  acked = false;
#endif

  protectAbortedByTimeout = false;

  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  usbTiny(1);
  buttonUpdate();  // Clear button state
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  timer_out_set(timer_out_oper, default_oper_time);
  if (g_bIsBixinAPP) acked = true;

  while (timer_out_get(timer_out_oper)) {
    usbPoll();

    // check for ButtonAck
    if (msg_tiny_id == MessageType_MessageType_ButtonAck) {
      msg_tiny_id = 0xFFFF;
      acked = true;
    }

    // button acked - check buttons
    if (acked) {
      waitAndProcessUSBRequests(5);
      buttonUpdate();
      if (button.YesUp) {
        timeout_flag = false;
        result = true;
        break;
      }
      if (!confirm_only && button.NoUp) {
        result = false;
        timeout_flag = false;
        break;
      }
    }

    // check for Cancel / Initialize
    protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
    protectAbortedByInitialize =
        (msg_tiny_id == MessageType_MessageType_Initialize);
    if (protectAbortedByCancel || protectAbortedByInitialize) {
      msg_tiny_id = 0xFFFF;
      timeout_flag = false;
      result = false;
      break;
    }

#if DEBUG_LINK
    // check DebugLink
    if (msg_tiny_id == MessageType_MessageType_DebugLinkDecision) {
      msg_tiny_id = 0xFFFF;
      DebugLinkDecision *dld = (DebugLinkDecision *)msg_tiny;
      result = dld->button;
      debug_decided = true;
    }

    if (acked && debug_decided) {
      break;
    }

    if (msg_tiny_id == MessageType_MessageType_DebugLinkGetState) {
      msg_tiny_id = 0xFFFF;
      fsm_msgDebugLinkGetState((DebugLinkGetState *)msg_tiny);
    }
#endif
  }
  timer_out_set(timer_out_oper, 0);
  usbTiny(0);
  if (timeout_flag) protectAbortedByTimeout = true;

  return result;
}

static uint8_t _protectButton_ex(ButtonRequestType type, bool confirm_only,
                                 bool requset, uint32_t timeout_s) {
  ButtonRequest resp = {0};
  bool acked = true;
  bool timeout_flag = true;
  uint8_t key = KEY_NULL;
#if DEBUG_LINK
  bool debug_decided = false;
  acked = false;
#endif

  protectAbortedByTimeout = false;

  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  usbTiny(1);

  if (requset) {
    msg_write(MessageType_MessageType_ButtonRequest, &resp);
  }
  if (timeout_s) {
    timer_out_set(timer_out_oper, timeout_s);
  }

  while (1) {
    if (timeout_s) {
      if (timer_out_get(timer_out_oper) == 0) break;
    }
    usbPoll();

    // check for ButtonAck
    if (msg_tiny_id == MessageType_MessageType_ButtonAck) {
      msg_tiny_id = 0xFFFF;
      acked = true;
    }

    // button acked - check buttons
    if (acked) {
      key = keyScan();
      if (key == KEY_CONFIRM) {
        timeout_flag = false;
        break;
      }
      if (!confirm_only && key != KEY_NULL) {
        timeout_flag = false;
        break;
      }
    }

    // check for Cancel / Initialize
    protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
    protectAbortedByInitialize =
        (msg_tiny_id == MessageType_MessageType_Initialize);
    if (protectAbortedByCancel || protectAbortedByInitialize) {
      msg_tiny_id = 0xFFFF;
      timeout_flag = false;
      break;
    }

#if DEBUG_LINK
    // check DebugLink
    if (msg_tiny_id == MessageType_MessageType_DebugLinkDecision) {
      msg_tiny_id = 0xFFFF;
      DebugLinkDecision *dld = (DebugLinkDecision *)msg_tiny;
      if (dld->button == DebugButton_YES) {
        key = KEY_CONFIRM;
      } else if (dld->button == DebugButton_NO) {
        key = KEY_CANCEL;
      }
      debug_decided = true;
      timeout_flag = false;
    }

    if (acked && debug_decided) {
      break;
    }

    if (msg_tiny_id == MessageType_MessageType_DebugLinkGetState) {
      msg_tiny_id = 0xFFFF;
      fsm_msgDebugLinkGetState((DebugLinkGetState *)msg_tiny);
    }
#endif
  }
  timer_out_set(timer_out_oper, 0);
  usbTiny(0);
  if (timeout_flag) protectAbortedByTimeout = true;

  return key;
}

bool protectButton_ex(ButtonRequestType type, bool confirm_only, bool requset,
                      uint32_t timeout_s) {
  uint8_t key = KEY_NULL;

  while (1) {
    key = _protectButton_ex(type, confirm_only, requset, timeout_s);
    if (key == KEY_CONFIRM) {
      return true;
    } else if (key == KEY_CANCEL) {
      return false;
    }
  }
}

uint8_t protectButtonValue(ButtonRequestType type, bool confirm_only,
                           bool requset, uint32_t timeout_s) {
  return _protectButton_ex(type, confirm_only, requset, timeout_s);
}

const char *requestPin(PinMatrixRequestType type, const char *text,
                       const char **new_pin) {
  bool button_no = false, pinmatrix_show = true;
  uint32_t timer_out_count = 0;
  PinMatrixRequest resp = {0};
  *new_pin = NULL;
  memzero(&resp, sizeof(PinMatrixRequest));
  resp.has_type = true;
  resp.type = type;
  usbTiny(1);
  msg_write(MessageType_MessageType_PinMatrixRequest, &resp);
  timer_out_set(timer_out_oper, default_oper_time);
  timer_out_count = default_oper_time;
  while (timer_out_count) {
    timer_out_count = timer_out_get(timer_out_oper);
    if ((timer_out_count < (default_oper_time - timer1s)) && pinmatrix_show) {
      pinmatrix_start(text);
      pinmatrix_show = false;
    }
    usbPoll();
    buttonUpdate();
    if (msg_tiny_id == MessageType_MessageType_PinMatrixAck) {
      timer_out_set(timer_out_oper, 0);
      msg_tiny_id = 0xFFFF;
      PinMatrixAck *pma = (PinMatrixAck *)msg_tiny;
      usbTiny(0);
      if (pma->has_new_pin) {
        if (sectrue ==
            pinmatrix_done(false, pma->new_pin))  // convert via pinmatrix
          *new_pin = pma->new_pin;
      }
      if (sectrue == pinmatrix_done(true, pma->pin))  // convert via pinmatrix
        return pma->pin;
      else
        return 0;
    } else if (msg_tiny_id == MessageType_MessageType_BixinPinInputOnDevice) {
      // uint8_t min_pin_len = MIN_PIN_LEN;
      // if (PinMatrixRequestType_PinMatrixRequestType_NewFirst == type ||
      //     PinMatrixRequestType_PinMatrixRequestType_NewSecond == type) {
      //   min_pin_len = DEFAULT_PIN_LEN;
      // }
      msg_tiny_id = 0xFFFF;
      usbTiny(0);
      return protectInputPin(text, DEFAULT_PIN_LEN, MAX_PIN_LEN, true);
    }
    if (button.NoUp) {
      timer_out_set(timer_out_oper, 0);
      button_no = true;
      msg_tiny_id = MessageType_MessageType_Cancel;
    }
    // check for Cancel / Initialize
    protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
    protectAbortedByInitialize =
        (msg_tiny_id == MessageType_MessageType_Initialize);
    if (protectAbortedByCancel || protectAbortedByInitialize) {
      pinmatrix_done(true, 0);
      msg_tiny_id = 0xFFFF;
      usbTiny(0);
      if (button_no)
        return PIN_CANCELED_BY_BUTTON;
      else
        return 0;
    }
#if DEBUG_LINK
    if (msg_tiny_id == MessageType_MessageType_DebugLinkGetState) {
      msg_tiny_id = 0xFFFF;
      fsm_msgDebugLinkGetState((DebugLinkGetState *)msg_tiny);
    }
#endif
  }
  // time out
  msg_tiny_id = 0xFFFF;
  usbTiny(0);
  return PIN_CANCELED_BY_BUTTON;
}

secbool protectPinUiCallback(uint32_t wait, uint32_t progress,
                             const char *message) {
  (void)wait;
  (void)message;
  oledClear_ex();
  oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT / 2 - 6, message,
                              FONT_STANDARD);

  // progressbar
  oledBox(2, OLED_HEIGHT - 13, OLED_WIDTH - 2, OLED_HEIGHT - 2, 0);
  oledBox(5, OLED_HEIGHT - 13, OLED_WIDTH - 3, OLED_HEIGHT - 13, 1);
  oledBox(5, OLED_HEIGHT - 3, OLED_WIDTH - 3, OLED_HEIGHT - 3, 1);

  progress = progress * (OLED_WIDTH - 4) / 1000;
  if (progress > OLED_WIDTH - 4) {
    progress = OLED_WIDTH - 4;
  }
  oledBox(2, OLED_HEIGHT - 10, 2, OLED_HEIGHT - 6, 1);
  oledBox(3, OLED_HEIGHT - 12, 4, OLED_HEIGHT - 4, 1);
  if (progress > 3) {
    oledBox(5, OLED_HEIGHT - 12, progress + 1, OLED_HEIGHT - 4, 1);
  }

  oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 13, OLED_WIDTH - 3, OLED_HEIGHT - 3, 0);

  oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 12, OLED_WIDTH - 4, OLED_HEIGHT - 11,
          1);
  oledClearPixel(OLED_WIDTH - 5, OLED_HEIGHT - 11);
  oledBox(OLED_WIDTH - 3, OLED_HEIGHT - 10, OLED_WIDTH - 3, OLED_HEIGHT - 6, 1);
  oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 5, OLED_WIDTH - 4, OLED_HEIGHT - 4, 1);
  oledClearPixel(OLED_WIDTH - 5, OLED_HEIGHT - 5);

  if (progress >= OLED_WIDTH - 6) {
    oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 11, OLED_WIDTH - 5, OLED_HEIGHT - 5,
            1);
    if (progress > OLED_WIDTH - 6) {
      oledBox(OLED_WIDTH - 4, OLED_HEIGHT - 11, OLED_WIDTH - 4, OLED_HEIGHT - 5,
              1);
    }
  }
  oledRefresh();
  // Check for Cancel / Initialize.
  protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
  protectAbortedByInitialize =
      (msg_tiny_id == MessageType_MessageType_Initialize);
  if (protectAbortedByCancel || protectAbortedByInitialize) {
    msg_tiny_id = 0xFFFF;
    usbTiny(0);
    fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
    return sectrue;
  }

  return secfalse;
}

bool protectPin(bool use_cached) {
  const char *newpin = NULL;
  if (use_cached && session_isUnlocked()) {
    return true;
  }

  const char *pin = "";
  if (config_hasPin()) {
    pin = requestPin(PinMatrixRequestType_PinMatrixRequestType_Current,
                     _(T__ENTER_PIN), &newpin);
    if (!pin) {
      fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
      return false;
    } else if (pin == PIN_CANCELED_BY_BUTTON)
      return false;
  }

  bool passphrase_protection = false;
  config_getPassphraseProtection(&passphrase_protection);
  pin_type_t pin_type = PIN_TYPE_USER;
  if (passphrase_protection) {
    pin_type = PIN_TYPE_USER_AND_PASSPHRASE_PIN;
  }

  bool ret = config_unlock(pin, pin_type);
  if (!ret) {
    fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
    msg_command_inprogress = false;
    protectPinErrorTips(false);
    msg_command_inprogress = true;
  } else {
    if (passphrase_protection) {
      pin_result_t pin_result = se_get_pin_result_type();
      if (pin_result == PASSPHRASE_PIN_ENTERED) {
        is_passphrase_pin_enabled = true;
        if (se_sessionClose()) {
          if (se_sessionClear()) {
            uint8_t *new_session = se_session_startSession(NULL);
            (void)new_session;
          }
        } else {
        }
      } else if (pin_result == USER_PIN_ENTERED) {
        is_passphrase_pin_enabled = false;
      } else {
        is_passphrase_pin_enabled = false;
      }
    } else {
      is_passphrase_pin_enabled = false;
    }
  }
  return ret;
}

bool protectChangePin(bool removal) {
  static CONFIDENTIAL char old_pin[MAX_PIN_LEN + 1] = "";
  static CONFIDENTIAL char new_pin[MAX_PIN_LEN + 1] = "";
  const char *pin = NULL;
  const char *newpin = NULL;
  bool need_new_pin = true;

  if (config_hasPin()) {
    pin = requestPin(PinMatrixRequestType_PinMatrixRequestType_Current,
                     _(T__ENTER_PIN), &newpin);

    if (pin == NULL) {
      fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
      return false;
    } else if (pin == PIN_CANCELED_BY_BUTTON)
      return false;

    usbTiny(1);
    bool ret = config_unlock(pin, PIN_TYPE_USER_CHECK);
    usbTiny(0);
    if (ret == false) {
      fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
      protectPinErrorTips(false);
      return false;
    }

    strlcpy(old_pin, pin, sizeof(old_pin));
    if (g_bIsBixinAPP) {
      need_new_pin = false;
      if (newpin == NULL) {
        newpin = protectInputPin(_(T__ENTER_NEW_PIN), DEFAULT_PIN_LEN,
                                 MAX_PIN_LEN, true);
      }
    }
  }

  if (!removal) {
    if (!g_bIsBixinAPP || need_new_pin) {
      pin = requestPin(PinMatrixRequestType_PinMatrixRequestType_NewFirst,
                       _(T__ENTER_NEW_PIN), &newpin);
    } else {
      if (newpin == NULL) {
        fsm_sendFailure(FailureType_Failure_PinExpected, NULL);
        layoutHome();
        return false;
      }
      pin = newpin;
    }
    if (pin == PIN_CANCELED_BY_BUTTON) {
      return false;
    } else if (pin == NULL || pin[0] == '\0') {
      memzero(old_pin, sizeof(old_pin));
      fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
      return false;
    }

    strlcpy(new_pin, pin, sizeof(new_pin));

    if (!g_bIsBixinAPP) {
      pin = requestPin(PinMatrixRequestType_PinMatrixRequestType_NewSecond,
                       _(T__ENTER_NEW_PIN_AGAIN), &newpin);
      if (pin == NULL) {
        memzero(old_pin, sizeof(old_pin));
        memzero(new_pin, sizeof(new_pin));
        fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
        return false;
      } else if (pin == PIN_CANCELED_BY_BUTTON)
        return false;
      if (strncmp(new_pin, pin, sizeof(new_pin)) != 0) {
        memzero(old_pin, sizeof(old_pin));
        memzero(new_pin, sizeof(new_pin));
        fsm_sendFailure(FailureType_Failure_PinMismatch, NULL);
        return false;
      }
    } else {
      layoutDialogCenterAdapterV2(
          NULL, &bmp_icon_question, &bmp_bottom_left_close,
          &bmp_bottom_right_confirm, NULL, NULL, _(C__PLEASE_CONFIRM_PIN),
          new_pin, NULL, NULL, NULL);
      if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        i2c_set_wait(false);
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return false;
      }
    }
  }

  bool ret = config_changePin(old_pin, new_pin);
  memzero(old_pin, sizeof(old_pin));
  memzero(new_pin, sizeof(new_pin));
  if (ret == false) {
    i2c_set_wait(false);
    if (removal) {
      fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "The new PIN must be different from your wipe code.");
    }
  }
  return ret;
}

bool protectChangeWipeCode(bool removal) {
  static CONFIDENTIAL char pin[MAX_PIN_LEN + 1] = "";
  static CONFIDENTIAL char wipe_code[MAX_PIN_LEN + 1] = "";
  const char *input = NULL;
  const char *newpin = NULL;

  if (config_hasPin()) {
    input = requestPin(PinMatrixRequestType_PinMatrixRequestType_Current,
                       _(C__PLEASE_ENTER_YOUR_PIN), &newpin);
    if (input == NULL) {
      fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
      return false;
    } else if (pin == PIN_CANCELED_BY_BUTTON)
      return false;

    if (!removal) {
      usbTiny(1);
      bool ret = config_unlock(input, PIN_TYPE_USER_CHECK);
      usbTiny(0);
      if (ret == false) {
        fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
        return false;
      }
    }

    strlcpy(pin, input, sizeof(pin));
  }

  if (!removal) {
    input = requestPin(PinMatrixRequestType_PinMatrixRequestType_WipeCodeFirst,
                       _(C__ENTER_NEW_WIPE_CODE), &newpin);
    if (input == NULL) {
      memzero(pin, sizeof(pin));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    } else if (pin == PIN_CANCELED_BY_BUTTON)
      return false;
    if (strncmp(pin, input, sizeof(pin)) == 0) {
      memzero(pin, sizeof(pin));
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "The wipe code must be different from your PIN.");
      return false;
    }
    strlcpy(wipe_code, input, sizeof(wipe_code));

    input = requestPin(PinMatrixRequestType_PinMatrixRequestType_WipeCodeSecond,
                       "Re-enter new wipe code:", &newpin);
    if (input == NULL) {
      memzero(pin, sizeof(pin));
      memzero(wipe_code, sizeof(wipe_code));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    } else if (pin == PIN_CANCELED_BY_BUTTON)
      return false;

    if (strncmp(wipe_code, input, sizeof(wipe_code)) != 0) {
      memzero(pin, sizeof(pin));
      memzero(wipe_code, sizeof(wipe_code));
      fsm_sendFailure(FailureType_Failure_WipeCodeMismatch, NULL);
      return false;
    }
  }

  bool ret = config_changeWipeCode(pin, wipe_code);
  memzero(pin, sizeof(pin));
  memzero(wipe_code, sizeof(wipe_code));
  if (ret == false) {
    fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
  }
  return ret;
}

bool protectPassphrase(char *passphrase) {
  memzero(passphrase, MAX_PASSPHRASE_LEN + 1);
  bool passphrase_protection = false;
  config_getPassphraseProtection(&passphrase_protection);
  if (!passphrase_protection) {
    return true;
  }

  if (is_passphrase_pin_enabled) {
    return true;
  }

  PassphraseRequest resp = {0};
  memzero(&resp, sizeof(PassphraseRequest));

  uint8_t space_available = 0;
  if (se_get_pin_passphrase_space(&space_available)) {
    resp.has_exists_attach_pin_user = true;
    resp.exists_attach_pin_user = (space_available < 30);

  } else {
    resp.has_exists_attach_pin_user = true;
    resp.exists_attach_pin_user = false;
  }

  usbTiny(1);
  msg_write(MessageType_MessageType_PassphraseRequest, &resp);

  bool result = false, show = true;
  uint32_t timer_out_count = 0;
  timer_out_set(timer_out_oper, default_oper_time);
  timer_out_count = default_oper_time;
  while (timer_out_count) {
    timer_out_count = timer_out_get(timer_out_oper);
    if ((timer_out_count < (default_oper_time - timer1s)) && show) {
      layoutDialogCenterAdapterV2(
          _(T__ENTER_PASSPHRASE), NULL, &bmp_bottom_left_close, NULL, NULL,
          NULL, NULL, NULL, NULL, NULL,
          _(C__ENTER_YOUR_PASSPHRASE_ON_CONNECTED_DEVICE));
      show = false;
    }
    usbPoll();
    buttonUpdate();
    if (msg_tiny_id == MessageType_MessageType_PassphraseAck) {
      msg_tiny_id = 0xFFFF;
      PassphraseAck *ppa = (PassphraseAck *)msg_tiny;

      if (ppa->has_on_device_attach_pin && ppa->on_device_attach_pin == true) {
        session_clear(true);
        layoutHome();
        PinMatrixRequest pin_req;
        memzero(&pin_req, sizeof(PinMatrixRequest));
        pin_req.has_type = true;
        pin_req.type = PinMatrixRequestType_PinMatrixRequestType_AttachToPin;
        msg_write(MessageType_MessageType_PinMatrixRequest, &pin_req);

        // Show 9-grid matrix on device
        pinmatrix_start(_(T__ENTER_HIDDEN_PIN));

        const char *entered_pin = NULL;
        bool pin_verified = false;

        while (!pin_verified) {
          usbPoll();

          if (msg_tiny_id == MessageType_MessageType_PinMatrixAck) {
            msg_tiny_id = 0xFFFF;
            PinMatrixAck *pma = (PinMatrixAck *)msg_tiny;

            // Decode PIN from matrix
            if (sectrue == pinmatrix_done(true, pma->pin)) {
              entered_pin = pma->pin;

              // Verify the entered PIN
              if (config_verifyPin(entered_pin, PIN_TYPE_PASSPHRASE_PIN)) {
                pin_result_t pin_result = se_get_pin_result_type();
                if (pin_result == PASSPHRASE_PIN_ENTERED) {
                  is_passphrase_pin_enabled = true;
                  pin_verified = true;

                  if (se_sessionClose()) {
                    if (se_sessionClear()) {
                      uint8_t *new_session = se_session_startSession(NULL);
                      if (new_session != NULL) {
                      } else {
                      }
                    } else {
                    }
                  } else {
                  }
                } else {
                  fsm_sendFailure(FailureType_Failure_PinInvalid,
                                  "Incorrect PIN");
                  protectPinErrorTips(true);

                  if (msg_tiny_id == MessageType_MessageType_Cancel) {
                    msg_tiny_id = 0xFFFF;
                    result = false;
                    goto matrix_input_exit;
                  }

                  result = false;
                  goto matrix_input_exit;
                }
              } else {
                fsm_sendFailure(FailureType_Failure_PinInvalid,
                                "Incorrect PIN");
                protectPinErrorTips(true);

                if (msg_tiny_id == MessageType_MessageType_Cancel) {
                  msg_tiny_id = 0xFFFF;
                  result = false;
                  goto matrix_input_exit;
                }

                result = false;
                goto matrix_input_exit;
              }
            } else {
              result = false;
              break;
            }

          } else if (msg_tiny_id ==
                     MessageType_MessageType_BixinPinInputOnDevice) {
            msg_tiny_id = 0xFFFF;

            while (true) {
              entered_pin =
                  protectInputPin(_(T__ENTER_HIDDEN_PIN), 6, MAX_PIN_LEN, true);
              if (!entered_pin || entered_pin == PIN_CANCELED_BY_BUTTON) {
                result = false;
                goto matrix_input_exit;
              }

              bool verify_result =
                  config_verifyPin(entered_pin, PIN_TYPE_PASSPHRASE_PIN);
              pin_result_t pin_result = se_get_pin_result_type();

              switch (pin_result) {
                case PIN_SUCCESS:
                  break;
                case USER_PIN_ENTERED:
                  break;
                case USER_PIN_FAILED:
                  break;
                case PASSPHRASE_PIN_ENTERED:
                  break;
                case PASSPHRASE_PIN_NO_MATCHED:
                  break;
                case USER_PIN_NOT_ENTERED:
                  break;
                case PIN_FAILED:

                  break;
                default:

                  break;
              }

              if (verify_result && pin_result == PASSPHRASE_PIN_ENTERED) {
                is_passphrase_pin_enabled = true;
                pin_verified = true;

                if (se_sessionClose()) {
                  if (se_sessionClear()) {
                    uint8_t *new_session = se_session_startSession(NULL);
                    if (new_session != NULL) {
                    } else {
                    }
                  } else {
                  }
                } else {
                }

                break;  // Exit device input retry loop
              }

              protectPinErrorTips(true);
              result = false;
              goto matrix_input_exit;
            }

          matrix_input_exit:
            if (!pin_verified && result == false) {
              break;  // Exit main loop
            }

            // Check for Cancel
          } else if (msg_tiny_id == MessageType_MessageType_Cancel) {
            msg_tiny_id = 0xFFFF;
            result = false;
            break;
          }
        }

        // If PIN input was cancelled or failed, exit
        if (!pin_verified) {
          result = false;
          break;
        }

        // Set empty passphrase for attach-to-pin (like Pro firmware)
        memzero(passphrase, sizeof(passphrase));
        result = true;
        break;
      }

      if (ppa->has_on_device && ppa->on_device == true) {
        return protectPassphraseOnDevice(passphrase);
      }
      if (!ppa->has_passphrase) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "No passphrase provided. Use empty string to set an "
                        "empty passphrase.");
        result = false;
        break;
      }
      strlcpy(passphrase, ppa->passphrase, sizeof(ppa->passphrase));
      result = true;
      break;
    }
    if (button.NoUp) {
      result = false;
      break;
    }
    // check for Cancel / Initialize
    protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
    protectAbortedByInitialize =
        (msg_tiny_id == MessageType_MessageType_Initialize);
    if (protectAbortedByCancel || protectAbortedByInitialize) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      result = false;
      msg_tiny_id = 0xFFFF;
      break;
    }
#if DEBUG_LINK
    if (msg_tiny_id == MessageType_MessageType_DebugLinkGetState) {
      msg_tiny_id = 0xFFFF;
      fsm_msgDebugLinkGetState((DebugLinkGetState *)msg_tiny);
    }
#endif
  }
  usbTiny(0);
  layoutHome();
  return result;
}

bool protectSeedPin(bool force_pin, bool setpin, bool update_pin) {
  static CONFIDENTIAL char old_pin[MAX_PIN_LEN + 1] = "";
  static CONFIDENTIAL char new_pin[MAX_PIN_LEN + 1] = "";
  const char *pin = NULL;
  const char *newpin = NULL;

  if (update_pin) {
    bool ret = config_changePin(old_pin, new_pin);
    memzero(old_pin, sizeof(old_pin));
    memzero(new_pin, sizeof(new_pin));
    if (ret == false) {
      i2c_set_wait(false);
      fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
      return false;
    }
  } else {
    if (config_hasPin()) {
      pin = requestPin(PinMatrixRequestType_PinMatrixRequestType_Current,
                       _(T__ENTER_PIN), &newpin);
      if (!pin) {
        fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
        return false;
      } else if (pin == PIN_CANCELED_BY_BUTTON)
        return false;

      bool ret = config_unlock(pin, PIN_TYPE_USER);
      if (!ret) {
        fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
        protectPinErrorTips(false);
        return false;
      }
    } else {
      if (force_pin) {
        pin = requestPin(PinMatrixRequestType_PinMatrixRequestType_NewFirst,
                         _(T__ENTER_NEW_PIN), &newpin);
        if (pin == PIN_CANCELED_BY_BUTTON) {
          return false;
        } else if (pin == NULL || pin[0] == '\0') {
          fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
          return false;
        }

        layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"), NULL,
                          __("Please confirm PIN"), NULL, NULL, pin, NULL,
                          NULL);

        if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
                           false)) {
          i2c_set_wait(false);
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return false;
        }
        strlcpy(new_pin, pin, sizeof(new_pin));
        if (setpin) {
          bool ret = config_changePin(old_pin, new_pin);
          memzero(old_pin, sizeof(old_pin));
          memzero(new_pin, sizeof(new_pin));
          if (ret == false) {
            i2c_set_wait(false);
            fsm_sendFailure(FailureType_Failure_PinInvalid, NULL);
            return false;
          }
        }
      } else {
        pin = "";
      }
    }

    if (!config_setSeedPin(pin)) {
      fsm_sendFailure(FailureType_Failure_PinMismatch, NULL);
      return false;
    }
  }
  return true;
}

uint8_t blindsignWaitKey(void) {
  uint8_t key = KEY_NULL;
  exitBlindSignByInitialize = false;

  usbTiny(1);
  usbPoll();
  protectAbortedByInitialize =
      (msg_tiny_id == MessageType_MessageType_Initialize);
  if (protectAbortedByInitialize) {
    msg_tiny_id = 0xFFFF;
  }
  usbTiny(0);

  if (protectAbortedByInitialize) {
    if (device_sleep_state) device_sleep_state = SLEEP_CANCEL_BY_USB;
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    exitBlindSignByInitialize = true;
    layoutHome();
  }

  key = keyScan();
  if (key != KEY_NULL) {
    if (device_sleep_state) device_sleep_state = SLEEP_CANCEL_BY_BUTTON;
  }
  return key;
}

extern bool u2f_init_command;

uint8_t protectWaitKey(uint32_t time_out, uint8_t mode) {
  uint8_t key = KEY_NULL;
  uint32_t start = timer_ms();

  protectAbortedByInitialize = false;
  protectAbortedByInitializeOnboarding = false;
  protectAbortedBySleep = false;
  protectAbortedByCancel = false;
  usbTiny(1);
  while (1) {
    if (layoutEnterSleep(1) && (layoutLast != layoutScreensaver)) {
      if (layoutLast == onboarding) {
#if !EMULATOR
        timer_sleep_start_reset();
        unregister_timer("poweroff");
#endif
      } else {
        key = KEY_NULL;
        protectAbortedBySleep = true;
        break;
      }
    }
    usbPoll();
#if !EMULATOR
    if ((host_channel == CHANNEL_USB) && ((sys_usbState() == false)) &&
        msg_command_inprogress) {
      usbTiny(0);
      layoutHome();
      return KEY_NULL;
    }
#endif
    if (time_out > 0 && (timer_ms() - start) >= time_out) break;
    protectAbortedByInitialize =
        (msg_tiny_id == MessageType_MessageType_Initialize);
    protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
    if (protectAbortedByInitialize || protectAbortedByCancel) {
      msg_tiny_id = 0xFFFF;
      break;
    }
#if !BITCOIN_ONLY
    if (layoutLast == layoutScreensaver) {
      if (u2f_init_command) {
        u2f_init_command = false;
        break;
      }
    }
#endif
    if (protectAbortedByFIDO && layoutLast == layoutHome) {
      protectAbortedByFIDO = false;
      break;
    }

    loop_callback_handler();

    key = keyScan();
    if (key != KEY_NULL) {
      if (device_sleep_state) device_sleep_state = SLEEP_CANCEL_BY_BUTTON;
      if (mode == 0) {
        break;
      } else {
        if (key == KEY_CONFIRM || key == KEY_CANCEL) break;
      }
    }
#if !EMULATOR
    if (isLongPress(KEY_UP_OR_DOWN) && getLongPressStatus()) {
      break;
    }
#endif
    if (device_sleep_state == SLEEP_REENTER) {
      break;
    }
  }
  usbTiny(0);
  protectAbortedByInitializeOnboarding = protectAbortedByInitialize;
  if (protectAbortedByInitialize || protectAbortedByCancel) {
    if (device_sleep_state) device_sleep_state = SLEEP_CANCEL_BY_USB;
    // this error code will be sent when the message processing fails
    if (false == msg_command_inprogress) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    }
    layoutHome();
  }

  return key;
}

uint8_t protectWaitKeyValue(ButtonRequestType type, bool requset,
                            uint32_t time_out, uint8_t mode) {
  if (requset) {
    ButtonRequest resp = {0};
    memzero(&resp, sizeof(ButtonRequest));
    resp.has_code = true;
    resp.code = type;
    msg_write(MessageType_MessageType_ButtonRequest, &resp);
  }
  return protectWaitKey(time_out, mode);
}

const char *protectInputPin(const char *text, uint8_t min_pin_len,
                            uint8_t max_pin_len, bool cancel_allowed) {
  uint8_t key = KEY_NULL;
  uint8_t counter = 0;
  int index = 0, max_index = 0;
  bool update = true;
  static char pin[10] = "";
  bool d = false;
  config_getInputDirection(&d);

  memzero(pin, sizeof(pin));

#if !EMULATOR
  enableLongPress(true);
#endif

refresh_menu:
  if (update) {
    update = false;
    max_index = (counter >= min_pin_len) ? 10 : 9;
    if (counter >= min_pin_len) {
      index = 10;
    } else {
      index = random_uniform(10);
    }
  }
  layoutInputPin(counter, text, index, cancel_allowed);
  key = protectWaitKey(0, 0);
#if !EMULATOR
  if (isLongPress(KEY_UP_OR_DOWN) && getLongPressStatus()) {
    if (isLongPress(KEY_UP)) {  // up
      if (!d) {                 // default direction
        if (index > 0)
          index--;
        else
          index = max_index;
      } else {
        if (index < max_index)
          index++;
        else
          index = 0;
      }
    } else if (isLongPress(KEY_DOWN)) {  // down
      if (!d) {
        if (index < max_index)
          index++;
        else
          index = 0;
      } else {
        if (index > 0)
          index--;
        else
          index = max_index;
      }
    }
    delay_ms(75);
    goto refresh_menu;
  }
#endif
  if (d) {  // Reverse direction
    if (key == KEY_UP) {
      key = KEY_DOWN;
    } else if (key == KEY_DOWN) {
      key = KEY_UP;
    }
  }
  switch (key) {
    case KEY_UP:
      if (index > 0)
        index--;
      else
        index = max_index;
      goto refresh_menu;
    case KEY_DOWN:
      if (index < max_index)
        index++;
      else
        index = 0;
      goto refresh_menu;
    case KEY_CONFIRM:
      (void)pin;
      if (index == 10) {
#if !EMULATOR
        enableLongPress(false);
#endif
        return pin;
      } else {
        pin[counter++] = index + '0';
        if (counter == max_pin_len) {
#if !EMULATOR
          enableLongPress(false);
#endif
          return pin;
        }
        update = true;
        goto refresh_menu;
      }
    case KEY_CANCEL:
      if (counter) {
        counter--;
        pin[counter] = 0;
        update = true;
        goto refresh_menu;
      }
      break;
    default:
      break;
  }

#if !EMULATOR
  enableLongPress(false);
#endif

  return NULL;
}

bool protectPinOnDevice(bool use_cached, bool cancel_allowed) {
  //   static bool input_pin = false;  // void recursive
  if (use_cached && session_isUnlocked()) {
    return true;
  }
  //   if (input_pin) return true;
  const char *pin = "";
input:
  if (config_hasPin()) {
    // input_pin = true;
    const char *pin_title;
    if (session_isUnlocked() && is_passphrase_pin_enabled) {
      pin_title = _(T__STANDARD_PIN);
    } else {
      pin_title = _(T__ENTER_PIN);
    }
    pin = protectInputPin(pin_title, DEFAULT_PIN_LEN, MAX_PIN_LEN,
                          cancel_allowed);
    // input_pin = false;
    if (!pin) {
      return false;
    } else if (pin == PIN_CANCELED_BY_BUTTON)
      return false;
  }

  bool ret = config_unlock(pin, PIN_TYPE_USER_AND_PASSPHRASE_PIN);
  if (ret == false) {
    protectPinErrorTips(true);
    goto input;
  }

  if (ret) {
    pin_result_t pin_result = se_get_pin_result_type();
    if (pin_result == PASSPHRASE_PIN_ENTERED) {
      is_passphrase_pin_enabled = true;

    } else if (pin_result == USER_PIN_ENTERED) {
      is_passphrase_pin_enabled = false;

    } else {
      is_passphrase_pin_enabled = false;
    }
  }

  return ret;
}

bool protectChangePinOnDevice(bool is_prompt, bool set, bool cancel_allowed) {
  static CONFIDENTIAL char old_pin[MAX_PIN_LEN + 1] = "";
  static CONFIDENTIAL char new_pin[MAX_PIN_LEN + 1] = "";
  const char *pin = NULL;
  bool is_change = false;
  uint8_t key;
  pin_result_t pin_result = PIN_SUCCESS;
  bool deleted_passphrase_pin = false;
  bool deleted_passphrase_current = false;

pin_set:
  if (config_hasPin()) {
    is_change = true;
  input:
    pin = protectInputPin(_(T__ENTER_PIN), DEFAULT_PIN_LEN, MAX_PIN_LEN, true);

    if (pin == NULL) {
      return false;
    } else if (pin == PIN_CANCELED_BY_BUTTON)
      return false;

    bool ret = config_unlock(pin, PIN_TYPE_USER_AND_PASSPHRASE_PIN_CHECK);

    if (ret == false) {
      protectPinErrorTips(true);
      goto input;
    }
    pin_result = se_get_pin_result_type();

    layoutDialogCenterAdapterV2(
        _(T__SET_PIN), NULL, NULL, &bmp_bottom_right_arrow, NULL, NULL, NULL,
        NULL, NULL, NULL, _(C__SET_A_4_TO_9_DIGITS_PIN_TO_PROTECT_YOUR_WALLET));
    key = protectWaitKey(0, 1);
    if (key != KEY_CONFIRM) {
      return false;
    }
    strlcpy(old_pin, pin, sizeof(old_pin));
  } else {
    if (!cancel_allowed) {
      layoutDialogCenterAdapterV2(
          _(T__SET_PIN), NULL, NULL, &bmp_bottom_right_arrow, NULL, NULL, NULL,
          NULL, NULL, NULL,
          _(C__SET_A_4_TO_9_DIGITS_PIN_TO_PROTECT_YOUR_WALLET));
      while (1) {
        key = protectWaitKey(0, 1);
        if (key == KEY_CONFIRM) {
          break;
        }
      }
    } else {
      layoutDialogCenterAdapterV2(
          _(T__SET_PIN), NULL, NULL, &bmp_bottom_right_arrow, NULL, NULL, NULL,
          NULL, NULL, NULL,
          _(C__SET_A_4_TO_9_DIGITS_PIN_TO_PROTECT_YOUR_WALLET));
      key = protectWaitKey(0, 1);
      if (key != KEY_CONFIRM) {
        return false;
      }
    }
  }

retry:
  uint8_t min_new_pin_len =
      (pin_result == PASSPHRASE_PIN_ENTERED) ? 6 : DEFAULT_PIN_LEN;
  pin =
      protectInputPin(_(T__ENTER_NEW_PIN), min_new_pin_len, MAX_PIN_LEN, true);
  if (pin == PIN_CANCELED_BY_BUTTON) {
    return false;
  } else if (pin == NULL || pin[0] == '\0') {
    memzero(old_pin, sizeof(old_pin));
    if (set) {
      goto_check(pin_set);
    }
    return false;
  }
  strlcpy(new_pin, pin, sizeof(new_pin));

  pin = protectInputPin(_(T__ENTER_NEW_PIN_AGAIN), min_new_pin_len, MAX_PIN_LEN,
                        true);
  if (pin == NULL) {
    memzero(old_pin, sizeof(old_pin));
    memzero(new_pin, sizeof(new_pin));
    if (set) {
      goto_check(retry);
    }
    return false;
  } else if (pin == PIN_CANCELED_BY_BUTTON)
    return false;
  if (strncmp(new_pin, pin, sizeof(new_pin)) != 0) {
    memzero(old_pin, sizeof(old_pin));
    memzero(new_pin, sizeof(new_pin));
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_error, NULL, &bmp_bottom_right_retry, NULL, NULL, NULL,
        NULL, NULL, NULL, _(C__PIN_NOT_MATCH_EXCLAM_TRY_AGAIN));

    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        goto retry;
      } else if (key == KEY_NULL) {
        return false;
      }
    }
  }

  if (is_change && pin_result == USER_PIN_ENTERED) {
  } else if (is_change) {
  } else {
  }

  if (pin_result == USER_PIN_ENTERED) {
    bool check_ok = config_verifyPin(new_pin, PIN_TYPE_PASSPHRASE_PIN_CHECK);
    pin_result_t new_pin_check_result = se_get_pin_result_type();
    if (!check_ok) {
      new_pin_check_result = PIN_FAILED;
    }

    if (strncmp(old_pin, new_pin, MAX_PIN_LEN) == 0) {
      memzero(old_pin, sizeof(old_pin));
      memzero(new_pin, sizeof(new_pin));

      if (is_prompt) {
        layoutDialogCenterAdapter(
            &bmp_icon_ok, NULL, NULL, &bmp_bottom_right_confirm, NULL, NULL,
            NULL, NULL, NULL, is_change ? _(C__PIN_CHANGED) : _(C__PIN_IS_SET),
            NULL, NULL);

        while (1) {
          key = protectWaitKey(0, 1);
          if (key == KEY_CONFIRM) {
            break;
          }
        }
      }
      return true;
    } else if (new_pin_check_result == PIN_SUCCESS ||
               new_pin_check_result == PASSPHRASE_PIN_ENTERED) {
      layoutDialogCenterAdapterV2(
          NULL, &bmp_icon_warning, &bmp_bottom_left_close,
          &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
          _(C__PIN_ALREADY_USED_DO_YOU_WANT_TO_OVERWRITE_IT));

      while (1) {
        key = protectWaitKey(0, 1);
        if (key == KEY_CONFIRM) {
          bool is_current = false;
          secbool delete_result =
              se_delete_pin_passphrase(new_pin, &is_current);
          if (delete_result == sectrue) {
            deleted_passphrase_pin = true;
            deleted_passphrase_current = is_current;
            if (is_current) {
              is_passphrase_pin_enabled = false;
            }
            break;
          } else {
            layoutDialogCenterAdapterV2(
                NULL, &bmp_icon_error, NULL, &bmp_bottom_right_confirm, NULL,
                NULL, NULL, NULL, NULL, NULL,
                _(C__PIN_ALREADY_USED_PLEASE_TRY_A_DIFFERENT_ONE));
            protectWaitKey(0, 1);
            memzero(old_pin, sizeof(old_pin));
            memzero(new_pin, sizeof(new_pin));
            return false;
          }
        } else if (key == KEY_CANCEL) {
          memzero(old_pin, sizeof(old_pin));
          memzero(new_pin, sizeof(new_pin));
          return false;
        }
      }
    }
  } else if (pin_result == PASSPHRASE_PIN_ENTERED) {
    bool check_ok =
        config_verifyPin(new_pin, PIN_TYPE_USER_AND_PASSPHRASE_PIN_CHECK);
    pin_result_t new_pin_check_result = se_get_pin_result_type();
    if (!check_ok) {
      new_pin_check_result = PIN_FAILED;
    }

    if (strncmp(old_pin, new_pin, MAX_PIN_LEN) == 0) {
      memzero(old_pin, sizeof(old_pin));
      memzero(new_pin, sizeof(new_pin));
      if (is_prompt) {
        layoutDialogCenterAdapter(
            &bmp_icon_ok, NULL, NULL, &bmp_bottom_right_confirm, NULL, NULL,
            NULL, NULL, NULL, is_change ? _(C__PIN_CHANGED) : _(C__PIN_IS_SET),
            NULL, NULL);
        while (1) {
          key = protectWaitKey(0, 1);
          if (key == KEY_CONFIRM) {
            break;
          }
        }
      }
      return true;
    } else if (new_pin_check_result == USER_PIN_ENTERED ||
               new_pin_check_result == PIN_SAME_AS_USER_PIN) {
      layoutDialogCenterAdapterV2(
          NULL, &bmp_icon_error, NULL, &bmp_bottom_right_retry, NULL, NULL,
          NULL, NULL, NULL, NULL,
          _(C__PIN_ALREADY_USED_PLEASE_TRY_A_DIFFERENT_ONE));
      while (1) {
        key = protectWaitKey(0, 1);
        if (key == KEY_CONFIRM) {
          // Retry entering new PIN only; keep verified old_pin
          memzero(new_pin, sizeof(new_pin));
          goto retry;
        } else if (key == KEY_NULL) {
          return false;
        }
      }
    } else if (new_pin_check_result == PASSPHRASE_PIN_ENTERED) {
      layoutDialogCenterAdapterV2(
          NULL, &bmp_icon_warning, &bmp_bottom_left_close,
          &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
          _(C__PIN_ALREADY_USED_DO_YOU_WANT_TO_OVERWRITE_IT));

      while (1) {
        key = protectWaitKey(0, 1);
        if (key == KEY_CONFIRM) {
          break;
        } else if (key == KEY_CANCEL) {
          memzero(old_pin, sizeof(old_pin));
          memzero(new_pin, sizeof(new_pin));
          return false;
        }
      }
    }
  }

  bool ret = false;

  if (pin_result == PASSPHRASE_PIN_ENTERED) {
    ret = (se_change_pin_passphrase(old_pin, new_pin) == sectrue);
  } else {
    ret = config_changePin(old_pin, new_pin);
  }

  if (ret == false) {
    // No fallback UI here; simply cleanup and return
    memzero(old_pin, sizeof(old_pin));
    memzero(new_pin, sizeof(new_pin));
  } else {
    memzero(old_pin, sizeof(old_pin));
    memzero(new_pin, sizeof(new_pin));
    if (deleted_passphrase_pin && deleted_passphrase_current) {
      is_passphrase_pin_enabled = false;
    }
    if (is_prompt) {
      layoutDialogCenterAdapter(
          &bmp_icon_ok, NULL, NULL, &bmp_bottom_right_confirm, NULL, NULL, NULL,
          NULL, NULL, is_change ? _(C__PIN_CHANGED) : _(C__PIN_IS_SET), NULL,
          NULL);

      while (1) {
        key = protectWaitKey(0, 1);
        if (key == KEY_CONFIRM) {
          break;
        }
      }
    }
  }
  return ret;
}

bool protectSelectMnemonicNumber(uint32_t *number, bool cancel_allowed) {
  uint8_t key = KEY_NULL;
  uint32_t index = 0;
  uint32_t num_s[3] = {12, 18, 24};

  layout_item_t items[3] = {
      {.label = _(O__12_WORDS), .value = NULL, .center = true},
      {.label = _(O__18_WORDS), .value = NULL, .center = true},
      {.label = _(O__24_WORDS), .value = NULL, .center = true},
  };

  layout_screen_t screen = {
      .bmp_up = &bmp_bottom_middle_arrow_up,
      .bmp_down = &bmp_bottom_middle_arrow_down,
      .bmp_no = cancel_allowed ? &bmp_bottom_left_arrow : NULL,
      .bmp_yes = &bmp_bottom_right_arrow,
      .btn_no = NULL,
      .btn_yes = NULL,
      .title = _(T__SELECT_NUMBER_OF_WORDS),
      .title_space = true,
      .items = items,
      .item_count = 3,
      .item_index = index,
      .item_offset = 0,
      .show_index = false,
      .show_scroll_bar = false,
  };

refresh_menu:
  screen.item_index = index;
  layout_screen(screen);

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (index > 0) index--;
      goto refresh_menu;
    case KEY_DOWN:
      if (index < 2) index++;
      goto refresh_menu;
    case KEY_CONFIRM:
      *number = num_s[index];
      return true;
    case KEY_CANCEL:
      if (cancel_allowed) {
        return false;
      }
      goto refresh_menu;
    default:
      return false;
  }
}

void protectPinErrorTips(bool retry) {
  char desc[128] = "";
  char times_str[3] = {0};
  snprintf(desc, 128, "%s", _(C__INCORRECT_PIN_STR_ATTEMPT_LEFT_TRY_AGAIN));

  uint8_t remain = 0;
  if (se_getRetryTimes(&remain) != sectrue) {
    remain = 0;
  }

  if (remain > 0) {
    uint2str(remain, times_str);
    bracket_replace(desc, times_str);
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, NULL,
        retry ? &bmp_bottom_right_retry : &bmp_bottom_right_confirm, NULL, NULL,
        NULL, NULL, NULL, NULL, desc);
  } else {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, NULL,
        retry ? &bmp_bottom_right_retry : &bmp_bottom_right_confirm, NULL, NULL,
        NULL, NULL, NULL, NULL,
        _(C__INCORRECT_PIN_0_ATTEMPT_LEFT_DEVICE_WILL_BE_RESET_NOW));
    protectWaitKey(timer1s * 1, 0);

    uint8_t ui_language_bak = ui_language;
    config_wipe();
    if (ui_language_bak) {
      ui_language = ui_language_bak;
    }
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_ok, NULL, &bmp_bottom_right_confirm, NULL, NULL, NULL,
        NULL, NULL, NULL, _(C__DEVICE_RESET_COMPLETE_RESTART_NOW_EXCLAM));
    protectWaitKey(0, 0);
#if !EMULATOR
    svc_system_reset();
#endif
  }
  protectWaitKey(0, 0);

  if ((5 - remain) >= 3 &&
      !(protectAbortedByInitialize || protectAbortedByCancel)) {
    fsm_sendFailure(FailureType_Failure_PinCancelled, NULL);
    memset(desc, 0, 128);
    memset(times_str, 0, 3);
    snprintf(desc, 128, "%s",
             _(C__CAUTION_DEVICE_WILL_BE_RESET_AFTER_STR_MORE_TIME_WRONG));
    uint2str(remain, times_str);
    bracket_replace(desc, times_str);

    uint8_t space_available = 0;
    bool attach_to_pin_used = false;
    if (se_get_pin_passphrase_space(&space_available)) {
      attach_to_pin_used = (space_available < 30);
    }

    bool passphrase_enabled = false;
    config_getPassphraseProtection(&passphrase_enabled);

    if (attach_to_pin_used && !passphrase_enabled) {
      int page = 0;
      char page_indicator[8] = {0};

      while (1) {
        oledClear_ex();

        if (page == 0) {
          snprintf(page_indicator, sizeof(page_indicator), "1/2");
          layoutDialogCenterAdapterV2(
              NULL, &bmp_icon_warning, NULL, &bmp_bottom_right_arrow_off, NULL,
              (const BITMAP *)&bmp_bottom_middle_arrow_down, NULL, NULL, NULL,
              NULL, desc);
        } else {
          snprintf(page_indicator, sizeof(page_indicator), "2/2");
          layoutDialogCenterAdapterV2(
              NULL, NULL, NULL, &bmp_bottom_right_arrow,
              (const BITMAP *)&bmp_bottom_middle_arrow_up, NULL, NULL, NULL,
              NULL, NULL, _(C__YOU_DO_NOT_HAVE_PASSPHRASE_TURNED_ON));
        }

        oledDrawString(OLED_WIDTH / 2 - strlen(page_indicator) * 3,
                       OLED_HEIGHT - 8, page_indicator, FONT_STANDARD);
        oledRefresh();

        uint8_t key = protectWaitKey(0, 0);
        if (key == KEY_CONFIRM) {
          if (page == 0) {
            page = 1;
            continue;
          } else {
            break;
          }
        } else if (key == KEY_DOWN && page == 0) {
          page = 1;
        } else if (key == KEY_UP && page == 1) {
          page = 0;
        }
      }
    } else {
      layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, NULL,
                                  &bmp_bottom_right_arrow, NULL, NULL, NULL,
                                  NULL, NULL, NULL, desc);
      protectWaitKey(0, 0);
    }
  }
}

#if !EMULATOR

void auto_poweroff_timer(void) {
  if (config_getAutoLockDelayMs() == 0) return;
  if (timer_get_sleep_count() >= config_getAutoLockDelayMs()) {
    if (sys_usbState()) {
      timer_sleep_start_reset();
    } else {
      shutdown();
    }
  }
}

void enter_sleep(void) {
  static int sleep_count = 0;
  uint8_t key = KEY_NULL;
  bool unlocked = false;
  uint8_t oled_prev[OLED_BUFSIZE];
  void *layoutBack = NULL;
  sleep_count++;
  if (sleep_count == 1) {
    timer_sleep_start_reset();
    config_getAutoLockDelayMs();  // Cached
    register_timer("poweroff", timer1s, auto_poweroff_timer);
    layoutBack = layoutLast;
    oledBufferLoad(oled_prev);
    if (config_hasPin()) {
      unlocked = session_isUnlocked();
      session_clear(true);
    }
  }

  host_channel = CHANNEL_NULL;
  layoutScreensaver();
  if (sleep_count == 1) {
  sleep_loop:
    device_sleep_state = SLEEP_ENTER;
    key = protectWaitKey(0, 0);
    if (device_sleep_state == SLEEP_REENTER) {
      goto sleep_loop;
    }
    if (key == KEY_NULL) {
      device_sleep_state = SLEEP_NONE;
      sleep_count = 0;
      return;
    }
    if (unlocked) {
    unlocked_loop:
      layoutHomeEx();
      key = protectWaitKey(0, 0);
      if (device_sleep_state == SLEEP_REENTER) {
        goto sleep_loop;
      }
      if (key == KEY_NULL) {
        device_sleep_state = SLEEP_NONE;
        sleep_count = 0;
        return;
      }
      if (!protectPinOnDevice(false, true)) {
        if (device_sleep_state == SLEEP_REENTER) {
          goto sleep_loop;
        }
        if (device_sleep_state == SLEEP_CANCEL_BY_BUTTON) {
          device_sleep_state = SLEEP_ENTER;
          goto unlocked_loop;
        }
        device_sleep_state = SLEEP_NONE;
        layoutHome();
        sleep_count = 0;
        return;
      }
    }
  }
  if (sleep_count > 1) {
    device_sleep_state = SLEEP_REENTER;
  }
  sleep_count--;
  if (sleep_count == 0) {
    layoutLast = layoutBack;
    oledBufferRestore(oled_prev);
    oledRefresh();
    device_sleep_state = SLEEP_NONE;
    return;
  }
}
#endif

enum { MENU_INPUT_PASSPHRASE = 0, MENU_INPUT_SELECT };
enum { INPUT_LOWERCASE = 0, INPUT_CAPITAL, INPUT_NUMS, INPUT_SYMBOLS };
#define INPUT_CONFIRM 0xFF

bool inputPassphraseOnDevice(char *passphrase) {
  char words[MAX_PASSPHRASE_LEN + 1] = {0};
  uint8_t key = KEY_NULL;
  uint8_t input_type = INPUT_LOWERCASE;
  uint8_t menu_status = MENU_INPUT_PASSPHRASE;
  uint8_t counter = 0, index = 0, symbol_index = 0;
  static uint8_t symbol_table[33] = " \'\",./_\?!:;&*$#=+-()[]{}<>@\\^`%|~";
  static uint8_t last_symbol = 0;
  bool ret = false;
  bool d = false;
  config_getInputDirection(&d);

#if !EMULATOR
  enableLongPress(true);
#endif

input_passphrase:
  layoutInputPassphrase(_(T__ENTER_PASSPHRASE), counter, words, index,
                        input_type);
wait_key:
  key = protectWaitKey(0, 0);
#if !EMULATOR
  if (isLongPress(KEY_UP_OR_DOWN) && getLongPressStatus()) {
    if (isLongPress(KEY_UP)) {
      key = KEY_UP;
    } else if (isLongPress(KEY_DOWN)) {
      key = KEY_DOWN;
    }
    delay_ms(75);
  }
  if (d && menu_status == MENU_INPUT_PASSPHRASE) {  // Reverse direction
    if (key == KEY_UP) {
      key = KEY_DOWN;
    } else if (key == KEY_DOWN) {
      key = KEY_UP;
    }
  }
#endif
  if (MENU_INPUT_PASSPHRASE == menu_status) {
    if (index == 0) {
      if (key == KEY_CONFIRM) {
        layoutInputMethod(input_type);
        menu_status = MENU_INPUT_SELECT;
#if !EMULATOR
        enableLongPress(false);
#endif
        goto wait_key;
      }
    }
    switch (key) {
      case KEY_UP:
        if (index == 0) {
          index = INPUT_CONFIRM;
        } else {
          if (INPUT_LOWERCASE == input_type) {
            if (index == INPUT_CONFIRM) {
              index = 'z';
            } else if (index == 'a') {
              index = 0;
            } else {
              index--;
            }
          } else if (INPUT_CAPITAL == input_type) {
            if (index == INPUT_CONFIRM) {
              index = 'Z';
            } else if (index == 'A') {
              index = 0;
            } else {
              index--;
            }
          } else if (INPUT_NUMS == input_type) {
            if (index == INPUT_CONFIRM) {
              index = '9';
            } else if (index == '0') {
              index = 0;
            } else {
              index--;
            }
          } else {
            if (index == INPUT_CONFIRM) {
              symbol_index = sizeof(symbol_table) - 1;
              index = symbol_table[symbol_index];
            } else if (index == symbol_table[0]) {
              symbol_index = 0;
              index = 0;
            } else {
              symbol_index--;
              index = symbol_table[symbol_index];
            }
          }
        }

        goto input_passphrase;
      case KEY_DOWN:
        if (INPUT_LOWERCASE == input_type) {
          if (index == 0) {
            index = 'a';
          } else if (index == 'z') {
            index = INPUT_CONFIRM;
          } else if (index == INPUT_CONFIRM) {
            index = 0;
          } else {
            index++;
          }
        } else if (INPUT_CAPITAL == input_type) {
          if (index == 0) {
            index = 'A';
          } else if (index == 'Z') {
            index = INPUT_CONFIRM;
          } else if (index == INPUT_CONFIRM) {
            index = 0;
          } else {
            index++;
          }
        } else if (INPUT_NUMS == input_type) {
          if (index == 0) {
            index = '0';
          } else if (index == '9') {
            index = INPUT_CONFIRM;
          } else if (index == INPUT_CONFIRM) {
            index = 0;
          } else {
            index++;
          }
        } else {
          if (index == 0) {
            symbol_index = 0;
            index = symbol_table[symbol_index];
          } else if (index == symbol_table[sizeof(symbol_table) - 1]) {
            symbol_index = 0;
            index = INPUT_CONFIRM;
          } else if (index == INPUT_CONFIRM) {
            symbol_index = 0;
            index = 0;
          } else {
            symbol_index++;
            index = symbol_table[symbol_index];
          }
        }
        goto input_passphrase;
      case KEY_CANCEL:
        if (counter > 0) {
          words[counter--] = 0;
          last_symbol = words[counter];
          words[counter] = 0;
          if (last_symbol >= 'a' && last_symbol <= 'z') {
            input_type = INPUT_LOWERCASE;
            index = last_symbol;
          } else if (last_symbol >= 'A' && last_symbol <= 'Z') {
            input_type = INPUT_CAPITAL;
            index = last_symbol;
          } else if (last_symbol >= '0' && last_symbol <= '9') {
            input_type = INPUT_NUMS;
            index = last_symbol;
          } else {
            input_type = INPUT_SYMBOLS;
            symbol_index = 0;
            for (int i = 0; i < 32 /*sizeof(symbol_table) - 1*/; i++) {
              if (symbol_table[i] == last_symbol) {
                symbol_index = i;
                break;
              }
            }
            index = symbol_table[symbol_index];
          }
        } else {
          ret = false;
          goto __ret;
        }
        goto input_passphrase;
      case KEY_CONFIRM:
        if (index == INPUT_CONFIRM) {
          strlcpy(passphrase, words, sizeof(words));
          ret = true;
          goto __ret;
        }
        if (counter < MAX_PASSPHRASE_LEN) {
          words[counter++] = index;
          if (counter == MAX_PASSPHRASE_LEN) {
            strlcpy(passphrase, words, sizeof(words));
            ret = true;
            goto __ret;
          }
        }
        if (INPUT_LOWERCASE == input_type) {
          index = 'a';
        } else if (INPUT_CAPITAL == input_type) {
          index = 'A';
        } else if (INPUT_NUMS == input_type) {
          index = '0';
        } else {
          symbol_index = 0;
          index = symbol_table[symbol_index];
        }
        goto input_passphrase;
      default:
        break;
    }
  }
  if (MENU_INPUT_SELECT == menu_status) {
    switch (key) {
      case KEY_UP:
        if (input_type > 0) input_type--;
        layoutInputMethod(input_type);
        goto wait_key;
      case KEY_DOWN:
        if (input_type < 3) input_type++;
        layoutInputMethod(input_type);
        goto wait_key;
      case KEY_CANCEL:
      case KEY_CONFIRM:
        menu_status = MENU_INPUT_PASSPHRASE;
        if (INPUT_LOWERCASE == input_type) {
          index = 'a';
        } else if (INPUT_CAPITAL == input_type) {
          index = 'A';
        } else if (INPUT_NUMS == input_type) {
          index = '0';
        } else {
          symbol_index = 0;
          index = symbol_table[symbol_index];
        }
#if !EMULATOR
        enableLongPress(true);
#endif
        goto input_passphrase;
      default:
        break;
    }
  }

__ret:
#if !EMULATOR
  enableLongPress(false);
#endif
  return ret;
}

bool inputPassphraseOnDeviceRequired(char *passphrase) {
  char words[MAX_PASSPHRASE_LEN + 1] = {0};
  uint8_t key = KEY_NULL;
  uint8_t input_type = INPUT_LOWERCASE;
  uint8_t menu_status = MENU_INPUT_PASSPHRASE;
  uint8_t counter = 0, index = 0, symbol_index = 0;
  static uint8_t symbol_table[33] = " \'\",./_\?!:;&*$#=+-()[]{}<>@\\^`%|~";
  static uint8_t last_symbol = 0;
  (void)last_symbol;  // Suppress unused variable warning
  bool ret = false;
  bool d = false;
  config_getInputDirection(&d);

#if !EMULATOR
  enableLongPress(true);
#endif

input_passphrase:
  layoutInputPassphrase(_(T__ENTER_PASSPHRASE), counter, words, index,
                        input_type);
wait_key:
  key = protectWaitKey(0, 0);
#if !EMULATOR
  if (isLongPress(KEY_UP_OR_DOWN) && getLongPressStatus()) {
    if (isLongPress(KEY_UP)) {
      key = KEY_UP;
    } else if (isLongPress(KEY_DOWN)) {
      key = KEY_DOWN;
    }
    delay_ms(75);
  }
  if (d && menu_status == MENU_INPUT_PASSPHRASE) {  // Reverse direction
    if (key == KEY_UP) {
      key = KEY_DOWN;
    } else if (key == KEY_DOWN) {
      key = KEY_UP;
    }
  }
#endif
  if (MENU_INPUT_PASSPHRASE == menu_status) {
    if (index == 0) {
      if (key == KEY_CONFIRM) {
        layoutInputMethod(input_type);
        menu_status = MENU_INPUT_SELECT;
#if !EMULATOR
        enableLongPress(false);
#endif
        goto wait_key;
      }
    }
    switch (key) {
      case KEY_UP:
        if (index == 0) {
          if (counter > 0) {
            index = INPUT_CONFIRM;
          } else {
            if (INPUT_LOWERCASE == input_type) {
              index = 'z';
            } else if (INPUT_CAPITAL == input_type) {
              index = 'Z';
            } else if (INPUT_NUMS == input_type) {
              index = '9';
            } else {
              index = symbol_table[sizeof(symbol_table) - 1];
              symbol_index = sizeof(symbol_table) - 1;
            }
          }
        } else {
          if (INPUT_LOWERCASE == input_type) {
            if (index == INPUT_CONFIRM) {
              index = 'z';
            } else if (index == 'a') {
              index = 0;
            } else {
              index--;
            }
          } else if (INPUT_CAPITAL == input_type) {
            if (index == INPUT_CONFIRM) {
              index = 'Z';
            } else if (index == 'A') {
              index = 0;
            } else {
              index--;
            }
          } else if (INPUT_NUMS == input_type) {
            if (index == INPUT_CONFIRM) {
              index = '9';
            } else if (index == '0') {
              index = 0;
            } else {
              index--;
            }
          } else {
            if (index == INPUT_CONFIRM) {
              index = symbol_table[sizeof(symbol_table) - 1];
              symbol_index = sizeof(symbol_table) - 1;
            } else {
              for (uint32_t i = 0; i < sizeof(symbol_table); i++) {
                if (symbol_table[i] == index) {
                  symbol_index = i;
                  break;
                }
              }
              if (symbol_index == 0) {
                symbol_index = 0;
                index = 0;
              } else {
                symbol_index--;
                index = symbol_table[symbol_index];
              }
            }
          }
        }
        goto input_passphrase;
      case KEY_DOWN:
        if (INPUT_LOWERCASE == input_type) {
          if (index == 0) {
            index = 'a';
          } else if (index == 'z') {
            if (counter > 0) {
              index = INPUT_CONFIRM;
            } else {
              index = 0;
            }
          } else if (index == INPUT_CONFIRM) {
            index = 0;
          } else {
            index++;
          }
        } else if (INPUT_CAPITAL == input_type) {
          if (index == 0) {
            index = 'A';
          } else if (index == 'Z') {
            if (counter > 0) {
              index = INPUT_CONFIRM;
            } else {
              index = 0;
            }
          } else if (index == INPUT_CONFIRM) {
            index = 0;
          } else {
            index++;
          }
        } else if (INPUT_NUMS == input_type) {
          if (index == 0) {
            index = '0';
          } else if (index == '9') {
            if (counter > 0) {
              index = INPUT_CONFIRM;
            } else {
              index = 0;
            }
          } else if (index == INPUT_CONFIRM) {
            index = 0;
          } else {
            index++;
          }
        } else {
          if (index == 0) {
            symbol_index = 0;
            index = symbol_table[symbol_index];
          } else if (index == symbol_table[sizeof(symbol_table) - 1]) {
            if (counter > 0) {
              symbol_index = 0;
              index = INPUT_CONFIRM;
            } else {
              symbol_index = 0;
              index = 0;
            }
          } else if (index == INPUT_CONFIRM) {
            symbol_index = 0;
            index = 0;
          } else {
            symbol_index++;
            if (symbol_index >= sizeof(symbol_table)) {
              symbol_index = sizeof(symbol_table) - 1;
            }
            index = symbol_table[symbol_index];
          }
        }
        goto input_passphrase;
      case KEY_CONFIRM:

        if (index == INPUT_CONFIRM) {
          if (counter > 0) {
            ret = true;
            goto __ret_required;
          } else {
          }
        } else {
          if (counter < MAX_PASSPHRASE_LEN) {
            words[counter] = index;
            counter++;
            words[counter] = '\0';

            if (counter == MAX_PASSPHRASE_LEN) {
              ret = true;
              goto __ret_required;
            }
          }
          if (INPUT_LOWERCASE == input_type) {
            index = 'a';
          } else if (INPUT_CAPITAL == input_type) {
            index = 'A';
          } else if (INPUT_NUMS == input_type) {
            index = '0';
          } else {
            symbol_index = 0;
            index = symbol_table[symbol_index];
          }
        }
        goto input_passphrase;
      case KEY_CANCEL:

        if (counter) {
          counter--;
          words[counter] = '\0';

          if (INPUT_LOWERCASE == input_type) {
            index = 'a';
          } else if (INPUT_CAPITAL == input_type) {
            index = 'A';
          } else if (INPUT_NUMS == input_type) {
            index = '0';
          } else {
            symbol_index = 0;
            index = symbol_table[symbol_index];
          }
        } else {
          ret = false;
          goto __ret_required;
        }
        goto input_passphrase;
      default:
        break;
    }
  } else if (MENU_INPUT_SELECT == menu_status) {
    switch (key) {
      case KEY_UP:
        if (input_type == 0) {
          input_type = 3;
        } else {
          input_type--;
        }
        layoutInputMethod(input_type);
        goto wait_key;
      case KEY_DOWN:
        if (input_type == 3) {
          input_type = 0;
        } else {
          input_type++;
        }
        layoutInputMethod(input_type);
        goto wait_key;
      case KEY_CONFIRM:
        last_symbol = input_type;
        menu_status = MENU_INPUT_PASSPHRASE;
        goto input_passphrase;
      case KEY_CANCEL:

        menu_status = MENU_INPUT_PASSPHRASE;
        goto input_passphrase;
      default:

        break;
    }
  } else {
  }

  goto wait_key;

__ret_required:

  strlcpy(passphrase, words, MAX_PASSPHRASE_LEN + 1);

#if !EMULATOR
  enableLongPress(false);
#endif
  return ret;
}

bool protectPassphraseOnDevice(char *passphrase) {
  ButtonRequest resp = {0};
  bool result = false;
  bool timeout_flag = true;

  memzero(passphrase, MAX_PASSPHRASE_LEN + 1);
  bool passphrase_protection = false;
  config_getPassphraseProtection(&passphrase_protection);
  if (!passphrase_protection) {
    return true;
  }

  protectAbortedByTimeout = false;

  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_PassphraseEntry;
  usbTiny(1);
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  timer_out_set(timer_out_oper, default_oper_time);

  while (timer_out_get(timer_out_oper)) {
    usbPoll();

    if (msg_tiny_id == MessageType_MessageType_ButtonAck) {
      msg_tiny_id = 0xFFFF;
      result = true;
      timeout_flag = false;
      break;
    }

    protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
    protectAbortedByInitialize =
        (msg_tiny_id == MessageType_MessageType_Initialize);
    if (protectAbortedByCancel || protectAbortedByInitialize) {
      msg_tiny_id = 0xFFFF;
      timeout_flag = false;
      result = false;
      break;
    }
  }
  timer_out_set(timer_out_oper, 0);
  usbTiny(0);
  if (timeout_flag) protectAbortedByTimeout = true;

  if (result) {
    if (false == inputPassphraseOnDevice(passphrase)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    }
    return true;
  }
  return false;
}
