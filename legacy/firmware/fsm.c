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

#include <stdio.h>
#include "address.h"
#include "aes/aes.h"
#include "base58.h"
#include "bip32.h"
#include "bip39.h"
#include "ble.h"
#include "buttons.h"
#include "coins.h"
#include "common.h"
#include "config.h"
#include "crypto.h"
#include "ctype.h"
#include "curves.h"
#include "debug.h"
#include "ecdsa.h"
#include "fsm.h"
#include "fw_signatures.h"
#include "gettext.h"
#include "hmac.h"
#include "layout2.h"
#include "memory.h"
#include "memzero.h"
#include "messages.h"
#include "messages.pb.h"
#include "oled.h"
#include "pinmatrix.h"
#include "protect.h"
#include "recovery.h"
#include "reset.h"
#include "rng.h"
#include "secp256k1.h"
#include "si2c.h"
#include "signing.h"
#include "supervise.h"
#include "sys.h"
#include "timer.h"
#include "transaction.h"
#include "trezor.h"
#include "usb.h"
#include "util.h"

#include "rtt_log.h"

#include "se_chip.h"

#if !BITCOIN_ONLY
#include "ada.h"
#include "alephium.h"
#include "algorand.h"
#include "aptos.h"
#include "benfen.h"
#include "cardano.h"
#include "conflux.h"
#include "cosmos.h"
#include "ethereum.h"
#include "ethereum_definitions.h"
#include "ethereum_networks.h"
#include "ethereum_onekey.h"
#include "filecoin.h"
#include "kaspa.h"
#include "lnurl.h"
#include "near.h"
#include "nem.h"
#include "nem2.h"
#include "neo.h"
#include "nervos.h"
#include "nexa.h"
#include "nostr.h"
#include "polkadot.h"
#include "ripple.h"
#include "scdo.h"
#include "solana.h"
#include "starcoin.h"
#include "stellar.h"
#include "sui.h"
#include "ton.h"
#include "tron.h"
#endif
#include "bip322_simple/bip322_simple.h"
#include "psbt/psbt.h"
#if EMULATOR
#include <stdio.h>
#endif

// message methods

static uint8_t msg_resp[MSG_OUT_DECODED_SIZE] __attribute__((aligned));

// Authorization message type triggered by DoPreauthorized.
static MessageType authorization_type = 0;

static uint32_t unlock_path = 0;

#define RESP_INIT(TYPE)                                                    \
  TYPE *resp = (TYPE *)(void *)msg_resp;                                   \
  _Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
  memzero(resp, sizeof(TYPE));

#if EMULATOR
#define CHECK_INITIALIZED                                      \
  if (config_getMnemonicsImported()) {                         \
    fsm_sendFailure(FailureType_Failure_ProcessError,          \
                    "device is already used for backup");      \
    return;                                                    \
  }                                                            \
  if (!config_isInitialized()) {                               \
    fsm_sendFailure(FailureType_Failure_NotInitialized, NULL); \
    return;                                                    \
  }
#else
#define CHECK_INITIALIZED                                      \
  if (!config_isInitialized()) {                               \
    fsm_sendFailure(FailureType_Failure_NotInitialized, NULL); \
    return;                                                    \
  }
#endif

#if EMULATOR
#define CHECK_NOT_INITIALIZED                                          \
  if (config_getMnemonicsImported()) {                                 \
    fsm_sendFailure(FailureType_Failure_ProcessError,                  \
                    "device is already used for backup");              \
    return;                                                            \
  }                                                                    \
  if (config_isInitialized()) {                                        \
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,             \
                    "Device is already initialized. Use Wipe first."); \
    return;                                                            \
  }
#else
#define CHECK_NOT_INITIALIZED                                          \
  if (config_isInitialized()) {                                        \
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,             \
                    "Device is already initialized. Use Wipe first."); \
    return;                                                            \
  }
#endif

#define CHECK_PIN          \
  if (!protectPin(true)) { \
    layoutHome();          \
    return;                \
  }

#define CHECK_PIN_UNCACHED  \
  if (!protectPin(false)) { \
    layoutHome();           \
    return;                 \
  }

#define CHECK_UNLOCKED                                           \
  if (!session_isUnlocked()) {                                   \
    fsm_sendFailure(FailureType_Failure_ProcessError, "Locked"); \
    layoutHome();                                                \
    return;                                                      \
  }

#define CHECK_PARAM(cond, errormsg)                             \
  if (!(cond)) {                                                \
    fsm_sendFailure(FailureType_Failure_DataError, (errormsg)); \
    layoutHome();                                               \
    return;                                                     \
  }

bool button_request(const ButtonRequestType code) {
  bool result = false;
  ButtonRequest resp = {0};
  resp.has_code = true;
  resp.code = code;
  usbTiny(1);
  buttonUpdate();  // Clear button state
  msg_write(MessageType_MessageType_ButtonRequest, &resp);
  for (;;) {
    usbPoll();

    // check for ButtonAck
    if (msg_tiny_id == MessageType_MessageType_ButtonAck) {
      msg_tiny_id = 0xFFFF;
      result = true;
      break;
    }

    // check for Cancel / Initialize
    protectAbortedByCancel = (msg_tiny_id == MessageType_MessageType_Cancel);
    protectAbortedByInitialize =
        (msg_tiny_id == MessageType_MessageType_Initialize);
    if (protectAbortedByCancel || protectAbortedByInitialize) {
      msg_tiny_id = 0xFFFF;
      result = false;
      break;
    }
  }
  usbTiny(0);
  return result;
}

void fsm_sendSuccess(const char *text) {
  RESP_INIT(Success);
  if (text) {
    resp->has_message = true;
    strlcpy(resp->message, text, sizeof(resp->message));
  }
  msg_write(MessageType_MessageType_Success, resp);
}

#if DEBUG_LINK
void fsm_sendFailureDebug(FailureType code, const char *text,
                          const char *source)
#else
void fsm_sendFailure(FailureType code, const char *text)
#endif
{
  if (protectAbortedByCancel) {
    protectAbortedByCancel = false;
  }
  if (protectAbortedByInitialize) {
    fsm_msgInitialize((Initialize *)0);
    protectAbortedByInitialize = false;
    return;
  }
  RESP_INIT(Failure);
  resp->has_code = true;
  resp->code = code;
  if (!text) {
    switch (code) {
      case FailureType_Failure_UnexpectedMessage:
        text = "Unexpected message";
        break;
      case FailureType_Failure_ButtonExpected:
        text = "Button expected";
        break;
      case FailureType_Failure_DataError:
        text = "Data error";
        break;
      case FailureType_Failure_ActionCancelled:
        text = "Action cancelled by user";
        break;
      case FailureType_Failure_PinExpected:
        text = "PIN expected";
        break;
      case FailureType_Failure_PinCancelled:
        text = "PIN cancelled";
        break;
      case FailureType_Failure_PinInvalid:
        text = "PIN invalid";
        break;
      case FailureType_Failure_InvalidSignature:
        text = "Invalid signature";
        break;
      case FailureType_Failure_ProcessError:
        text = "Process error";
        break;
      case FailureType_Failure_NotEnoughFunds:
        text = "Not enough funds";
        break;
      case FailureType_Failure_NotInitialized:
        text = "Device not initialized";
        break;
      case FailureType_Failure_PinMismatch:
        text = "PIN mismatch";
        break;
      case FailureType_Failure_WipeCodeMismatch:
        text = "Wipe code mismatch";
        break;
      case FailureType_Failure_InvalidSession:
        text = "Invalid session";
        break;
      case FailureType_Failure_BatteryLow:
        text = "Battery low";
        break;
      case FailureType_Failure_FirmwareError:
        text = "Firmware error";
        break;
    }
  }
#if DEBUG_LINK
  resp->has_message = true;
  strlcpy(resp->message, source, sizeof(resp->message));
  if (text) {
    strlcat(resp->message, text, sizeof(resp->message));
  }
#else
  if (text) {
    resp->has_message = true;
    strlcpy(resp->message, text, sizeof(resp->message));
  }
#endif
  msg_write(MessageType_MessageType_Failure, resp);
}

static const CoinInfo *fsm_getCoin(bool has_name, const char *name) {
  const CoinInfo *coin = NULL;
  if (has_name) {
    coin = coinByName(name);
  } else {
    coin = coinByName("Bitcoin");
  }
  if (!coin) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid coin name");
    layoutHome();
    return 0;
  }
  return coin;
}

HDNode *fsm_getDerivedNode(const char *curve, const uint32_t *address_n,
                           size_t address_n_count, uint32_t *fingerprint) {
  static CONFIDENTIAL HDNode node;
  if (fingerprint) {
    *fingerprint = 0;
  }
#if EMULATOR
  if (!config_getRootNode(&node, curve)) {
    layoutHome();
    return 0;
  }
  if (!address_n || address_n_count == 0) {
    return &node;
  }
  if (hdnode_private_ckd_cached(&node, address_n, address_n_count,
                                fingerprint) == 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to derive private key");
    layoutHome();
    return 0;
  }
#else
  if (!config_genSessionSeed()) {
    layoutHome();
    return 0;
  }
  if (!se_derive_keys(&node, curve, address_n, address_n_count, fingerprint)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to derive private key");
    layoutHome();
    return 0;
  }
#endif
  return &node;
}

static bool fsm_getSlip21Key(const char *path[], size_t path_count,
                             uint8_t key[32]) {
#if EMULATOR
  const uint8_t *seed = config_getSeed();
  if (seed == NULL) {
    return false;
  }
  static CONFIDENTIAL Slip21Node node;
  slip21_from_seed(seed, 64, &node);
  for (size_t i = 0; i < path_count; ++i) {
    slip21_derive_path(&node, (uint8_t *)path[i], strlen(path[i]));
  }
  memcpy(key, slip21_key(&node), 32);
  memzero(&node, sizeof(node));
#else
  static CONFIDENTIAL Slip21Node node;
  // slip21_from_seed(NULL, 0, &node);
  se_slip21_node(node.data);
  for (size_t i = 0; i < path_count; ++i) {
    slip21_derive_path(&node, (uint8_t *)path[i], strlen(path[i]));
  }
  memcpy(key, slip21_key(&node), 32);
  memzero(&node, sizeof(node));
#endif

  return true;
}

static bool fsm_layoutAddress(const char *address, const char *address_type,
                              const char *desc, bool ignorecase,
                              size_t prefixlen, const uint32_t *address_n,
                              size_t address_n_count, bool address_is_account,
                              const MultisigRedeemScriptType *multisig,
                              int multisig_index, uint32_t multisig_xpub_magic,
                              const CoinInfo *coin) {
  (void)prefixlen;
  uint8_t key = KEY_NULL;
  int screen = 0, screens = 3;
  if (multisig) {
    screens += cryptoMultisigPubkeyCount(multisig);
  }
  if (!button_request(ButtonRequestType_ButtonRequest_Address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return false;
  }
  for (;;) {
    key = KEY_NULL;
    switch (screen) {
      case 0: {  // show address
        key = layoutAddress(address, address_type, desc, false, false,
                            ignorecase, address_n, address_n_count,
                            address_is_account, multisig != NULL);
        if (protectAbortedByInitialize) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          return false;
        }
        break;
      }
      case 1: {
        layoutAddress(address, address_type, desc, false, true, ignorecase,
                      address_n, address_n_count, address_is_account,
                      multisig != NULL);
        break;
      }
      case 2: {
        layoutAddress(address, address_type, desc, true, false, ignorecase,
                      address_n, address_n_count, address_is_account,
                      multisig != NULL);
        break;
      }
      default: {  // show XPUBs
        int index = screen - 3;
        char xpub[XPUB_MAXLEN] = {0};
        const HDNodeType *node_ptr = NULL;
        if (multisig->nodes_count) {  // use multisig->nodes
          node_ptr = &(multisig->nodes[index]);
        } else if (multisig->pubkeys_count) {  // use multisig->pubkeys
          node_ptr = &(multisig->pubkeys[index].node);
        }

        if (!node_ptr) {
          strlcat(xpub, "ERROR", sizeof(xpub));
        } else {
          HDNode node;
          if (!hdnode_from_xpub(node_ptr->depth, node_ptr->child_num,
                                node_ptr->chain_code.bytes,
                                node_ptr->public_key.bytes, coin->curve_name,
                                &node)) {
            strlcat(xpub, "ERROR", sizeof(xpub));
          } else {
            hdnode_serialize_public(&node, node_ptr->fingerprint,
                                    multisig_xpub_magic, xpub, sizeof(xpub));
          }
        }
        key = layoutXPUBMultisig(desc, xpub, index, 0, multisig_index == index,
                                 screen == (screens - 1));
      }
    }

    if ((key == KEY_NULL) && (!protectAbortedBySleep)) {
      key = protectWaitKey(0, 1);
      if (protectAbortedByInitialize) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        return false;
      }
    }

    if (key == KEY_CONFIRM) {
      if (multisig) {
        if ((screen == (screens - 1)) || (screen == 2)) {
          return true;
        }
        screen++;
        if (screen == 2) screen++;
      } else {
        if (screen == 1 || screen == 2) {
          return true;
        }
        screen++;
      }
    } else {
      if (!multisig) {
        if (screen == 0)
          screen = 2;
        else if (screen == 1)
          screen = 2;
        else if (screen == 2)
          screen = 0;
      } else {
        if (screen == 0)
          screen = 2;
        else if (screen == 1)
          screen = 2;
        else if (screen == 2)
          screen = 0;
        else {
          screen--;
          if (screen == 2) screen--;
        }
      }
    }

    if (protectAbortedByCancel || protectAbortedByInitialize) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return false;
    } else if (protectAbortedByTimeout) {
      layoutHome();
      return false;
    } else if (protectAbortedBySleep) {
      protectAbortedBySleep = false;
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return false;
#if !EMULATOR
    } else if ((host_channel == CHANNEL_USB) && ((sys_usbState() == false))) {
      layoutHome();
      return false;
#endif
    }
  }
}

static bool fsm_layoutPaginated(const char *description, const uint8_t *msg,
                                uint32_t len, bool is_ascii) {
  const char **str = NULL;
  const uint32_t row_len = is_ascii ? 18 : 8;
  do {
    const uint32_t show_len = MIN(len, row_len * 4);
    if (is_ascii) {
      str = split_message(msg, show_len, row_len);
    } else {
      str = split_message_hex(msg, show_len);
    }

    msg += show_len;
    len -= show_len;

    const char *label = len > 0 ? "Next" : "Confirm";
    layoutDialogSwipeEx(&bmp_icon_question, "Cancel", label, description,
                        str[0], str[1], str[2], str[3], NULL, NULL, FONT_FIXED);
    if (!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
      return false;
    }
  } while (len > 0);

  return true;
}

bool fsm_layoutSignMessage(const char *chain_name, const char *signer,
                           const uint8_t *msg, uint32_t len) {
  if (is_printable(msg, len)) {
    return layoutSignMessage(chain_name, false, signer, msg, len, true, NULL,
                             NULL, false);
  } else {
    return layoutSignMessage(chain_name, false, signer, msg, len, false, NULL,
                             NULL, false);
  }
}

bool fsm_layoutVerifyMessage(const char *chain_name, const char *signer,
                             const uint8_t *msg, uint32_t len) {
  if (is_printable(msg, len)) {
    return layoutSignMessage(chain_name, true, signer, msg, len, true, NULL,
                             NULL, false);
  } else {
    return layoutSignMessage(chain_name, true, signer, msg, len, false, NULL,
                             NULL, false);
  }
}

bool fsm_layoutSignHash(const char *chain_name, const char *signer,
                        const char *domain_hash, const char *message_hash,
                        const char *warning) {
  return layoutSignHash(chain_name, false, signer, domain_hash, message_hash,
                        warning);
}

bool fsm_layoutVerifyHash(const char *chain_name, const char *signer,
                          const char *domain_hash, const char *message_hash,
                          const char *warning) {
  return layoutSignHash(chain_name, true, signer, domain_hash, message_hash,
                        warning);
}

bool fsm_layoutCommitmentData(const uint8_t *msg, uint32_t len) {
  if (is_valid_ascii(msg, len)) {
    return fsm_layoutPaginated("Commitment data", msg, len, true);
  } else {
    return fsm_layoutPaginated("Binary commitment data", msg, len, false);
  }
}

void fsm_msgRebootToBootloader(void) {
  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"), NULL,
                    __("Do you want to"), __("restart device in"),
                    __("bootloader mode?"), NULL, NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  oledClear();
  oledRefresh();
  fsm_sendSuccess("Rebooting");
  // make sure the outgoing message is sent
  usbFlush(500);
#if !EMULATOR
  svc_reboot_to_bootloader();
#else
  printf("Reboot!\n");
#endif
}

void fsm_abortWorkflows(void) {
  recovery_abort();
  signing_abort();
  authorization_type = 0;
  unlock_path = 0;
#if !BITCOIN_ONLY
  ethereum_signing_abort();
  stellar_signingAbort();
#endif
}

void fsm_postMsgCleanup(MessageType message_type) {
  if (message_type != MessageType_MessageType_DoPreauthorized) {
    authorization_type = 0;
  }

  if (message_type != MessageType_MessageType_UnlockPath) {
    unlock_path = 0;
  }
}

bool fsm_layoutPathWarning(uint32_t address_n_count,
                           const uint32_t *address_n) {
  char desc[128] = {0};
  strlcpy(desc, _(C__STR_IS_A_NON_STANDARD_PATH_USE_THIS_PATH_QUES), 120);
  bracket_replace(desc, address_n_str(address_n, address_n_count, false));
  layoutDialogAdapterEx(_(T__CHECK_PATH), &bmp_bottom_left_close, NULL,
                        &bmp_bottom_right_confirm, NULL, desc, NULL, NULL, NULL,
                        NULL);

  if (protectWaitKeyValue(ButtonRequestType_ButtonRequest_UnknownDerivationPath,
                          true, 0, 1) != KEY_CONFIRM) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    return false;
  }
  return true;
}

bool fsm_common_path_check(const uint32_t *address_n, uint32_t address_n_count,
                           uint32_t slip44_id, const char *curve_name,
                           bool strict) {
  if (address_n == NULL || curve_name == NULL) {
    return false;
  }
  if (address_n_count < 3) {
    return false;
  }
  bool purpose_is_hardened = (address_n[0] & PATH_HARDENED) != 0;
  bool coin_type_is_expected = (address_n[1] == (slip44_id | PATH_HARDENED));
  bool account_is_hardened = (address_n[2] & PATH_HARDENED) != 0;
  if (!purpose_is_hardened || !coin_type_is_expected || !account_is_hardened) {
    return false;
  }
  if (strict) {
    if ((address_n[0] != (44 | PATH_HARDENED))) {
      return false;
    }
  }
  if (strcmp(curve_name, ED25519_NAME) == 0) {
    for (uint32_t i = 3; i < address_n_count; i++) {
      if ((address_n[i] & PATH_HARDENED) == 0) {
        return false;
      }
    }
  }
  return true;
}

#include "fsm_msg_coin.h"
#include "fsm_msg_common.h"
#include "fsm_msg_crypto.h"
#include "fsm_msg_debug.h"

#if !BITCOIN_ONLY

#include "fsm_msg_ada.h"
#include "fsm_msg_alephium.h"
#include "fsm_msg_algorand.h"
#include "fsm_msg_aptos.h"
#include "fsm_msg_benfen.h"
#include "fsm_msg_conflux.h"
#include "fsm_msg_cosmos.h"
#include "fsm_msg_ethereum.h"
#include "fsm_msg_ethereum_onekey.h"
#include "fsm_msg_filecoin.h"
#include "fsm_msg_kaspa.h"
#include "fsm_msg_lnurl.h"
#include "fsm_msg_near.h"
#include "fsm_msg_nem.h"
#include "fsm_msg_neo.h"
#include "fsm_msg_nervos.h"
#include "fsm_msg_nexa.h"
#include "fsm_msg_nostr.h"
#include "fsm_msg_polkadot.h"
#include "fsm_msg_ripple.h"
#include "fsm_msg_scdo.h"
#include "fsm_msg_solana.h"
#include "fsm_msg_starcoin.h"
#include "fsm_msg_stellar.h"
#include "fsm_msg_sui.h"
#include "fsm_msg_ton.h"
#include "fsm_msg_tron.h"
#include "fsm_msg_webauthn.h"

#endif
