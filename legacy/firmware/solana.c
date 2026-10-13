/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2021 OneKey Team <core@onekey.so>
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
#include "solana.h"
#include <stdio.h>
#include "buttons.h"
#include "config.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "sol/message.h"
#include "sol/printer.h"
#include "sol/transaction_summary.h"
#include "util.h"

static const uint8_t _SIGN_DOMAIN[] =
    "\xff"
    "solana offchain";
static const uint8_t _SIGNER_COUNT = 1;
#define _SIGN_DOMAIN_LENGTH (sizeof(_SIGN_DOMAIN) - 1)
#define _APPLICATION_DOMAIN_LENGTH (32)
#define _PREAMBLE_LENGTH                                          \
  (_SIGN_DOMAIN_LENGTH + 1 + _APPLICATION_DOMAIN_LENGTH + 1 + 1 + \
   _SIGNER_COUNT * SIZE_PUBKEY + 2)
#define _MAX_MESSAGE_LENGTH_WITH_PREAMBLE (1232)
#define _MAX_MESSAGE_LENGTH \
  (_MAX_MESSAGE_LENGTH_WITH_PREAMBLE - _PREAMBLE_LENGTH)
#define _MAX_REQUIRED_SIGNERS                                   \
  (sizeof(((SolanaSignOffChainMessage *)0)->required_signers) / \
   sizeof(((SolanaSignOffChainMessage *)0)->required_signers[0]))

void solana_get_address_from_public_key(const uint8_t *public_key,
                                        char *address) {
  encode_base58(public_key, SIZE_PUBKEY, address, BASE58_PUBKEY_LENGTH);
}

void solana_sign_tx(const SolanaSignTx *msg, const HDNode *node,
                    SolanaSignedTx *resp) {
  Parser parser = {msg->raw_tx.bytes, msg->raw_tx.size};
  MessageHeader header;
  if (parse_message_header(&parser, &header)) {
    // This is not a valid Solana message
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid message");
    return;
  } else {
    uint8_t signer_pubkey[SIZE_PUBKEY];
    memcpy(signer_pubkey, &node->public_key[1], SIZE_PUBKEY);
    size_t signer_count = header.pubkeys_header.num_required_signatures;
    size_t i;
    for (i = 0; i < signer_count; i++) {
      const Pubkey *pubkey = &header.pubkeys[i];
      if (memcmp(pubkey, signer_pubkey, PUBKEY_SIZE) == 0) {
        break;
      }
    }
    if (i >= signer_count) {
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid params");
      return;
    }
  }
  transaction_summary_reset();
  PrintConfig print_config = {.header = header,
                              .expert_mode = true,
                              .signer_pubkey = &header.pubkeys[0]};
  if (process_message_body(parser.buffer, parser.buffer_length,
                           &print_config)) {
    if (config_getCoinSwitch(COIN_SWITCH_SOLANA)) {
      SummaryItem *item = transaction_summary_primary_item();
      summary_item_set_string(item, "Unrecognized", "format");
      struct SHA3_CTX ctx = {0};
      sha3_256_Init(&ctx);
      sha3_Update(&ctx, parser.buffer, parser.buffer_length);
      Hash UnrecognizedMessageHash;
      keccak_Final(&ctx, (uint8_t *)&UnrecognizedMessageHash);

      item = transaction_summary_general_item();
      summary_item_set_hash(item, "Message Hash", &UnrecognizedMessageHash);
    } else {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Please confirm the BlindSign enabled");
      return;
    }
  }
  // Set fee-payer if it hasn't already been resolved by
  // the transaction printer
  transaction_summary_set_fee_payer_pubkey(&header.pubkeys[0]);

  enum SummaryItemKind summary_step_kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
  size_t num_summary_steps = 0;
  size_t steps = 0;
  uint8_t steps_list[MAX_TRANSACTION_SUMMARY_ITEMS];

  const char **tx_msg = format_tx_message("Solana");
  if (transaction_summary_finalize(summary_step_kinds, &num_summary_steps) ==
      0) {
    char desc[64] = {0};
    for (size_t i = 0; i < num_summary_steps; i++) {
      if (transaction_summary_display_item(i, DisplayFlagAll)) {
        fsm_sendFailure(FailureType_Failure_DataError, "Parse error");
        return;
      } else {
        char *title = G_transaction_summary_title;
        char *text = G_transaction_summary_text;

        if (strcmp(title, "Create token acct") == 0) {
          continue;
        } else if (strcmp(title, "From mint") == 0) {
          continue;
        } else if (strcmp(title, "From") == 0) {
          continue;
        } else if (strcmp(title, "To") == 0) {
          continue;
        } else if (strcmp(title, "Funded by") == 0) {
          continue;
        } else if (strcmp(title, "Max fees") == 0) {
          continue;
        } else if (strcmp(title, "Owned by") == 0) {
          continue;
        } else if (strcmp(title, "Token Sender") == 0) {
          title = "From (Token Account)";
        } else if (strcmp(title, "Token Recipient") == 0) {
          title = "To (Token Account)";
        } else if (strcmp(title, "Owner") == 0) {
          continue;
        } else if (strcmp(title, "Sender") == 0) {
          title = "From";
        } else if (strcmp(title, "Recipient") == 0) {
          title = "Send to";
        } else if (strcmp(title, "Transfer tokens") == 0 ||
                   strcmp(title, "Transfer") == 0) {
          title = "Amount";
        }

        snprintf(desc, sizeof(desc), "%s:", title);

        steps_list[steps++] = i;

        layoutDialogAdapterEx(
            tx_msg[0], &bmp_bottom_left_close, NULL,
            i < num_summary_steps - 1 ? &bmp_bottom_right_arrow
                                      : &bmp_bottom_right_confirm,
            NULL, NULL, gettext_from_en(desc), text, NULL, NULL);

        uint8_t key;
      button_scan:
        key = protectWaitKeyValue(ButtonRequestType_ButtonRequest_ProtectCall,
                                  true, 0, 0);
        if (key == KEY_CANCEL) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          return;
        } else if (key == KEY_UP) {
          if (steps == 1) {
            goto button_scan;
          } else {
            i = steps_list[steps - 2] - 1;
            steps -= 2;
          }
        } else if (key == KEY_DOWN) {
          if (i == num_summary_steps - 1) {
            goto button_scan;
          }
        } else if (key == KEY_NULL) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          return;
        }
      }
    }
    oledClear_ex();
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, 13, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
    oledRefresh();
    if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return;
    }
#if EMULATOR
    ed25519_sign(msg->raw_tx.bytes, msg->raw_tx.size, node->private_key,
                 resp->signature.bytes);
#else
    hdnode_sign(node, msg->raw_tx.bytes, msg->raw_tx.size, 0,
                resp->signature.bytes, NULL, NULL);
#endif
    resp->signature.size = 64;
  } else {
    fsm_sendFailure(FailureType_Failure_DataError, "Parse error");
    return;
  }
  msg_write(MessageType_MessageType_SolanaSignedTx, resp);
}

//=====================Offchain Message Signing=====================
static bool prepare_message_v0(const SolanaSignOffChainMessage *msg,
                               const uint8_t *public_key,
                               BufferWriter *writer) {
  const uint8_t version = 0;
  const uint8_t format = (uint8_t)msg->message_format;
  const uint8_t message_length[] = {
      (uint8_t)(msg->message.size & 0xff),
      (uint8_t)((msg->message.size >> 8) & 0xff),
  };

  if (!write_bytes(_SIGN_DOMAIN, _SIGN_DOMAIN_LENGTH, writer) ||
      !write_bytes(&version, sizeof(version), writer)) {
    return false;
  }
  if (msg->has_application_domain) {
    if (!write_bytes(msg->application_domain.bytes, _APPLICATION_DOMAIN_LENGTH,
                     writer)) {
      return false;
    }
  }
  if (!write_bytes(&format, sizeof(format), writer)) {
    return false;
  }
  if (msg->has_application_domain) {
    if (!write_bytes(&_SIGNER_COUNT, sizeof(_SIGNER_COUNT), writer) ||
        !write_bytes(public_key, SIZE_PUBKEY, writer)) {
      return false;
    }
  }
  return write_bytes(message_length, sizeof(message_length), writer) &&
         write_bytes(msg->message.bytes, msg->message.size, writer);
}

static bool prepare_message_v1(const SolanaSignOffChainMessage *msg,
                               BufferWriter *writer) {
  const uint8_t version = 1;
  const uint8_t signer_count = (uint8_t)msg->required_signers_count;

  if (!write_bytes(_SIGN_DOMAIN, _SIGN_DOMAIN_LENGTH, writer) ||
      !write_bytes(&version, sizeof(version), writer) ||
      !write_bytes(&signer_count, sizeof(signer_count), writer)) {
    return false;
  }
  for (pb_size_t i = 0; i < msg->required_signers_count; i++) {
    if (!write_bytes(msg->required_signers[i].bytes, SIZE_PUBKEY, writer)) {
      return false;
    }
  }
  return write_bytes(msg->message.bytes, msg->message.size, writer);
}

static bool prepare_message(const SolanaSignOffChainMessage *msg,
                            const uint8_t *public_key, BufferWriter *writer) {
  switch (msg->message_version) {
    case SolanaOffChainMessageVersion_MESSAGE_VERSION_0:
      return prepare_message_v0(msg, public_key, writer);
    case SolanaOffChainMessageVersion_MESSAGE_VERSION_1:
      return prepare_message_v1(msg, writer);
    default:
      return false;
  }
}

static bool is_required_signer(const SolanaSignOffChainMessage *msg,
                               const uint8_t *public_key) {
  for (pb_size_t i = 0; i < msg->required_signers_count; i++) {
    if (memcmp(msg->required_signers[i].bytes, public_key, SIZE_PUBKEY) == 0) {
      return true;
    }
  }
  return false;
}

static bool format_required_signers(const SolanaSignOffChainMessage *msg,
                                    char output[][BASE58_PUBKEY_LENGTH]) {
  for (pb_size_t i = 0; i < msg->required_signers_count; i++) {
    if (encode_base58(msg->required_signers[i].bytes, SIZE_PUBKEY, output[i],
                      BASE58_PUBKEY_LENGTH) != 0 ||
        output[i][0] == '\0') {
      return false;
    }
  }
  return true;
}

static bool is_valid_v1_utf8(const uint8_t *data, size_t length) {
  if (data == NULL) {
    return false;
  }

  /*
   * The shared validator rejects U+FFFE/U+FFFF even though their UTF-8
   * encodings are well formed. V1 follows the SRFC/Pro2 UTF-8 contract, so
   * validate the surrounding segments with the shared helper and admit only
   * these two additional sequences locally.
   */
  size_t segment_start = 0;
  for (size_t i = 0; i + 2 < length; i++) {
    if (data[i] == 0xef && data[i + 1] == 0xbf &&
        (data[i + 2] == 0xbe || data[i + 2] == 0xbf)) {
      if (!is_valid_utf8(data + segment_start, i - segment_start)) {
        return false;
      }
      i += 2;
      segment_start = i + 1;
    }
  }
  return is_valid_utf8(data + segment_start, length - segment_start);
}

bool solana_sign_offchain_message(const SolanaSignOffChainMessage *msg,
                                  const HDNode *node,
                                  SolanaMessageSignature *resp) {
  const uint8_t *public_key = node->public_key + 1;
  const bool is_v1 =
      msg->message_version == SolanaOffChainMessageVersion_MESSAGE_VERSION_1;
  if (is_v1 && !is_required_signer(msg, public_key)) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Derived public key is not a required signer");
    return false;
  }

  BufferWriter size_writer = {0};
  if (!prepare_message(msg, public_key, &size_writer) ||
      size_writer.position > UINT16_MAX) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid message");
    return false;
  }

  char address[BASE58_PUBKEY_LENGTH] = {0};
  solana_get_address_from_public_key(public_key, address);
  char application_domain[45] = {0};
  char required_signers[_MAX_REQUIRED_SIGNERS][BASE58_PUBKEY_LENGTH] = {0};
  const char *additional_signer_pages[_MAX_REQUIRED_SIGNERS - 1] = {0};
  uint8_t additional_signer_count = 0;
  const char *item_name = NULL;
  const char *item_value = NULL;
  bool display_as_text = true;
  if (is_v1) {
    if (!format_required_signers(msg, required_signers)) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid required signers");
      return false;
    }
    /* The first page already shows the derived signer. */
    for (pb_size_t i = 0; i < msg->required_signers_count; i++) {
      if (memcmp(msg->required_signers[i].bytes, public_key, SIZE_PUBKEY) ==
          0) {
        continue;
      }
      additional_signer_pages[additional_signer_count++] = required_signers[i];
    }
    display_as_text = is_valid_ascii(msg->message.bytes, msg->message.size);
  } else if (msg->has_application_domain) {
    encode_base58(msg->application_domain.bytes, _APPLICATION_DOMAIN_LENGTH,
                  application_domain, sizeof(application_domain));
    item_name = "Application domain:";
    item_value = application_domain;
  }
  const bool confirmed =
      is_v1 && additional_signer_count > 0
          ? layoutSignMessageWithItemPages(
                "SOL", false, address, msg->message.bytes, msg->message.size,
                display_as_text, _(I__ADDITIONAL_SIGNERS),
                additional_signer_pages, additional_signer_count, false)
          : layoutSignMessage("SOL", false, address, msg->message.bytes,
                              msg->message.size, display_as_text, item_name,
                              item_value, false);
  if (!confirmed) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "user cancelled");
    return false;
  }

  const size_t message_length = size_writer.position;
  BufferWriter writer = {0};
  uint8_t message[message_length];
  init_buffer_writer(&writer, message, message_length);
  if (!prepare_message(msg, public_key, &writer) ||
      writer.position != message_length) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid message");
    return false;
  }
  // sign message
#if EMULATOR
  ed25519_sign(message, message_length, node->private_key,
               resp->signature.bytes);
#else
  if (hdnode_sign(node, message, message_length, 0, resp->signature.bytes, NULL,
                  NULL) != 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "signing failed");
    return false;
  }
#endif
  resp->signature.size = 64;
  return true;
}

bool solana_sanitize_offchain_message(const SolanaSignOffChainMessage *msg) {
  if (msg->message_version == SolanaOffChainMessageVersion_MESSAGE_VERSION_1) {
    if (msg->has_application_domain) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Application domain is not supported for version 1");
      return false;
    }
    if (msg->has_message_format) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Message format is not supported for version 1");
      return false;
    }
    if (msg->message.size == 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Message must not be empty");
      return false;
    }
    if (!is_valid_v1_utf8(msg->message.bytes, msg->message.size)) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Message must be valid UTF-8");
      return false;
    }
    if (msg->required_signers_count == 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid required signer count");
      return false;
    }
    for (pb_size_t i = 0; i < msg->required_signers_count; i++) {
      if (msg->required_signers[i].size != SIZE_PUBKEY) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Required signer must be 32 bytes");
        return false;
      }
      if (i > 0 && memcmp(msg->required_signers[i - 1].bytes,
                          msg->required_signers[i].bytes, SIZE_PUBKEY) >= 0) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Required signers must be sorted and unique");
        return false;
      }
    }
    return true;
  }

  if (msg->message_version != SolanaOffChainMessageVersion_MESSAGE_VERSION_0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Message version must be 0 or 1");
    return false;
  }

  if (msg->required_signers_count != 0) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Required signers are not supported for version 0");
    return false;
  }
  if (msg->has_application_domain &&
      msg->application_domain.size != _APPLICATION_DOMAIN_LENGTH) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Application domain must be 32 bytes");
    return false;
  }
  if (msg->has_application_domain && msg->message.size > _MAX_MESSAGE_LENGTH) {
    fsm_sendFailure(FailureType_Failure_DataError, "Message is too long");
    return false;
  }
  switch (msg->message_format) {
    case SolanaOffChainMessageFormat_V0_RESTRICTED_ASCII:
      if (!is_valid_ascii(msg->message.bytes, msg->message.size)) {
        fsm_sendFailure(
            FailureType_Failure_DataError,
            "Message format 0 must contain only printable characters");
        return false;
      }
      break;
    case SolanaOffChainMessageFormat_V0_LIMITED_UTF8:
      if (!is_valid_utf8(msg->message.bytes, msg->message.size)) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Message format 1 must be a valid UTF-8 string");
        return false;
      }
      break;
    default:
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Message format must be 0 or 1");
      return false;
  }
  return true;
}
//=====================Offchain Message Signing=====================

bool solana_is_offchain_message(const uint8_t *message, size_t message_length) {
  return message != NULL && message_length >= _SIGN_DOMAIN_LENGTH &&
         memcmp(message, _SIGN_DOMAIN, _SIGN_DOMAIN_LENGTH) == 0;
}

//=====================Unsafe Message Signing=====================
bool solana_sign_unsafe_message(const SolanaSignUnsafeMessage *msg,
                                const HDNode *node,
                                SolanaMessageSignature *resp) {
  // address
  char address[BASE58_PUBKEY_LENGTH] = {0};
  solana_get_address_from_public_key(node->public_key + 1, address);
  // show message
  if (!layoutSignMessage("SOL", false, address, msg->message.bytes,
                         msg->message.size,
                         is_printable(msg->message.bytes, msg->message.size),
                         NULL, NULL, true)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "user cancelled");
    return false;
  }
  // sign message
#if EMULATOR
  ed25519_sign(msg->message.bytes, msg->message.size, node->private_key,
               resp->signature.bytes);
#else
  if (hdnode_sign(node, msg->message.bytes, msg->message.size, 0,
                  resp->signature.bytes, NULL, NULL) != 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "signing failed");
    return false;
  }
#endif
  resp->signature.size = 64;
  return true;
}
//=====================Unsafe Message Signing=====================
