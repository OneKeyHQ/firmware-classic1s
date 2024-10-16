/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2022 OneKey Team <core@onekey.so>
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

#include "ada.h"
#include "base58.h"
#include "bip39.h"
#include "buttons.h"
#include "cardano.h"
#include "cbor.h"
#include "config.h"
#include "curves.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "segwit_addr.h"
#include "sha3.h"
#include "util.h"

struct AdaSigner ada_signer;
static CardanoTxItemAck ada_msg_item_ack;
static CardanoSignTxFinished ada_msg_sign_tx_finished;
extern int convert_bits(uint8_t *out, size_t *outlen, int outbits,
                        const uint8_t *in, size_t inlen, int inbits, int pad);

extern HDNode *fsm_getDerivedNode(const char *curve, const uint32_t *address_n,
                                  size_t address_n_count,
                                  uint32_t *fingerprint);
#if EMULATOR
static HDNode ada_node;

bool fsm_getCardanoIcaruNode(HDNode *node, const uint32_t *address_n,
                             size_t address_n_count, uint32_t *fingerprint) {
  if (!config_getCardanoRootNode(node)) {
    layoutHome();
    return 0;
  }
  if (hdnode_private_ckd_cached(node, address_n, address_n_count,
                                fingerprint) == 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to derive private key");
    return false;
  }
  hdnode_fill_public_key(node);

  return true;
}
#endif
bool deriveCardanoIcaruNode(HDNode *node, const uint32_t *address_n,
                            size_t address_n_count, uint32_t *fingerprint) {
#if EMULATOR
  memcpy(node, &ada_node, sizeof(HDNode));
  if (hdnode_private_ckd_cached(node, address_n, address_n_count,
                                fingerprint) == 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to derive private key");
    return false;
  }
  hdnode_fill_public_key(node);
#else
  HDNode *node_temp;
  node_temp = fsm_getDerivedNode(ED25519_CARDANO_NAME, address_n,
                                 address_n_count, fingerprint);

  if (!node_temp) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to derive private key");
    return false;
  }
  if (node_temp->public_key[0] != 1) {
    return false;
  }
  hdnode_fill_public_key(node_temp);
  memcpy(node, node_temp, sizeof(HDNode));
#endif
  return true;
}

bool validate_network_info(int network_id, int protocol_magic) {
  /*
    We are only concerned about checking that both network_id and protocol_magic
    belong to the mainnet or that both belong to a testnet. We don't need to
    check for consistency between various testnets (at least for now).
  */
  bool is_mainnet_network_id = network_id != 0;
  bool is_mainnet_protocol_magic = protocol_magic == 764824073;
  if (is_mainnet_network_id != is_mainnet_protocol_magic) {
    return false;
  }

  return true;
}

static void to_seq(uint32_t x, uint8_t *out, int *bytes_generated) {
  int i, j;
  for (i = 5; i > 0; i--) {
    if (x & 127UL << i * 7) break;
  }
  for (j = 0; j <= i; j++) {
    out[j] = ((x >> ((i - j) * 7)) & 127) | 128;
  }

  out[i] ^= 128;
  if (NULL != bytes_generated) {
    *bytes_generated = j;
  }
}

static uint32_t reflect(uint32_t ref, char ch) {
  uint32_t value = 0;

  for (int i = 1; i < (ch + 1); i++) {
    if (ref & 1) value |= 1 << (ch - i);
    ref >>= 1;
  }

  return value;
}

uint32_t crc32(uint8_t *buf, uint32_t len) {
  uint32_t result = 0xFFFFFFFF;
  uint32_t m_Table[256];

  uint32_t ulPolynomial = 0x04C11DB7;

  for (int i = 0; i <= 0xFF; i++) {
    m_Table[i] = reflect(i, 8) << 24;
    for (int j = 0; j < 8; j++)
      m_Table[i] =
          (m_Table[i] << 1) ^ (m_Table[i] & (1 << 31) ? ulPolynomial : 0);
    m_Table[i] = reflect(m_Table[i], 32);
  }

  while (len--) result = (result >> 8) ^ m_Table[(result & 0xFF) ^ *buf++];

  result ^= 0xFFFFFFFF;

  return result;
}

bool derive_bytes(const CardanoAddressParametersType *address_parameters,
                  uint32_t network_id, uint32_t protocol_magic,
                  uint8_t *address_bytes, int *address_len) {
  int address_bytes_len = 0;
  uint8_t public_key[32] = {0};
  if (!validate_network_info(network_id, protocol_magic)) return false;
  if (address_parameters->address_type == CardanoAddressType_BYRON) {
    uint8_t extpubkey[64] = {0};
    HDNode node = {0};
    uint32_t fingerprint;

    if (!deriveCardanoIcaruNode(&node, address_parameters->address_n,
                                address_parameters->address_n_count,
                                &fingerprint)) {
      return false;
    }
    memcpy(extpubkey, node.public_key + 1, 32);
    memcpy(extpubkey + 32, node.chain_code, 32);

    // [0, [0, extpubkey], address_attributes]
    uint8_t cbor_buffer[64 + 10] = {0};
    size_t cbor_index = 0;
    cbor_index += cbor_writeToken(CBOR_TYPE_ARRAY, 3, cbor_buffer + cbor_index,
                                  74 - cbor_index);
    cbor_index += cbor_writeToken(CBOR_TYPE_UNSIGNED, 0,
                                  cbor_buffer + cbor_index, 74 - cbor_index);
    cbor_index += cbor_writeToken(CBOR_TYPE_ARRAY, 2, cbor_buffer + cbor_index,
                                  74 - cbor_index);
    cbor_index += cbor_writeToken(CBOR_TYPE_UNSIGNED, 0,
                                  cbor_buffer + cbor_index, 74 - cbor_index);
    cbor_index += cbor_writeToken(CBOR_TYPE_BYTES, 64, cbor_buffer + cbor_index,
                                  74 - cbor_index);
    memcpy(cbor_buffer + cbor_index, extpubkey, 64);
    cbor_index += 64;
    if (protocol_magic == MAINNET_PROTOCOL_MAGIC) {  // MAINNET
      cbor_index += cbor_writeToken(CBOR_TYPE_MAP, 0, cbor_buffer + cbor_index,
                                    74 - cbor_index);
    } else {
      cbor_index += cbor_writeToken(CBOR_TYPE_MAP, 1, cbor_buffer + cbor_index,
                                    74 - cbor_index);
      cbor_index += cbor_writeToken(CBOR_TYPE_UNSIGNED, 2,
                                    cbor_buffer + cbor_index, 74 - cbor_index);
      uint8_t scratch[10] = {0};
      size_t scratchSize =
          cbor_writeToken(CBOR_TYPE_UNSIGNED, protocol_magic, scratch, 10);
      cbor_index += cbor_writeToken(CBOR_TYPE_BYTES, scratchSize,
                                    cbor_buffer + cbor_index, 74 - cbor_index);
      memcpy(cbor_buffer + cbor_index, scratch, scratchSize);
      cbor_index += scratchSize;
    }

    // cborBuffer is hashed twice. First by sha3_256 and then by blake2b_224
    uint8_t sha_hash[32] = {0};
    uint8_t hash[ADDRESS_KEY_HASH_SIZE] = {0};
    struct SHA3_CTX ctx = {0};
    sha3_256_Init(&ctx);
    sha3_Update(&ctx, cbor_buffer, cbor_index);
    sha3_Final(&ctx, sha_hash);
    blake2b(sha_hash, 32, hash, ADDRESS_KEY_HASH_SIZE);

    // [address_root, address_attributes, address_type]
    memset(cbor_buffer, 0, 74);
    cbor_index = 0;
    cbor_index += cbor_writeToken(CBOR_TYPE_ARRAY, 3, cbor_buffer + cbor_index,
                                  74 - cbor_index);
    cbor_index += cbor_writeToken(CBOR_TYPE_BYTES, ADDRESS_KEY_HASH_SIZE,
                                  cbor_buffer + cbor_index, 74 - cbor_index);
    memcpy(cbor_buffer + cbor_index, hash, ADDRESS_KEY_HASH_SIZE);
    cbor_index += ADDRESS_KEY_HASH_SIZE;
    if (protocol_magic == MAINNET_PROTOCOL_MAGIC) {  // MAINNET
      cbor_index += cbor_writeToken(CBOR_TYPE_MAP, 0, cbor_buffer + cbor_index,
                                    74 - cbor_index);
    } else {
      cbor_index += cbor_writeToken(CBOR_TYPE_MAP, 1, cbor_buffer + cbor_index,
                                    74 - cbor_index);
      cbor_index += cbor_writeToken(CBOR_TYPE_UNSIGNED, 2,
                                    cbor_buffer + cbor_index, 74 - cbor_index);
      uint8_t scratch[10] = {0};
      size_t scratchSize =
          cbor_writeToken(CBOR_TYPE_UNSIGNED, protocol_magic, scratch, 10);
      cbor_index += cbor_writeToken(CBOR_TYPE_BYTES, scratchSize,
                                    cbor_buffer + cbor_index, 74 - cbor_index);
      memcpy(cbor_buffer + cbor_index, scratch, scratchSize);
      cbor_index += scratchSize;
    }
    cbor_index += cbor_writeToken(CBOR_TYPE_UNSIGNED, 0,
                                  cbor_buffer + cbor_index, 74 - cbor_index);

    // Array[
    //     tag(24):bytes(rawAddress),
    //     crc32(rawAddress)
    // ]
    address_bytes_len +=
        cbor_writeToken(CBOR_TYPE_ARRAY, 2, address_bytes + address_bytes_len,
                        128 - address_bytes_len);
    address_bytes_len += cbor_writeToken(
        CBOR_TYPE_TAG, CBOR_TAG_EMBEDDED_CBOR_BYTE_STRING,
        address_bytes + address_bytes_len, 128 - address_bytes_len);
    address_bytes_len += cbor_writeToken(CBOR_TYPE_BYTES, cbor_index,
                                         address_bytes + address_bytes_len,
                                         128 - address_bytes_len);
    memcpy(address_bytes + address_bytes_len, cbor_buffer, cbor_index);
    address_bytes_len += cbor_index;
    uint32_t checksum = crc32(cbor_buffer, cbor_index);
    address_bytes_len += cbor_writeToken(CBOR_TYPE_UNSIGNED, checksum,
                                         address_bytes + address_bytes_len,
                                         128 - address_bytes_len);
  } else {
    // _create_header
    address_bytes[0] = address_parameters->address_type << 4 | network_id;
    address_bytes_len = 1;

    // _get_payment_part
    if (address_parameters->address_n_count > 0) {
      HDNode node = {0};
      uint32_t fingerprint;
      if (!deriveCardanoIcaruNode(&node, address_parameters->address_n,
                                  address_parameters->address_n_count,
                                  &fingerprint)) {
        return false;
      }
      memcpy(public_key, node.public_key + 1, 32);

      uint8_t hash[ADDRESS_KEY_HASH_SIZE] = {0};
      blake2b(public_key, 32, hash, ADDRESS_KEY_HASH_SIZE);
      memcpy(address_bytes + address_bytes_len, hash, ADDRESS_KEY_HASH_SIZE);
      address_bytes_len += ADDRESS_KEY_HASH_SIZE;
    } else if (address_parameters->has_script_payment_hash) {
      memcpy(address_bytes + address_bytes_len,
             address_parameters->script_payment_hash.bytes, SCRIPT_HASH_SIZE);
      address_bytes_len += SCRIPT_HASH_SIZE;
    }

    // _get_staking_part
    if (address_parameters->has_staking_key_hash) {
      memcpy(address_bytes + address_bytes_len,
             address_parameters->staking_key_hash.bytes, ADDRESS_KEY_HASH_SIZE);
      address_bytes_len += ADDRESS_KEY_HASH_SIZE;
    } else if (address_parameters->address_n_staking_count > 0) {
      HDNode node = {0};
      uint32_t fingerprint;
      if (!deriveCardanoIcaruNode(&node, address_parameters->address_n_staking,
                                  address_parameters->address_n_staking_count,
                                  &fingerprint)) {
        return false;
      }
      memcpy(public_key, node.public_key + 1, 32);
      uint8_t hash[ADDRESS_KEY_HASH_SIZE] = {0};
      blake2b(public_key, 32, hash, ADDRESS_KEY_HASH_SIZE);
      memcpy(address_bytes + address_bytes_len, hash, ADDRESS_KEY_HASH_SIZE);
      address_bytes_len += ADDRESS_KEY_HASH_SIZE;
    } else if (address_parameters->has_script_staking_hash) {
      memcpy(address_bytes + address_bytes_len,
             address_parameters->script_staking_hash.bytes, SCRIPT_HASH_SIZE);
      address_bytes_len += SCRIPT_HASH_SIZE;
    } else if (address_parameters->has_certificate_pointer) {
      int bytes_generated;
      to_seq(address_parameters->certificate_pointer.block_index,
             address_bytes + address_bytes_len, &bytes_generated);
      address_bytes_len += bytes_generated;
      to_seq(address_parameters->certificate_pointer.tx_index,
             address_bytes + address_bytes_len, &bytes_generated);
      address_bytes_len += bytes_generated;
      to_seq(address_parameters->certificate_pointer.certificate_index,
             address_bytes + address_bytes_len, &bytes_generated);
      address_bytes_len += bytes_generated;
    }
  }

  *address_len = address_bytes_len;
  return true;
}

static const char *get_bech32_hrp(CardanoAddressType address_type,
                                  int network_id) {
  if (address_type == CardanoAddressType_BYRON) {
    return NULL;
  }

  if (address_type == CardanoAddressType_REWARD ||
      address_type == CardanoAddressType_REWARD_SCRIPT) {
    return network_id == NETWORK_ID_MAINNET ? HRP_REWARD_ADDRESS
                                            : HRP_TESTNET_REWARD_ADDRESS;
  }

  return network_id == NETWORK_ID_MAINNET ? HRP_ADDRESS : HRP_TESTNET_ADDRESS;
}

static inline CardanoAddressType get_type(const uint8_t *address_bytes) {
  return (CardanoAddressType)(address_bytes[0] >> 4);
}

static inline int get_network_id(const uint8_t *address_bytes) {
  return (address_bytes[0] & 0x0F);
}

static bool encode_human_readable(const uint8_t *address_bytes,
                                  size_t address_bytes_len, char *address) {
  CardanoAddressType address_type = get_type(address_bytes);
  if (address_type == CardanoAddressType_BYRON) {
    base58_encode(address_bytes, address_bytes_len, address, 128);
  } else {
    const char *hrp =
        get_bech32_hrp(address_type, get_network_id(address_bytes));
    if (hrp == NULL) {
      return false;
    }
    uint8_t data[128] = {0};
    size_t datalen = 0;
    convert_bits(data, &datalen, 5, address_bytes, address_bytes_len, 8, 1);
    if (1 !=
        bech32_encode(address, hrp, data, datalen, BECH32_ENCODING_BECH32)) {
      return false;
    }
  }

  return true;
}

bool ada_get_address(const CardanoGetAddress *msg, char *address) {
  uint8_t address_bytes[128] = {0};
  int address_bytes_len = 0;
  if (!derive_bytes(&msg->address_parameters, msg->network_id,
                    msg->protocol_magic, address_bytes, &address_bytes_len)) {
    return false;
  }

  return encode_human_readable(address_bytes, address_bytes_len, address);
}

#define BUILDER_APPEND_CBOR(type, value) \
  blake2b_256_append_cbor_tx_body(&ada_signer.ctx, type, value)

#define BUILDER_APPEND_DATA(buffer, bufferSize) \
  blake2b_256_append_buffer_tx_body(&ada_signer.ctx, buffer, bufferSize)

void blake2b_256_append_buffer_tx_body(BLAKE2B_CTX *ctx, const uint8_t *buffer,
                                       size_t bufferSize) {
  blake2b_Update(ctx, buffer, bufferSize);
}

void blake2b_256_append_cbor_tx_body(BLAKE2B_CTX *ctx, uint8_t type,
                                     uint64_t value) {
  uint8_t buffer[10] = {0};
  size_t size = cbor_writeToken(type, value, buffer, 10);
  blake2b_Update(ctx, buffer, size);
}

// ============================== input ==============================

void txHashBuilder_enterInputs(void) {
  if (ada_signer.state != TX_HASH_BUILDER_INIT) return;
  {
    // Enter inputs
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_INPUTS);
    if (ada_signer.signertx->has_tag_cbor_sets &&
        ada_signer.signertx->tag_cbor_sets) {
      BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_SET_TAG);
    }
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, ada_signer.remainingInputs);
  }
  ada_signer.state = TX_HASH_BUILDER_IN_INPUTS;
  ada_signer.tx_dict_items_count--;
}

void cbor_append_txInput(const uint8_t *utxoHashBuffer, size_t utxoHashSize,
                         uint32_t utxoIndex) {
  // Array(2)[
  //    Bytes[hash],
  //    Unsigned[index]
  // ]
  BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
  {
    BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, utxoHashSize);
    BUILDER_APPEND_DATA(utxoHashBuffer, utxoHashSize);
  }
  { BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, utxoIndex); }
}

void txHashBuilder_addInput(const CardanoTxInput *input) {
  ada_signer.remainingInputs--;
  cbor_append_txInput(input->prev_hash.bytes, input->prev_hash.size,
                      input->prev_index);
  msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
}

// ============================== output ==============================

void txHashBuilder_enterOutputs(void) {
  {
    // Enter outputs
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_OUTPUTS);
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, ada_signer.remainingOutputs);
  }
  ada_signer.state = TX_HASH_BUILDER_IN_OUTPUTS;
  ada_signer.tx_dict_items_count--;
}

bool get_bytes_unsafe(const char *address, uint8_t *address_bytes,
                      int *address_len) {
  char hrp[16] = {0};
  size_t res;
  uint8_t dbuf[128] = {0};
  int r = bech32_decode(hrp, dbuf, &res, address);
  if (r == BECH32_ENCODING_NONE) {
    res = *address_len;
    uint8_t d[*address_len];
    if (b58tobin(d, &res, address) != true) {
      *address_len = 0;
      return false;
    }
    memcpy(address_bytes, d + (*address_len - res), res);
    *address_len = res;
  } else {
    size_t len = 0;
    if (!convert_bits(address_bytes, &len, 8, dbuf, res, 5, 0)) return false;
    *address_len = len;
  }

  return true;
}

static bool layoutOutput(const CardanoTxOutput *output) {
  bool ret = true;
  uint8_t key = KEY_NULL;
  char desc[32] = {0};
  char str_amount[32] = {0};
  const char **tx_msg = format_tx_message("Cardano");
  ada_signer.is_change = false;

  if (!output->has_address_parameters) {
    if (output->asset_groups_count > 0) {
      oledClear();
      layoutHeader(tx_msg[0]);
      oledDrawStringAdapter(0, 13, _(T__THE_FOLLOWING_TX_OUTPUT_CONTAINS_TOKEN),
                            FONT_STANDARD);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      oledRefresh();
      while (1) {
        key = protectWaitKey(0, 1);
        if (key == KEY_CONFIRM) {
          ret = true;
          break;
        }
        if (key == KEY_CANCEL || key == KEY_NULL) {
          return false;
        }
      }
    }

    ButtonRequest resp = {0};
    memzero(&resp, sizeof(ButtonRequest));
    resp.has_code = true;
    resp.code = ButtonRequestType_ButtonRequest_SignTx;
    msg_write(MessageType_MessageType_ButtonRequest, &resp);

    oledClear();
    layoutHeader(tx_msg[0]);
    bn_format_uint64(output->amount, NULL, " ADA", 6, 0, false, ',', str_amount,
                     sizeof(str_amount));
    strcat(desc, _(I__AMOUNT_COLON));
    oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, str_amount, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    oledRefresh();
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        ret = true;
        break;
      }
      if (key == KEY_CANCEL || key == KEY_NULL) {
        return false;
      }
    }
  } else {
    ada_signer.is_change = true;
  }
  if (output->has_address) {
    uint32_t rowlen = 21, addrlen = strlen(output->address);
    int index = 0, rowcount = addrlen / rowlen + 1;
    if (rowcount > 3) {
      const char **str =
          split_message((const uint8_t *)output->address, addrlen, rowlen);

    refresh_addr:
      oledClear_ex();
      layoutHeader(tx_msg[0]);

      if (0 == index) {
        oledDrawStringAdapter(0, 13, _(I__SEND_TO_COLON), FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[0], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[2], FONT_STANDARD);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else {
        oledDrawStringAdapter(0, 13, str[index - 1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[index], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[index + 1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[index + 2], FONT_STANDARD);
        if (index == rowcount - 3) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }
      }

      // scrollbar
      int i, bar_start = 12, bar_end = 52;
      int bar_heght = 40 - 2 * (rowcount - 4);
      for (i = bar_start; i < bar_end; i += 2) {  // 40 pixel
        oledDrawPixel(OLED_WIDTH - 1, i);
      }
      for (i = bar_start + 2 * ((int)index);
           i < (bar_start + bar_heght + 2 * ((int)index - 1)) - 1; i++) {
        oledDrawPixel(OLED_WIDTH - 1, i);
        oledDrawPixel(OLED_WIDTH - 2, i);
      }

      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);

      oledRefresh();
      key = protectWaitKey(0, 0);
      switch (key) {
        case KEY_UP:
          if (index > 0) {
            index--;
          }
          goto refresh_addr;
        case KEY_DOWN:
          if (index < rowcount - 3) {
            index++;
          }
          goto refresh_addr;
        case KEY_CONFIRM:
          return true;
        case KEY_CANCEL:
          return false;
        default:
          return false;
      }
    } else {
      oledClear();
      layoutHeader(tx_msg[0]);
      oledDrawStringAdapter(0, 13, _(I__SEND_TO_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, output->address, FONT_STANDARD);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      oledRefresh();
      while (1) {
        key = protectWaitKey(0, 0);
        if (key == KEY_CONFIRM) {
          ret = true;
          break;
        }
        if (key == KEY_CANCEL || key == KEY_NULL) {
          ret = false;
          break;
        }
      }
    }
  }
  return ret;
}

static bool layoutFinal(void) {
  uint8_t key = KEY_NULL;
  const char **tx_msg = format_tx_message("Cardano");

  oledClear();
  layoutHeader(_(T__SIGN_TRANSACTION));
  layoutTxConfirmPage(tx_msg[1]);
  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  oledRefresh();
  while (1) {
    key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      return true;
      break;
    }
    if (key == KEY_CANCEL || key == KEY_NULL) {
      return false;
    }
  }
}

static bool layoutFee(void) {
  uint8_t key = KEY_NULL;
  char desc[32] = {0};
  char str_amount[32] = {0};
  const char **tx_msg = format_tx_message("Cardano");

  oledClear();
  layoutHeader(tx_msg[0]);
  strcat(desc, _(I__FEE_COLON));
  bn_format_uint64(ada_signer.signertx->fee, NULL, " ADA", 6, 0, false, ',',
                   str_amount, sizeof(str_amount));
  oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);
  oledDrawStringAdapter(0, 13 + 10, str_amount, FONT_STANDARD);

  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  oledRefresh();
  while (1) {
    key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      break;
    }
    if (key == KEY_CANCEL || key == KEY_NULL) {
      return false;
    }
  }
  return layoutFinal();
}

bool txHashBuilder_addOutput(const CardanoTxOutput *output) {
  if (!layoutOutput(output)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return false;
  }
  ada_signer.remainingOutputs--;
  int output_items_count = 2;
  if (output->has_datum_hash) output_items_count++;
  if (output->has_inline_datum_size && (output->inline_datum_size > 0))
    output_items_count++;
  if (output->has_reference_script_size && (output->reference_script_size > 0))
    output_items_count++;
  if (output->format == CardanoTxOutputSerializationFormat_ARRAY_LEGACY) {
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, output_items_count);

    uint8_t address_bytes[128] = {0};
    int address_bytes_len = 64;
    if (output->has_address_parameters) {
      if (!derive_bytes(&output->address_parameters,
                        ada_signer.signertx->network_id,
                        ada_signer.signertx->protocol_magic, address_bytes,
                        &address_bytes_len)) {
        return false;
      }
    } else {
      if (!get_bytes_unsafe(output->address, address_bytes,
                            &address_bytes_len)) {
        return false;
      }
    }
    BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, address_bytes_len);
    BUILDER_APPEND_DATA(address_bytes, address_bytes_len);
    // Output structure is: [address, amount, datum_hash?]
    if (0 == output->asset_groups_count) {
      BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, output->amount);
      if (output->has_datum_hash) {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, output->datum_hash.size);
        BUILDER_APPEND_DATA(output->datum_hash.bytes, output->datum_hash.size);
      }

      ada_signer.outputState = TX_OUTPUT_FINISHED;
    } else {
      // Output structure is: [address, [amount, asset_groups], datum_hash?]
      BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
      BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, output->amount);
      BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, output->asset_groups_count);

      ada_signer.outputState = TX_OUTPUT_TOP_LEVEL_DATA;
      ada_signer.output_asset_groups_count = output->asset_groups_count;
      if (output->has_datum_hash) {
        memcpy(ada_signer.datum_hash, output->datum_hash.bytes,
               output->datum_hash.size);
        ada_signer.datum_hash_size = output->datum_hash.size;
      } else {
        ada_signer.datum_hash_size = 0;
      }
    }
  } else if (output->format == CardanoTxOutputSerializationFormat_MAP_BABBAGE) {
    return false;  // unsupport
  } else {
    return false;
  }

  return true;
}

bool txHashBuilder_addAssetGroup(const CardanoAssetGroup *msg) {
  BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, msg->policy_id.size);
  BUILDER_APPEND_DATA(msg->policy_id.bytes, msg->policy_id.size);
  BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, msg->tokens_count);

  memcpy(ada_signer.policy_id, msg->policy_id.bytes, msg->policy_id.size);
  ada_signer.policy_id_size = msg->policy_id.size;
  return true;
}

bool txHashBuilder_addToken(const CardanoToken *msg) {
  BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, msg->asset_name_bytes.size);
  BUILDER_APPEND_DATA(msg->asset_name_bytes.bytes, msg->asset_name_bytes.size);
  if (msg->has_amount) {
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, msg->amount);
  }
  if (ada_signer.outputState != TX_OUTPUT_FINISHED) {
    ada_signer.output_asset_groups_count--;
    if ((0 == ada_signer.output_asset_groups_count) &&
        (0 != ada_signer.datum_hash_size)) {
      BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, ada_signer.datum_hash_size);
      BUILDER_APPEND_DATA(ada_signer.datum_hash, ada_signer.datum_hash_size);
      ada_signer.outputState = TX_OUTPUT_FINISHED;
    }
  }

  uint8_t message_digest[20];
  char fingerprint[128] = {0};
  uint8_t data[65] = {0};
  size_t datalen = 0;
  bool ret = false;
  char amount[32] = {0};
  uint8_t key = KEY_NULL, index = 0;
  const char **tx_msg = format_tx_message("Cardano");

  BLAKE2B_CTX ctx;
  blake2b_Init(&ctx, 20);
  blake2b_Update(&ctx, ada_signer.policy_id, ada_signer.policy_id_size);
  blake2b_Update(&ctx, msg->asset_name_bytes.bytes, msg->asset_name_bytes.size);
  blake2b_Final(&ctx, message_digest, 20);

  // bech32_encode
  convert_bits(data, &datalen, 5, message_digest, 20, 8, 1);
  bech32_encode(fingerprint, "asset", data, datalen, BECH32_ENCODING_BECH32);

  uint2str(msg->amount, amount);

  if (ada_signer.is_change) return true;

refresh_layout:
  oledClear();
  layoutHeader(tx_msg[0]);

  if (0 == index) {
    oledDrawStringAdapter(0, 13, _(I__ASSET_FINGERPRINT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, fingerprint, FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 30, _(I__TOKEN_AMOUNT_COLON), FONT_STANDARD);
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
  } else {
    oledDrawStringAdapter(0, 13, fingerprint, FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 20, _(I__TOKEN_AMOUNT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 30, amount, FONT_STANDARD);
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  }

  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  oledRefresh();
  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (index > 0) {
        index--;
      }
      goto refresh_layout;
    case KEY_DOWN:
      if (index < 1) {
        index++;
      }
      goto refresh_layout;
    case KEY_CONFIRM:
      ret = true;
      break;
    case KEY_CANCEL:
      ret = false;
      break;
    default:
      ret = false;
      break;
  }
  if (!ret) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return false;
  }

  return true;
}

// ============================== FEE ==============================

void txHashBuilder_addTtl(uint64_t ttl) {
  BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_TTL);
  BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, ttl);

  ada_signer.state = TX_HASH_BUILDER_IN_TTL;
  ada_signer.tx_dict_items_count--;
}

void txHashBuilder_addFee(uint64_t fee) {
  // add fee item into the main tx body map
  BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_FEE);
  BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, fee);

  ada_signer.state = TX_HASH_BUILDER_IN_FEE;
  ada_signer.tx_dict_items_count--;

  if (ada_signer.signertx->has_ttl) {
    txHashBuilder_addTtl(ada_signer.signertx->ttl);
  }
}

static bool get_public_key_hash(const uint32_t *address_n,
                                size_t address_n_count,
                                uint8_t hash[ADDRESS_KEY_HASH_SIZE]) {
  HDNode node = {0};
  uint32_t fingerprint;
  uint8_t public_key[32] = {0};
  if (!deriveCardanoIcaruNode(&node, address_n, address_n_count,
                              &fingerprint)) {
    return false;
  }
  memcpy(public_key, node.public_key + 1, 32);
  blake2b(public_key, 32, hash, ADDRESS_KEY_HASH_SIZE);
  return true;
}

// ============================== Certificate ==============================

static bool layoutCertificate(const CardanoTxCertificate *cert) {
  uint8_t key = KEY_NULL;
  const char **tx_msg = format_tx_message("Cardano");

  oledClear();
  layoutHeader(tx_msg[0]);
  oledDrawStringAdapter(0, 13, _(I__TRANSACTION_TYPE_COLON), FONT_STANDARD);
  if (cert->type == CardanoCertificateType_STAKE_REGISTRATION) {
    oledDrawStringAdapter(0, 13 + 10, _(I__STAKE_KEY_REGISTRATION_COLON),
                          FONT_STANDARD);
  } else if (cert->type == CardanoCertificateType_STAKE_DEREGISTRATION) {
    oledDrawStringAdapter(0, 13 + 10, _(I__STAKE_DEREGISTRATION_COLON),
                          FONT_STANDARD);
  } else if (cert->type == CardanoCertificateType_STAKE_DELEGATION) {
    oledDrawStringAdapter(0, 13 + 10, _(I__STAKE_DELEGATION_COLON),
                          FONT_STANDARD);
  } else if (cert->type == CardanoCertificateType_STAKE_POOL_REGISTRATION) {
    oledDrawStringAdapter(0, 13 + 10, _(T__POOL_REGISTRATION), FONT_STANDARD);
  }

  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  oledRefresh();
  while (1) {
    key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      break;
    }
    if (key == KEY_CANCEL || key == KEY_NULL) {
      return false;
    }
  }

  // account
  if (cert->path_count > 0) {
    oledClear();
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, 13, _(I__ACCOUNT_COLON), FONT_STANDARD);
    oledDrawString(0, 13 + 10,
                   address_n_str(cert->path, cert->path_count, true),
                   FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
    oledRefresh();
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        break;
      }
      if (key == KEY_CANCEL || key == KEY_NULL) {
        return false;
      }
    }
  }
  if (cert->has_pool) {
    char pool[65] = {0};
    uint8_t data[65] = {0};
    size_t datalen = 0;
    convert_bits(data, &datalen, 5, cert->pool.bytes, cert->pool.size, 8, 1);
    bech32_encode(pool, "pool", data, datalen, BECH32_ENCODING_BECH32);
    oledClear();
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, 13, _(I__TO_POOL_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, pool, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
    oledRefresh();
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        break;
      }
      if (key == KEY_CANCEL || key == KEY_NULL) {
        return false;
      }
    }
  }
  return true;
}

bool txHashBuilder_addCertificate(const CardanoTxCertificate *cert) {
  if (!ada_signer.is_feeed) {
    txHashBuilder_addFee(ada_signer.signertx->fee);
    ada_signer.is_feeed = true;
  }
  if (!layoutCertificate(cert)) {
    return false;
  }

  if (ada_signer.state != TX_HASH_BUILDER_IN_CERTIFICATES) {
    // enter Certificate
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_CERTIFICATES);
    if (ada_signer.signertx->has_tag_cbor_sets &&
        ada_signer.signertx->tag_cbor_sets) {
      BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_SET_TAG);
    }
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, ada_signer.remainingCertificates);

    ada_signer.state = TX_HASH_BUILDER_IN_CERTIFICATES;
    ada_signer.tx_dict_items_count--;
  }

  if ((cert->type == CardanoCertificateType_STAKE_REGISTRATION) ||
      (cert->type == CardanoCertificateType_STAKE_DEREGISTRATION)) {
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
    { BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, cert->type); }
    {
      BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
      {
        if (cert->has_key_hash) {
          BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);

          BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, cert->key_hash.size);
          BUILDER_APPEND_DATA(cert->key_hash.bytes, cert->key_hash.size);
        } else if (cert->path_count > 0) {
          BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);

          uint8_t hash[ADDRESS_KEY_HASH_SIZE] = {0};
          if (!get_public_key_hash(cert->path, cert->path_count, hash)) {
            return false;
          }
          BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, ADDRESS_KEY_HASH_SIZE);
          BUILDER_APPEND_DATA(hash, ADDRESS_KEY_HASH_SIZE);
        } else if (cert->has_script_hash) {
          BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 1);

          BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, cert->script_hash.size);
          BUILDER_APPEND_DATA(cert->script_hash.bytes, cert->script_hash.size);
        } else {
          return false;
        }
      }
    }
  } else if (cert->type == CardanoCertificateType_STAKE_DELEGATION) {
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
    { BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, cert->type); }
    {
      BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
      {
        if (cert->has_key_hash) {
          BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);

          BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, cert->key_hash.size);
          BUILDER_APPEND_DATA(cert->key_hash.bytes, cert->key_hash.size);
        } else if (cert->path_count > 0) {
          BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);

          uint8_t hash[ADDRESS_KEY_HASH_SIZE] = {0};
          if (!get_public_key_hash(cert->path, cert->path_count, hash)) {
            return false;
          }
          BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, ADDRESS_KEY_HASH_SIZE);
          BUILDER_APPEND_DATA(hash, ADDRESS_KEY_HASH_SIZE);
        } else if (cert->has_script_hash) {
          BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 1);

          BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, cert->script_hash.size);
          BUILDER_APPEND_DATA(cert->script_hash.bytes, cert->script_hash.size);
        } else {
          return false;
        }
      }
    }
    {
      if (cert->has_pool) {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, cert->pool.size);
        BUILDER_APPEND_DATA(cert->pool.bytes, cert->pool.size);
      } else {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, 0);
      }
    }
  } else if (cert->type == CardanoCertificateType_STAKE_POOL_REGISTRATION) {
    return false;
  } else {
    return false;
  }

  ada_signer.remainingCertificates--;
  return true;
}

// ============================== Withdrawal ==============================

bool txHashBuilder_addWithdrawal(const CardanoTxWithdrawal *wdr) {
  if (!ada_signer.is_feeed) {
    txHashBuilder_addFee(ada_signer.signertx->fee);
    ada_signer.is_feeed = true;
  }
  if (ada_signer.state != TX_HASH_BUILDER_IN_WITHDRAWALS) {
    // enter Certificate
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_WITHDRAWALS);
    BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, ada_signer.remainingWithdrawals);

    ada_signer.state = TX_HASH_BUILDER_IN_WITHDRAWALS;
    ada_signer.tx_dict_items_count--;
  }

  uint8_t address_bytes[128] = {0};
  int address_bytes_len = 0;
  CardanoAddressParametersType address_parameters;
  memset(&address_parameters, 0, sizeof(CardanoAddressParametersType));
  if (wdr->path_count > 0) {
    address_parameters.address_type = CardanoAddressType_REWARD;
    memcpy(address_parameters.address_n_staking, wdr->path,
           wdr->path_count * 4);
    address_parameters.address_n_staking_count = wdr->path_count;
  }

  if (wdr->has_key_hash) {
    address_parameters.address_type = CardanoAddressType_REWARD;
    memcpy(address_parameters.staking_key_hash.bytes, wdr->key_hash.bytes, 28);
    address_parameters.staking_key_hash.size = 28;
    address_parameters.has_staking_key_hash = true;
  }
  if (wdr->has_script_hash) {
    address_parameters.address_type = CardanoAddressType_REWARD_SCRIPT;
    memcpy(address_parameters.script_staking_hash.bytes, wdr->script_hash.bytes,
           28);
    address_parameters.script_staking_hash.size = 28;
    address_parameters.has_script_staking_hash = true;
  }
  if (!derive_bytes(&address_parameters, ada_signer.signertx->network_id,
                    ada_signer.signertx->protocol_magic, address_bytes,
                    &address_bytes_len)) {
    return false;
  }

  BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, address_bytes_len);
  BUILDER_APPEND_DATA(address_bytes, address_bytes_len);
  BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, wdr->amount);

  ada_signer.remainingWithdrawals--;
  return true;
}

// ============================== AuxiliaryData ==============================

bool txHashBuilder_addAuxiliaryData(const CardanoTxAuxiliaryData *au) {
  CardanoTxAuxiliaryDataSupplement au_data_sup;
  if (!ada_signer.is_feeed) {
    txHashBuilder_addFee(ada_signer.signertx->fee);
    ada_signer.is_feeed = true;
  }

  memset(&au_data_sup, 0, sizeof(CardanoTxAuxiliaryDataSupplement));

  if (au->has_hash) {
    au_data_sup.type = CardanoTxAuxiliaryDataSupplementType_NONE;
    au_data_sup.has_auxiliary_data_hash = false;
    au_data_sup.has_cvote_registration_signature = false;
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_AUX_DATA);
    BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, au->hash.size);
    BUILDER_APPEND_DATA(au->hash.bytes, au->hash.size);
  } else if (au->has_cvote_registration_parameters) {
    return false;  // unsupport
  } else {
    return false;
  }

  ada_signer.state = TX_HASH_BUILDER_IN_AUX_DATA;
  ada_signer.tx_dict_items_count--;

  // CardanoTxHostAck
  msg_write(MessageType_MessageType_CardanoTxAuxiliaryDataSupplement,
            &au_data_sup);

  return true;
}

bool hash_stage() {
  switch (ada_signer.state) {
    case TX_HASH_BUILDER_IN_INPUTS:
      if (0 == ada_signer.remainingInputs) {
        ada_signer.state = TX_HASH_BUILDER_IN_OUTPUTS;
        txHashBuilder_enterOutputs();
      }
      break;
    case TX_HASH_BUILDER_IN_OUTPUTS:
      if (ada_signer.remainingOutputs > 0 ||
          (ada_signer.remainingOutputs == 0 && ada_signer.is_feeed == false)) {
        msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
      }
      break;
    case TX_HASH_BUILDER_IN_CERTIFICATES:
      if (ada_signer.remainingCertificates > 0) {
        msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
      }
      break;
    case TX_HASH_BUILDER_IN_WITHDRAWALS:
      if (ada_signer.remainingWithdrawals > 0) {
        msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
      }
      break;
    case TX_HASH_BUILDER_IN_AUX_DATA:
      if (ada_signer.signertx->has_auxiliary_data &&
          ada_signer.tx_dict_items_count > 0) {
        msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
      }
      break;
    case TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START:
      if (ada_signer.signertx->has_validity_interval_start) {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
                            TX_BODY_KEY_VALIDITY_INTERVAL_START);
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
                            ada_signer.signertx->validity_interval_start);
        ada_signer.state = TX_DUMMY_BREAK;
        ada_signer.tx_dict_items_count--;
      }
      //-fallthrough
    case TX_HASH_BUILDER_IN_MINT:
      if (ada_signer.remainingMintingAssetGroupsCount > 0) {
        msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
        break;
      }
      //-fallthrough
    case TX_HASH_BUILDER_IN_SCRIPT_DATA_HASH:
      if (ada_signer.signertx->has_script_data_hash) {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_SCRIPT_HASH_DATA);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES,
                            ada_signer.signertx->script_data_hash.size);
        BUILDER_APPEND_DATA(ada_signer.signertx->script_data_hash.bytes,
                            ada_signer.signertx->script_data_hash.size);
        ada_signer.state = TX_DUMMY_BREAK;
        ada_signer.tx_dict_items_count--;
        // msg_write(MessageType_MessageType_CardanoTxItemAck,
        // &ada_msg_item_ack);
      }
      break;
    //   //-fallthrough
    // case TX_HASH_BUILDER_IN_COLLATERAL_INPUTS:
    //   if (ada_signer.remainingCollateralInputs > 0) {
    //     msg_write(MessageType_MessageType_CardanoTxItemAck,
    //     &ada_msg_item_ack); break;
    //   }
    //   //-fallthrough
    // case TX_HASH_BUILDER_IN_REQUIRED_SIGNERS:
    //   if (ada_signer.remainingRequiredSigners > 0) {
    //     msg_write(MessageType_MessageType_CardanoTxItemAck,
    //     &ada_msg_item_ack); break;
    //   }
    //   //-fallthrough
    // case TX_HASH_BUILDER_IN_NETWORK_ID:
    //   if (ada_signer.signertx.has_include_network_id &&
    //       ada_signer.signertx.include_network_id) {
    //     BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_NETWORK_ID);
    //     BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
    //     ada_signer.signertx.network_id);
    //     ada_signer.signertx.has_include_network_id = false;
    //     ada_signer.state = TX_HASH_BUILDER_IN_COLLATERAL_OUTPUT;
    //     ada_signer.tx_dict_items_count--;
    //   }
    //   //-fallthrough
    // case TX_HASH_BUILDER_IN_COLLATERAL_OUTPUT:
    //   if (ada_signer.remainingCollateralInputs > 0) {
    //     msg_write(MessageType_MessageType_CardanoTxItemAck,
    //     &ada_msg_item_ack); break;
    //   }
    //   //-fallthrough
    // case TX_HASH_BUILDER_IN_TOTAL_COLLATERAL:
    //   if (ada_signer.signertx.has_total_collateral) {
    //     BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
    //     TX_BODY_KEY_TOTAL_COLLATERAL);
    //     BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
    //                         ada_signer.signertx.total_collateral);
    //     ada_signer.signertx.has_total_collateral = false;
    //     ada_signer.tx_dict_items_count--;
    //   }
    //   //-fallthrough
    // case TX_HASH_BUILDER_IN_REFERENCE_INPUTS:
    //   if (ada_signer.remainingReferenceInputs > 0) {
    //     msg_write(MessageType_MessageType_CardanoTxItemAck,
    //     &ada_msg_item_ack); break;
    //   }
    //   //-fallthrough
    // case TX_HASH_BUILDER_FINISHED:
    //   ada_signer.state = TX_HASH_BUILDER_FINISHED;
    //   break;
    default:
      break;
  }

  return true;
}

bool _processs_tx_init(const CardanoSignTxInit *msg) {
  if (msg->signing_mode != CardanoTxSigningMode_ORDINARY_TRANSACTION) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Only support ORDINARY TRANSACTION");
    return false;
  }
  memset(&ada_signer, 0, sizeof(struct AdaSigner));
  static CardanoSignTxInit ada_tx_context;
  memcpy(&ada_tx_context, msg, sizeof(CardanoSignTxInit));
  ada_signer.signertx = &ada_tx_context;

  // _validate_tx_init
  if ((msg->fee > LOVELACE_MAX_SUPPLY) ||
      (msg->total_collateral > LOVELACE_MAX_SUPPLY) ||
      (msg->has_total_collateral)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Invalid tx signing request");
    return false;
  }
  if (!validate_network_info(msg->network_id, msg->protocol_magic))
    return false;
  // if((msg->collateral_inputs_count != 0) || (msg->has_total_collateral) ||
  // (msg->has_reference_inputs_count) ) {
  //   fsm_sendFailure(FailureType_Failure_ProcessError,
  //                   _("Invalid tx signing request"));
  //   return false;
  // }

  if (0 != blake2b_Init(&ada_signer.ctx, 32)) return false;
  // Inputs, outputs and fee are mandatory, count the number of optional fields
  // present.
  ada_signer.tx_dict_items_count = 3;
  if (ada_signer.signertx->has_ttl) ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->certificates_count > 0)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->withdrawals_count > 0)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->has_auxiliary_data) ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->has_validity_interval_start)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->minting_asset_groups_count > 0)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->has_include_network_id &&
      ada_signer.signertx->include_network_id)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->has_script_data_hash)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->collateral_inputs_count > 0)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->required_signers_count > 0)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->has_has_collateral_return &&
      ada_signer.signertx->has_collateral_return) {
    ada_signer.tx_dict_items_count++;
  }
  if (ada_signer.signertx->has_total_collateral)
    ada_signer.tx_dict_items_count++;
  if (ada_signer.signertx->reference_inputs_count > 0)
    ada_signer.tx_dict_items_count++;
  blake2b_256_append_cbor_tx_body(&ada_signer.ctx, CBOR_TYPE_MAP,
                                  ada_signer.tx_dict_items_count);

  ada_signer.state = TX_HASH_BUILDER_INIT;
  ada_signer.remainingInputs = ada_signer.signertx->inputs_count;
  ada_signer.remainingOutputs = ada_signer.signertx->outputs_count;
  ada_signer.remainingWithdrawals = ada_signer.signertx->withdrawals_count;
  ada_signer.remainingCertificates = ada_signer.signertx->certificates_count;
  ada_signer.remainingCollateralInputs =
      ada_signer.signertx->collateral_inputs_count;
  ada_signer.remainingRequiredSigners =
      ada_signer.signertx->required_signers_count;
  ada_signer.remainingMintingAssetGroupsCount =
      ada_signer.signertx->minting_asset_groups_count;

  if (ada_signer.signertx->has_reference_inputs_count)
    ada_signer.remainingReferenceInputs =
        ada_signer.signertx->reference_inputs_count;

  ada_signer.is_feeed = false;
  ada_signer.is_finished = false;

  txHashBuilder_enterInputs();
  msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
  return true;
}

void cardano_txack(void) {
  if (ada_signer.state == TX_HASH_BUILDER_IN_AUX_DATA) {
    msg_write(MessageType_MessageType_CardanoTxItemAck, &ada_msg_item_ack);
    if (ada_signer.tx_dict_items_count > 0) {
      ada_signer.state = TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START;
      hash_stage();
    }
  } else if (ada_signer.state == TX_HASH_BUILDER_FINISHED) {
    ada_signer.state = TX_SIGN_FINISHED;
    CardanoTxBodyHash resp;
    memset(&resp, 0, sizeof(CardanoTxBodyHash));
    resp.tx_hash.size = 32;
    memcpy(resp.tx_hash.bytes, ada_signer.digest, 32);
    msg_write(MessageType_MessageType_CardanoTxBodyHash, &resp);
  } else {
    msg_write(MessageType_MessageType_CardanoSignTxFinished,
              &ada_msg_sign_tx_finished);
  }
}

bool cardano_txwitness(const CardanoTxWitnessRequest *msg,
                       CardanoTxWitnessResponse *resp) {
  if (!ada_signer.is_feeed) {
    txHashBuilder_addFee(ada_signer.signertx->fee);
    ada_signer.is_feeed = true;
  }
  if (!ada_signer.is_finished) {
    blake2b_Final(&ada_signer.ctx, ada_signer.digest, 32);
    if (!layoutFee()) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return false;
    }
    ada_signer.state = TX_HASH_BUILDER_FINISHED;
    ada_signer.is_finished = true;
  }
  HDNode node = {0};
  uint32_t fingerprint;
  if (!deriveCardanoIcaruNode(&node, msg->path, msg->path_count,
                              &fingerprint)) {
    return false;
  }
  resp->pub_key.size = 32;
  memcpy(resp->pub_key.bytes, node.public_key + 1, 32);
#if EMULATOR
  ed25519_public_key pk = {0};
  ed25519_publickey_ext(node.private_key_extension, pk);
  ed25519_sign_ext(ada_signer.digest, 32, node.private_key,
                   node.private_key_extension, resp->signature.bytes);
#else
  if (hdnode_sign(&node, ada_signer.digest, 32, 0, resp->signature.bytes, NULL,
                  NULL) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Failed to sign");
    return false;
  }
#endif

  resp->signature.size = 64;
  if ((msg->path[0] == 2147483692) &&
      (msg->path[1] == 2147485463)) {  // BYRON_ROOT = [44,1815...]
    resp->type = CardanoTxWitnessType_BYRON_WITNESS;
    resp->has_chain_code = true;
    resp->chain_code.size = 32;
    memcpy(resp->chain_code.bytes, node.chain_code, 32);
  } else {
    resp->type = CardanoTxWitnessType_SHELLEY_WITNESS;
    resp->has_chain_code = false;
  }

  return true;
}

#define STAKING_CHANGE 2
#define STAKING_INDEX 0

static inline void write_cbor_to_buffer(uint8_t *buffer, size_t *index,
                                        const uint8_t *data, size_t data_size) {
  memcpy(buffer + *index, data, data_size);
  *index += data_size;
}

bool ada_sign_messages(const CardanoSignMessage *msg,
                       CardanoMessageSignature *resp) {
  uint8_t data[1024 + 128] = {0};
  uint8_t sig_structure[1024 + 128] = {0};
  uint8_t phdr_encoded[128] = {0};
  uint8_t sig[64];
  size_t data_index = 0, phdr_encoded_index = 0, sig_structure_index = 0;
  size_t size = 0;
  uint32_t *staking_path = NULL;
  const uint32_t *address_n = msg->address_n;
  uint32_t _staking_path[5];
  CardanoAddressType address_type =
      msg->has_address_type ? msg->address_type : CardanoAddressType_BASE;
  switch (msg->address_type) {
    case CardanoAddressType_BYRON:
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "BYRON ADDRESS NOT SUPPORTED");
      return false;
    case CardanoAddressType_BASE:
    case CardanoAddressType_REWARD:
      if (msg->address_n_count != 5) {
        fsm_sendFailure(FailureType_Failure_DataError, "Invalid path");
        return false;
      }
      memcpy(_staking_path, msg->address_n, 3 * sizeof(uint32_t));
      _staking_path[3] = STAKING_CHANGE;
      _staking_path[4] = STAKING_INDEX;
      staking_path = _staking_path;
      if (msg->address_type == CardanoAddressType_REWARD) {
        address_n = NULL;
      }
      break;
    case CardanoAddressType_ENTERPRISE:
      break;
    default:
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "UNSUPPORTED ADDRESS TYPE");
      return false;
  }
  uint8_t address_bytes[57];
  int address_bytes_len = 0;
  CardanoAddressParametersType address_params = {
      .address_type = address_type,
      .address_n_count = address_n ? msg->address_n_count : 0,
      .address_n_staking_count = staking_path ? 5 : 0,
      .has_staking_key_hash = false,
      .has_certificate_pointer = false,
      .has_script_payment_hash = false,
      .has_script_staking_hash = false};
  if (address_params.address_n_count > 0) {
    memcpy(address_params.address_n, address_n,
           address_params.address_n_count * sizeof(uint32_t));
  }
  if (address_params.address_n_staking_count > 0) {
    memcpy(address_params.address_n_staking, staking_path,
           address_params.address_n_staking_count * sizeof(uint32_t));
  }
  if (!derive_bytes(&address_params, msg->network_id, MAINNET_PROTOCOL_MAGIC,
                    address_bytes, &address_bytes_len)) {
    return false;
  }
  if (address_bytes_len != sizeof(address_bytes)) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Invalid address bytes length");
    return false;
  }
  char address_str[128] = {0};
  if (!encode_human_readable(address_bytes, address_bytes_len, address_str)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid address");
    return false;
  }
  if (!fsm_layoutSignMessage("ADA", address_str, msg->message.bytes,
                             msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return false;
  }

  // phdr={
  //     1: -8, # Algorithm: EdDSA,
  //     "address": address_bytes
  // }
  uint8_t buffer[10] = {0};
  size = cbor_writeToken(CBOR_TYPE_MAP, 2, buffer, sizeof(buffer));
  write_cbor_to_buffer(phdr_encoded, &phdr_encoded_index, buffer, size);

  size = cbor_writeToken(CBOR_TYPE_UNSIGNED, 1, buffer, sizeof(buffer));
  write_cbor_to_buffer(phdr_encoded, &phdr_encoded_index, buffer, size);

  size = cbor_writeToken(CBOR_TYPE_NEGATIVE, -8, buffer, sizeof(buffer));
  write_cbor_to_buffer(phdr_encoded, &phdr_encoded_index, buffer, size);

  size = cbor_writeToken(CBOR_TYPE_TEXT, 7, buffer, sizeof(buffer));
  write_cbor_to_buffer(phdr_encoded, &phdr_encoded_index, buffer, size);
  write_cbor_to_buffer(phdr_encoded, &phdr_encoded_index, (uint8_t *)"address",
                       7);

  size = cbor_writeToken(CBOR_TYPE_BYTES, address_bytes_len, buffer,
                         sizeof(buffer));
  write_cbor_to_buffer(phdr_encoded, &phdr_encoded_index, buffer, size);
  write_cbor_to_buffer(phdr_encoded, &phdr_encoded_index, address_bytes,
                       address_bytes_len);
  // msg = [
  //         "phdr": phdr,
  //         "uhdr": {"hashed": False},
  //         "payload": msg.message.bytes,
  //         "sig": sig
  // ]
  size = cbor_writeToken(CBOR_TYPE_ARRAY, 4, buffer, sizeof(buffer));
  write_cbor_to_buffer(data, &data_index, buffer, size);

  size = cbor_writeToken(CBOR_TYPE_BYTES, phdr_encoded_index, buffer,
                         sizeof(buffer));
  write_cbor_to_buffer(data, &data_index, buffer, size);
  write_cbor_to_buffer(data, &data_index, phdr_encoded, phdr_encoded_index);

  // Sign1Message.uhdr  = {"hashed": False}
  data[data_index++] = CBOR_TYPE_MAP | 1;
  size = cbor_writeToken(CBOR_TYPE_TEXT, 6, buffer, sizeof(buffer));
  write_cbor_to_buffer(data, &data_index, buffer, size);
  write_cbor_to_buffer(data, &data_index, (uint8_t *)"hashed", 6);
  data[data_index++] = CBOR_TYPE_FALSE;

  // Sign1Message.payload
  size = cbor_writeToken(CBOR_TYPE_BYTES, msg->message.size, buffer,
                         sizeof(buffer));
  write_cbor_to_buffer(data, &data_index, buffer, size);
  write_cbor_to_buffer(data, &data_index, msg->message.bytes,
                       msg->message.size);

  // Signature1 sig_structure = ["Signature1", phdr_encoded, b"", payload]
  size = cbor_writeToken(CBOR_TYPE_ARRAY, 4, buffer, sizeof(buffer));
  write_cbor_to_buffer(sig_structure, &sig_structure_index, buffer, size);

  size = cbor_writeToken(CBOR_TYPE_TEXT, 10, buffer, sizeof(buffer));
  write_cbor_to_buffer(sig_structure, &sig_structure_index, buffer, size);
  write_cbor_to_buffer(sig_structure, &sig_structure_index,
                       (uint8_t *)"Signature1", 10);

  size = cbor_writeToken(CBOR_TYPE_BYTES, phdr_encoded_index, buffer,
                         sizeof(buffer));
  write_cbor_to_buffer(sig_structure, &sig_structure_index, buffer, size);
  write_cbor_to_buffer(sig_structure, &sig_structure_index, phdr_encoded,
                       phdr_encoded_index);

  size = cbor_writeToken(CBOR_TYPE_BYTES, 0, buffer, sizeof(buffer));
  write_cbor_to_buffer(sig_structure, &sig_structure_index, buffer, size);

  size = cbor_writeToken(CBOR_TYPE_BYTES, msg->message.size, buffer,
                         sizeof(buffer));
  write_cbor_to_buffer(sig_structure, &sig_structure_index, buffer, size);
  write_cbor_to_buffer(sig_structure, &sig_structure_index, msg->message.bytes,
                       msg->message.size);
  HDNode node = {0};
  uint32_t _fingerprint;

  if (!deriveCardanoIcaruNode(&node, address_n ? address_n : staking_path, 5,
                              &_fingerprint)) {
    return false;
  }
#if EMULATOR
  ed25519_sign_ext(sig_structure, sig_structure_index, node->private_key,
                   node->private_key_extension, sig);
#else
  if (hdnode_sign(&node, sig_structure, sig_structure_index, 0, sig, NULL,
                  NULL) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Failed to sign message");
    return false;
  }
#endif

  size = cbor_writeToken(CBOR_TYPE_BYTES, 64, buffer, sizeof(buffer));
  write_cbor_to_buffer(data, &data_index, buffer, size);
  write_cbor_to_buffer(data, &data_index, sig, 64);

  memcpy(resp->signature.bytes, data, data_index);
  resp->signature.size = data_index;

  /*
      key_to_return = {
        1: 1, # KpKty: KtyOKP,
        3: -8, # KpAlg: EdDSA,
        -1: 6, # OKPKpCurve: Ed25519,
        -2: verification_key,  # OKPKpX: public key
    }
  */
  const uint8_t *verification_key = node.public_key + 1;
  data_index = 0;
  size = cbor_writeToken(CBOR_TYPE_MAP, 4, buffer, sizeof(buffer));
  write_cbor_to_buffer(data, &data_index, buffer, size);

  uint8_t key_data[] = {0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20};
  write_cbor_to_buffer(data, &data_index, key_data, sizeof(key_data));
  write_cbor_to_buffer(data, &data_index, verification_key, 32);

  memcpy(resp->key.bytes, data, data_index);
  resp->key.size = data_index;

  return true;
}
