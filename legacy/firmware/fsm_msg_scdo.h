/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2023 OneKey Team <core@onekey.so>
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

#undef COIN_TYPE
#define COIN_TYPE 541

void fsm_msgScdoSignTx(ScdoSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");

  CHECK_PIN

  const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                          msg->address_n_count, NULL);
  if (!node) return;

  char scdo_address[43];
  uint8_t pubkey[65] = {0};
  if (!ecdsa_uncompress_pubkey(node->curve->params, node->public_key, pubkey)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to uncompress pubkey");
  }
  scdo_eth_2_address(pubkey + 1, scdo_address, sizeof(scdo_address));
  scdo_sign_tx(msg, node, scdo_address);
}

void fsm_msgScdoTxAck(const ScdoTxAck *msg) { scdo_signing_txack(msg); }

void fsm_msgScdoGetAddress(const ScdoGetAddress *msg) {
  RESP_INIT(ScdoAddress);

  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");

  CHECK_PIN

  const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                          msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkey[65] = {0};
  ecdsa_uncompress_pubkey(node->curve->params, node->public_key, pubkey);
  scdo_eth_2_address(pubkey + 1, resp->address, sizeof(resp->address));

  if (msg->has_show_display && msg->show_display) {
    char desc[64] = {0};
    strlcpy(desc, _(T__CHAIN_STR_ADDRESS), sizeof(desc));
    bracket_replace(desc, "SCDO");
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, false, NULL, 0, 0, NULL)) {
      return;
    }
  }

  msg_write(MessageType_MessageType_ScdoAddress, resp);
  layoutHome();
}

void fsm_msgScdoSignMessage(const ScdoSignMessage *msg) {
  RESP_INIT(ScdoSignedMessage);

  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");

  CHECK_PIN

  const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                          msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkey[65] = {0};
  ecdsa_uncompress_pubkey(node->curve->params, node->public_key, pubkey);
  scdo_eth_2_address(pubkey + 1, resp->address, sizeof(resp->address));
  resp->has_address = true;

  if (!fsm_layoutSignMessage("SCDO", resp->address, msg->message.bytes,
                             msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  scdo_sign_message(msg, node, resp);
  layoutHome();
}
