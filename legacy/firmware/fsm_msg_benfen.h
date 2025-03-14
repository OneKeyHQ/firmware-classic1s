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
#undef COIN_TYPE
#define COIN_TYPE 728
void fsm_msgBenfenGetAddress(const BenfenGetAddress *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, ED25519_NAME, true),
              "Invalid path");
  CHECK_PIN

  RESP_INIT(BenfenAddress);

  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);
  resp->has_address = true;

  benfen_get_address_from_public_key(node->public_key + 1, resp->address);

  if (msg->has_show_display && msg->show_display) {
    char desc[64] = {0};
    strlcpy(desc, _(T__CHAIN_STR_ADDRESS), sizeof(desc));
    bracket_replace(desc, "Benfen");
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, true, NULL, 0, 0, NULL)) {
      return;
    }
  }

  msg_write(MessageType_MessageType_BenfenAddress, resp);
  layoutHome();
}

void fsm_msgBenfenSignTx(const BenfenSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, ED25519_NAME, true),
              "Invalid path");
  CHECK_PIN

  RESP_INIT(BenfenSignedTx);

  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);
  if (msg->has_data_length && msg->data_length > 0) {
    benfen_signing_init(msg, node);
  } else {
    benfen_sign_tx(msg, node, resp);
    layoutHome();
  }
}

void fsm_msgBenfenTxAck(BenfenTxAck *msg) {
  CHECK_UNLOCKED

  benfen_signing_txack(msg);
}

void fsm_msgBenfenSignMessage(BenfenSignMessage *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, ED25519_NAME, true),
              "Invalid path");
  CHECK_PIN

  RESP_INIT(BenfenMessageSignature);

  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);

  benfen_get_address_from_public_key(node->public_key + 1, resp->address);

  if (!fsm_layoutSignMessage("Benfen", resp->address, msg->message.bytes,
                             msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  benfen_message_sign(msg, node, resp);
  layoutHome();
}
