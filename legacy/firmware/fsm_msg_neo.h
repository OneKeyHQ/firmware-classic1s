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
#define COIN_TYPE 888

void fsm_msgNeoGetAddress(const NeoGetAddress *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, NIST256P1_NAME, true),
              "Invalid path");
  CHECK_PIN

  RESP_INIT(NeoAddress);

  HDNode *node = fsm_getDerivedNode(NIST256P1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);
  if (!neo_address_from_pubkey(node->public_key, resp->address)) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Failed to get address");
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    char desc[64] = {0};
    strlcpy(desc, _(T__CHAIN_STR_ADDRESS), sizeof(desc));
    bracket_replace(desc, "Neo");
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, false, NULL, 0, 0, NULL)) {
      return;
    }
  }
  resp->has_address = true;
  resp->has_public_key = true;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);
  msg_write(MessageType_MessageType_NeoAddress, resp);

  layoutHome();
}

void fsm_msgNeoSignTx(const NeoSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, NIST256P1_NAME, true),
              "Invalid path");
  CHECK_PIN

  RESP_INIT(NeoSignedTx);

  HDNode *node = fsm_getDerivedNode(NIST256P1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);

  if (!neo_sign_tx(msg, node, resp)) {
    layoutHome();
    return;
  }
  resp->signature.size = 64;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);
  msg_write(MessageType_MessageType_NeoSignedTx, resp);
  layoutHome();
}
