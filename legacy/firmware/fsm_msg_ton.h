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
#define COIN_TYPE 607
#include <unistd.h>
void fsm_msgTonGetAddress(const TonGetAddress *msg) {
  CHECK_INITIALIZED;

  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, ED25519_NAME, true),
              "Invalid path");
  CHECK_PIN;

  RESP_INIT(TonAddress);

  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);
  memmove(resp->public_key.bytes, node->public_key + 1, 32);
  resp->public_key.size = 32;

  char raw_address[32] = {0};
  ton_get_address_from_public_key(node->public_key + 1, raw_address);
  ton_to_user_friendly(msg->workchain, (const char *)raw_address,
                       msg->is_bounceable, msg->is_testnet_only, resp->address);

  if (msg->has_show_display && msg->show_display) {
    char desc[64] = {0};
    strlcpy(desc, _(T__CHAIN_STR_ADDRESS), sizeof(desc));
    bracket_replace(desc, "Ton");

    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, false, NULL, 0, 0, NULL)) {
      return;
    }
  }

  msg_write(MessageType_MessageType_TonAddress, resp);

  layoutHome();
}

void fsm_msgTonSignMessage(const TonSignMessage *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, ED25519_NAME, true),
              "Invalid path");
  CHECK_PIN
  RESP_INIT(TonSignedMessage);
  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);

  if (ton_sign_message(msg, node, resp)) {
    msg_write(MessageType_MessageType_TonSignedMessage, resp);
  } else {
    fsm_sendFailure(FailureType_Failure_DataError, "Signing failed");
  }

  layoutHome();
}

void fsm_msgTonSignProof(const TonSignProof *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, ED25519_NAME, true),
              "Invalid path");
  CHECK_PIN
  RESP_INIT(TonSignedProof);
  HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  hdnode_fill_public_key(node);

  if (ton_sign_proof(msg, node, resp)) {
    msg_write(MessageType_MessageType_TonSignedProof, resp);
  } else {
    fsm_sendFailure(FailureType_Failure_DataError, "Signing Proof failed");
  }

  layoutHome();
}