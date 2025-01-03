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
#define COIN_TYPE 309
void fsm_msgNervosGetAddress(const NervosGetAddress *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");
  CHECK_PIN
  RESP_INIT(NervosAddress);
  if (strcmp(msg->network, "ckt") != 0 && strcmp(msg->network, "ckb") != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    __("network format error"));
    layoutHome();
    return;
  }
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  hdnode_fill_public_key(node);
  if (!node) return;
  nervos_get_address_from_public_key(node->public_key, resp->address,
                                     msg->network);

  if (msg->has_show_display && msg->show_display) {
    char desc[16] = {0};
    strcat(desc, "Nervos");
    strcat(desc, __("Address:"));
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, false, NULL, 0, 0, NULL)) {
      return;
    }
  }
  msg_write(MessageType_MessageType_NervosAddress, resp);
  layoutHome();
}

void fsm_msgNervosSignTx(const NervosSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");
  CHECK_PIN
  RESP_INIT(NervosSignedTx);
  if (strcmp(msg->network, "ckt") != 0 && strcmp(msg->network, "ckb") != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    __("network format error"));
    layoutHome();
    return;
  }
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);
  nervos_get_address_from_public_key(node->public_key, resp->address,
                                     msg->network);
  if (msg->has_data_length && msg->data_length > 0 &&
      msg->data_length > msg->data_initial_chunk.size) {
    nervos_sign_sighash_init(node, msg, resp);
  } else {
    nervos_sign_sighash(node, msg, resp);
    msg_write(MessageType_MessageType_NervosSignedTx, resp);
    layoutHome();
  }
}

void fsm_msgNervosTxAck(const NervosTxAck *msg) {
  CHECK_UNLOCKED
  nervos_signing_txack(msg);
}
