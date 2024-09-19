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

#ifndef __FSM_MSG_ALEPHIUM_H__
#define __FSM_MSG_ALEPHIUM_H__

#undef COIN_TYPE
#define COIN_TYPE 1234

void fsm_msgAlephiumGetAddress(const AlephiumGetAddress *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");
  CHECK_PIN
  RESP_INIT(AlephiumAddress);

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Failed to derive node");
    return;
  }
  if (!alephium_get_address(node, msg, resp)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to get Alephium address");
    layoutHome();
    return;
  }
  if (msg->show_display) {
    char desc[16] = "Alephium";
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0,
                           resp->derived_path, resp->derived_path_count, false,
                           NULL, 0, 0, NULL)) {
      return;
    }
  }
  msg_write(MessageType_MessageType_AlephiumAddress, resp);
  layoutHome();
}

void fsm_msgAlephiumSignTx(const AlephiumSignTx *msg) {
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);
  alephium_sign_tx(node, msg);
}

void fsm_msgAlephiumBytecodeAck(const AlephiumBytecodeAck *msg) {
  alephium_handle_bytecode_ack(msg);
}

void fsm_msgAlephiumTxAck(const AlephiumTxAck *msg) {
  CHECK_UNLOCKED
  alephium_signing_txack(msg);
}

void fsm_msgAlephiumSignMessage(const AlephiumSignMessage *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");
  if (msg->message.size == 0 || msg->message.size > ALEPHIUM_MAX_MESSAGE_SIZE) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid message length");
    return;
  }

  if (msg->has_message_type &&
      memcmp(msg->message_type.bytes, "alephium", 8) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Unsupported Message Type");
    return;
  }

  CHECK_PIN

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Failed to derive node");
    return;
  }

  RESP_INIT(AlephiumMessageSignature);

  if (!alephium_sign_message(node, msg, resp)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to sign Alephium message");
    layoutHome();
    return;
  }

  if (!fsm_layoutSignMessage("Alephium", resp->address, msg->message.bytes,
                             msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_AlephiumMessageSignature, resp);
  layoutHome();
}

#endif
