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
#define COIN_TYPE 111111
void fsm_msgKaspaGetAddress(const KaspaGetAddress *msg) {
  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");
  CHECK_PIN

  RESP_INIT(KaspaAddress);

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  CHECK_PARAM(msg->has_scheme && kaspa_valid_scheme(msg->scheme),
              "Invalid scheme");
  CHECK_PARAM(kaspa_valid_prefix(msg->prefix), "Invalid prefix");
  bool is_schnorr = (strcmp(msg->scheme, "schnorr") == 0);
  uint8_t *pub_key = node->public_key + (is_schnorr ? 1 : 0);
  uint32_t key_len = is_schnorr ? 32 : 33;
  bool use_tweak = !msg->has_use_tweak || msg->use_tweak;
  kaspa_get_address(pub_key, key_len, msg->prefix, resp->address, use_tweak);

  if (msg->has_show_display && msg->show_display) {
    char desc[64] = {0};
    strlcpy(desc, _(T__CHAIN_STR_ADDRESS), sizeof(desc));
    bracket_replace(desc, "Kaspa");
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, true, NULL, 0, 0, NULL)) {
      return;
    }
  }
  msg_write(MessageType_MessageType_KaspaAddress, resp);
  layoutHome();
}

#define SIGN_DYNAMIC                                                      \
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count, \
                                    COIN_TYPE, SECP256K1_NAME, true),     \
              "Invalid path");                                            \
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,       \
                                    msg->address_n_count, NULL);          \
  CHECK_PARAM(node, "Failed to get derived node");                        \
  hdnode_fill_public_key(node);                                           \
  if (input_count > 1) {                                                  \
    RESP_INIT(KaspaTxInputRequest);                                       \
    resp->request_index = input_index++;                                  \
    resp->has_signature = true;                                           \
    if (!kaspa_sign_sighash(node, msg->raw_message.bytes,                 \
                            msg->raw_message.size, resp->signature.bytes, \
                            &resp->signature.size)) {                     \
      kaspa_signing_abort();                                              \
      return;                                                             \
    }                                                                     \
    msg_write(MessageType_MessageType_KaspaTxInputRequest, resp);         \
  } else {                                                                \
    RESP_INIT(KaspaSignedTx);                                             \
    if (!kaspa_sign_sighash(node, msg->raw_message.bytes,                 \
                            msg->raw_message.size, resp->signature.bytes, \
                            &resp->signature.size)) {                     \
      kaspa_signing_abort();                                              \
      return;                                                             \
    }                                                                     \
    msg_write(MessageType_MessageType_KaspaSignedTx, resp);               \
    kaspa_signing_abort();                                                \
  }

#define KASPA_CHECK_OR_ABORT(cond, failure_type, errormsg) \
  if (!(cond)) {                                           \
    fsm_sendFailure((failure_type), (errormsg));           \
    kaspa_signing_abort();                                 \
    return;                                                \
  }

void fsm_msgKaspaSignTx(const KaspaSignTx *msg) {
  CHECK_INITIALIZED

  CHECK_PIN
  if (kaspa_is_streaming_signing(msg)) {
    if (!kaspa_streaming_signing_init(msg)) {
      kaspa_signing_abort();
      return;
    }
    RESP_INIT(KaspaTxRequest);
    if (!kaspa_send_request(resp)) {
      kaspa_signing_abort();
      return;
    }
    return;
  }

  if (kaspa_is_legacy_signing(msg)) {
    CHECK_PARAM(msg->input_count >= 1, "Invalid input count");
    CHECK_PARAM(kaspa_valid_scheme(msg->scheme), "Invalid scheme");
    CHECK_PARAM(kaspa_valid_prefix(msg->prefix), "Invalid prefix");

    kaspa_signing_init(msg);
    SIGN_DYNAMIC;
    return;
  }
}

void fsm_msgKaspaTxInputAck(const KaspaTxInputAck *msg) { SIGN_DYNAMIC; }

void fsm_msgKaspaTxAckInput(const KaspaTxAckInput *msg) {
  HDNode *node = NULL;

  KASPA_CHECK_OR_ABORT(kaspa_signing_mode() == KASPA_SIGNING_MODE_STREAMING,
                       FailureType_Failure_UnexpectedMessage,
                       "Not in Kaspa signing mode");

  KASPA_CHECK_OR_ABORT(
      fsm_common_path_check(msg->address_n, msg->address_n_count, COIN_TYPE,
                            SECP256K1_NAME, true),
      FailureType_Failure_DataError, "Invalid path");
  RESP_INIT(KaspaTxRequest);
  if (kaspa_signing_phase() == KASPA_PHASE_COLLECT_INPUTS) {
    if (!kaspa_process_input(msg)) {
      kaspa_signing_abort();
      return;
    }
  } else if (kaspa_signing_phase() == KASPA_PHASE_REPLAY_INPUT) {
    node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                              msg->address_n_count, NULL);
    KASPA_CHECK_OR_ABORT(node, FailureType_Failure_ProcessError,
                         "Failed to get derived node");
    if (!kaspa_prepare_prev_tx_verification(msg, node)) {
      kaspa_signing_abort();
      return;
    }
  } else if (kaspa_signing_phase() == KASPA_PHASE_SIGN_INPUTS) {
    node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                              msg->address_n_count, NULL);
    KASPA_CHECK_OR_ABORT(node, FailureType_Failure_ProcessError,
                         "Failed to get derived node");
    if (!kaspa_sign_input(msg, node, resp->signature.signature.bytes,
                          &resp->signature.signature.size)) {
      kaspa_signing_abort();
      return;
    }
  } else {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Invalid kaspa input ack received");
    kaspa_signing_abort();
    return;
  }
  if (!kaspa_send_request(resp)) {
    kaspa_signing_abort();
    return;
  }
}

void fsm_msgKaspaTxAckOutput(const KaspaTxAckOutput *msg) {
  KASPA_CHECK_OR_ABORT(kaspa_signing_mode() == KASPA_SIGNING_MODE_STREAMING,
                       FailureType_Failure_UnexpectedMessage,
                       "Not in Kaspa signing mode");
  KASPA_CHECK_OR_ABORT(kaspa_signing_phase() == KASPA_PHASE_COLLECT_OUTPUTS,
                       FailureType_Failure_UnexpectedMessage,
                       "Unexpected Kaspa output ack");

  HDNode *node = NULL;
  if (msg->address_n_count > 0) {
    KASPA_CHECK_OR_ABORT(
        fsm_common_path_check(msg->address_n, msg->address_n_count, COIN_TYPE,
                              SECP256K1_NAME, true),
        FailureType_Failure_DataError, "Invalid path");
    node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                              msg->address_n_count, NULL);
    KASPA_CHECK_OR_ABORT(node, FailureType_Failure_ProcessError,
                         "Failed to get derived node");
  }

  if (!kaspa_process_output(msg, node)) {
    kaspa_signing_abort();
    return;
  }

  RESP_INIT(KaspaTxRequest);
  if (!kaspa_send_request(resp)) {
    kaspa_signing_abort();
    return;
  }
}

void fsm_msgKaspaTxAckPayloadChunk(const KaspaTxAckPayloadChunk *msg) {
  KASPA_CHECK_OR_ABORT(kaspa_signing_mode() == KASPA_SIGNING_MODE_STREAMING,
                       FailureType_Failure_UnexpectedMessage,
                       "Not in Kaspa signing mode");
  KASPA_CHECK_OR_ABORT(
      kaspa_signing_phase() == KASPA_PHASE_COLLECT_PAYLOAD ||
          kaspa_signing_phase() == KASPA_PHASE_VERIFY_PREV_PAYLOAD,
      FailureType_Failure_UnexpectedMessage,
      "Unexpected kaspa payload chunk ack received");

  RESP_INIT(KaspaTxRequest);
  if (!kaspa_receive_payload(msg)) {
    kaspa_signing_abort();
    return;
  }
  if (!kaspa_send_request(resp)) {
    kaspa_signing_abort();
    return;
  }
}

void fsm_msgKaspaTxAckPrevMeta(const KaspaTxAckPrevMeta *msg) {
  KASPA_CHECK_OR_ABORT(kaspa_signing_mode() == KASPA_SIGNING_MODE_STREAMING,
                       FailureType_Failure_UnexpectedMessage,
                       "Not in Kaspa signing mode");
  KASPA_CHECK_OR_ABORT(kaspa_signing_phase() == KASPA_PHASE_VERIFY_PREV_META,
                       FailureType_Failure_UnexpectedMessage,
                       "Unexpected Kaspa previous metadata ack");

  if (!kaspa_process_prev_meta(msg)) {
    kaspa_signing_abort();
    return;
  }

  RESP_INIT(KaspaTxRequest);
  if (!kaspa_send_request(resp)) {
    kaspa_signing_abort();
    return;
  }
}

void fsm_msgKaspaTxAckPrevInput(const KaspaTxAckPrevInput *msg) {
  KASPA_CHECK_OR_ABORT(kaspa_signing_mode() == KASPA_SIGNING_MODE_STREAMING,
                       FailureType_Failure_UnexpectedMessage,
                       "Not in Kaspa signing mode");
  KASPA_CHECK_OR_ABORT(kaspa_signing_phase() == KASPA_PHASE_VERIFY_PREV_INPUTS,
                       FailureType_Failure_UnexpectedMessage,
                       "Unexpected Kaspa previous input ack");

  if (!kaspa_process_prev_input(msg)) {
    kaspa_signing_abort();
    return;
  }

  RESP_INIT(KaspaTxRequest);
  if (!kaspa_send_request(resp)) {
    kaspa_signing_abort();
    return;
  }
}

void fsm_msgKaspaTxAckPrevOutput(const KaspaTxAckPrevOutput *msg) {
  KASPA_CHECK_OR_ABORT(kaspa_signing_mode() == KASPA_SIGNING_MODE_STREAMING,
                       FailureType_Failure_UnexpectedMessage,
                       "Not in Kaspa signing mode");
  KASPA_CHECK_OR_ABORT(kaspa_signing_phase() == KASPA_PHASE_VERIFY_PREV_OUTPUTS,
                       FailureType_Failure_UnexpectedMessage,
                       "Unexpected Kaspa previous output ack");

  if (!kaspa_process_prev_output(msg)) {
    kaspa_signing_abort();
    return;
  }

  RESP_INIT(KaspaTxRequest);
  if (!kaspa_send_request(resp)) {
    kaspa_signing_abort();
    return;
  }
}
