#include "fido2/cose_key.h"
#include "fido2/ctap.h"
#include "fido2/resident_credential.h"

void fsm_msgWebAuthnListResidentCredentials(
    const WebAuthnListResidentCredentials *msg) {
  CHECK_INITIALIZED
  CHECK_PIN
  RESP_INIT(WebAuthnCredentials);

  if (!check_se_fido_seed(NULL)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "FIDO seed generation failed");
    return;
  }

  CTAP_credential_id_storage cred_id_storage = {0};
  uint16_t len;
  uint8_t status;
  static bool is_protect_button_pressed = false;
  static uint8_t last_index = 0;

  if (msg->has_request_list_index && msg->request_list_index) {
    uint8_t count = 0;
    layoutDialogAdapterEx(_(FIDO_2_LIST_CREDENTIALS), NULL, NULL,
                          &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL,
                          NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
    is_protect_button_pressed = true;
    for (uint8_t i = 0; i < FIDO2_RESIDENT_CREDENTIALS_COUNT; i++) {
      len = sizeof(CTAP_credential_id_storage) -
            FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN;
      status = se_get_fido2_resident_credentials(i, cred_id_storage.rp_id_hash,
                                                 &len);
      if (status == SE_FIDO2_SLOT_DATA_OK) {
        resp->id_map[0].bytes[count] = i;
        last_index = i;
        count++;
      }
      if (count > sizeof(resp->id_map[0].bytes)) {
        break;
      }
    }
    resp->id_map_count = 1;
    resp->id_map[0].size = count;
    layoutHome();
  } else {
    if (!is_protect_button_pressed) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Please get the index information first ");
      layoutHome();
      return;
    }
    if (!msg->has_index) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Invalid credential index.");
      return;
    }
    if (msg->index >= FIDO2_RESIDENT_CREDENTIALS_COUNT) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Credential index out of range.");
      return;
    }

    if (last_index == msg->index) {
      is_protect_button_pressed = false;
    }

    status = se_get_fido2_resident_credentials(
        msg->index, cred_id_storage.rp_id_hash, &len);
    if (status == SE_FIDO2_SLOT_DATA_NULL) {
      resp->credentials_count = 0;
      msg_write(MessageType_MessageType_WebAuthnCredentials, resp);
      return;
    } else if (status == SE_FIDO2_SLOT_DATA_OK) {
      resp->credentials_count = 1;
      resp->credentials[0].index = msg->index;
    }

    CTAP_credentialDescriptor desc = {0};
    desc.type = PUB_KEY_CRED_PUB_KEY;
    desc.cred_id_len = len - RP_ID_HASH_LENGTH;
    memcpy(desc.cred_id, cred_id_storage.credential_id, desc.cred_id_len);
    if (ctap_authenticate_credential_data(cred_id_storage.rp_id_hash, &desc) ==
        0) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "The credential data is invalid.");
      return;
    }

    resp->credentials_count = 1;
    resp->credentials[0].has_index = true;
    resp->credentials[0].index = msg->index;

    if (strlen(desc.credential.rp.id) > 0) {
      resp->credentials[0].has_rp_id = true;
      strlcpy(resp->credentials[0].rp_id, desc.credential.rp.id,
              sizeof(resp->credentials[0].rp_id));
    }

    if (strlen(desc.credential.rp.name) > 0) {
      resp->credentials[0].has_rp_name = true;
      strlcpy(resp->credentials[0].rp_name, desc.credential.rp.name,
              sizeof(resp->credentials[0].rp_name));
    }

    if (desc.credential.user.id_size > 0) {
      resp->credentials[0].has_user_id = true;
      memcpy(resp->credentials[0].user_id.bytes, desc.credential.user.id,
             desc.credential.user.id_size);
      resp->credentials[0].user_id.size = desc.credential.user.id_size;
    }

    if (strlen(desc.credential.user.name) > 0) {
      resp->credentials[0].has_user_name = true;
      strlcpy(resp->credentials[0].user_name, desc.credential.user.name,
              sizeof(resp->credentials[0].user_name));
    }

    if (strlen(desc.credential.user.displayName) > 0) {
      resp->credentials[0].has_user_display_name = true;
      strlcpy(resp->credentials[0].user_display_name,
              desc.credential.user.displayName,
              sizeof(resp->credentials[0].user_display_name));
    }

    resp->credentials[0].has_creation_time = true;
    resp->credentials[0].creation_time = desc.credential.creation_time;

    resp->credentials[0].has_hmac_secret = true;
    resp->credentials[0].hmac_secret = desc.credential.hmac_secret;

    resp->credentials[0].has_use_sign_count = true;
    resp->credentials[0].use_sign_count = true;

    resp->credentials[0].has_algorithm = true;
    resp->credentials[0].algorithm = COSE_ALG_ES256;

    resp->credentials[0].has_curve = true;
    resp->credentials[0].curve = COSE_KEY_CRV_P256;

    resp->credentials[0].has_id = true;
    memcpy(resp->credentials[0].id.bytes, cred_id_storage.credential_id,
           len - RP_ID_HASH_LENGTH);
    resp->credentials[0].id.size = len - RP_ID_HASH_LENGTH;
  }

  msg_write(MessageType_MessageType_WebAuthnCredentials, resp);

  return;
}
void fsm_msgWebAuthnAddResidentCredential(
    const WebAuthnAddResidentCredential *msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_credential_id) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Credential ID not provided.");
    return;
  }
  if (msg->credential_id.size < CTAP_CREDENTIAL_ID_MIN_SIZE ||
      memcmp(CRED_ID_VERSION, msg->credential_id.bytes, 4) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Credential ID data is invalid.");
    return;
  }

  if (!check_se_fido_seed(NULL)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "FIDO seed generation failed");
    return;
  }

  CTAP_credentialDescriptor desc = {0};
  desc.type = PUB_KEY_CRED_PUB_KEY;
  desc.cred_id_len = msg->credential_id.size;
  memcpy(desc.cred_id, msg->credential_id.bytes, desc.cred_id_len);

  if (!ctap_authenticate_credential_data(NULL, &desc)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "The credential you are trying to import does\nnot belong "
                    "to this authenticator.");
    return;
  }

  layoutDialogAdapterEx(_(FIDO_2_IMPORT_CREDENTIAL), NULL, NULL,
                        &bmp_bottom_right_confirm, NULL, NULL,
                        _(GLOBAL_APP_NAME), desc.credential.rp.id,
                        _(GLOBAL_ACCOUNT), desc.credential.user.name);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  uint8_t rp_id_hash[32];
  sha256_Raw((uint8_t *)desc.credential.rp.id, desc.credential.rp.size,
             rp_id_hash);

  if (!resident_credential_store(rp_id_hash, desc.credential.user.id,
                                 desc.credential.user.id_size, desc.cred_id,
                                 desc.cred_id_len)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to store resident credential");
    return;
  }
  fsm_sendSuccess("Credential imported");
  layoutHome();
  return;
}
void fsm_msgWebAuthnRemoveResidentCredential(
    const WebAuthnRemoveResidentCredential *msg) {
  CHECK_INITIALIZED
  CHECK_PIN
  if (!msg->has_index) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Invalid credential index.");
    return;
  }
  if (msg->index >= FIDO2_RESIDENT_CREDENTIALS_COUNT) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Credential index out of range.");
    return;
  }
  if (!check_se_fido_seed(NULL)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "FIDO seed generation failed");
    return;
  }

  CTAP_credential_id_storage cred_id_storage = {0};
  CTAP_credentialDescriptor desc = {0};
  uint16_t len = sizeof(CTAP_credential_id_storage) -
                 FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN;

  uint8_t status = se_get_fido2_resident_credentials(
      msg->index, cred_id_storage.rp_id_hash, &len);
  if (status == SE_FIDO2_SLOT_DATA_NULL) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "The credential data is invalid.");
    return;
  } else if (status == SE_FIDO2_SLOT_DATA_OK) {
    desc.type = PUB_KEY_CRED_PUB_KEY;
    desc.cred_id_len = len - RP_ID_HASH_LENGTH;
    memcpy(desc.cred_id, cred_id_storage.credential_id, desc.cred_id_len);
    ctap_authenticate_credential_data(cred_id_storage.rp_id_hash, &desc);
  }

  layoutDialogAdapterEx(_(FIDO_2_REMOVE_CREDENTIALS), NULL, NULL,
                        &bmp_bottom_right_confirm, NULL, NULL,
                        _(GLOBAL_APP_NAME), desc.credential.rp.id,
                        _(GLOBAL_ACCOUNT), desc.credential.user.name);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (se_delete_fido2_resident_credentials(msg->index)) {
    fsm_sendSuccess("Credential removed");
  } else {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to remove resident credential");
  }
  layoutHome();
  return;
}
