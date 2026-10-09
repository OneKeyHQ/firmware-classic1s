
#include "resident_credential.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "../i18n/keys.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "se_chip.h"

uint32_t resident_credential_find_by_rp_id_hash(
    const uint8_t *rp_id_hash, CTAP_credentialDescriptor *cred_desc,
    uint32_t max_count) {
  uint8_t indexes[FIDO2_RESIDENT_CREDENTIALS_COUNT] = {0};
  uint8_t index_count = sizeof(indexes);
  uint8_t plaintext[SE_FIDO_RESIDENT_CREDENTIAL_PLAINTEXT_MAX_LEN] = {0};
  uint32_t count = 0;
  UI_WAIT_CALLBACK ui_callback = se_get_ui_callback();

  if (rp_id_hash == NULL || cred_desc == NULL || max_count == 0 ||
      max_count > FIDO2_RESIDENT_CREDENTIALS_COUNT) {
    goto cleanup;
  }
  memzero(cred_desc, max_count * sizeof(*cred_desc));
  if (!se_fido_resident_list(indexes, &index_count)) {
    goto cleanup;
  }
  for (uint8_t i = 0; i < index_count && count < max_count; i++) {
    CTAP_credentialDescriptor candidate = {0};
    uint8_t candidate_hash[RP_ID_HASH_LENGTH] = {0};
    uint16_t credential_id_len = sizeof(candidate.cred_id);
    uint16_t plaintext_len = sizeof(plaintext);

    if (ui_callback != NULL) {
      ui_callback(_(C__PROCESSING_ETC), (i + 1U) * 1000U / index_count);
    }
    if (!se_fido_resident_read(indexes[i], candidate.cred_id,
                               &credential_id_len, plaintext,
                               &plaintext_len) ||
        ctap_parse_credential_id(&candidate.credential, plaintext,
                                 plaintext_len) != CTAP1_ERR_SUCCESS ||
        candidate.credential.rp.size == 0) {
      memzero(&candidate, sizeof(candidate));
      memzero(candidate_hash, sizeof(candidate_hash));
      goto cleanup;
    }
    sha256_Raw((uint8_t *)candidate.credential.rp.id,
               candidate.credential.rp.size, candidate_hash);
    if (memcmp(candidate_hash, rp_id_hash, RP_ID_HASH_LENGTH) == 0) {
      candidate.type = PUB_KEY_CRED_PUB_KEY;
      candidate.cred_id_len = credential_id_len;
      memcpy(&cred_desc[count++], &candidate, sizeof(candidate));
    }
    memzero(&candidate, sizeof(candidate));
    memzero(candidate_hash, sizeof(candidate_hash));
    memzero(plaintext, sizeof(plaintext));
  }
  goto done;

cleanup:
  count = 0;
  if (cred_desc != NULL && max_count <= FIDO2_RESIDENT_CREDENTIALS_COUNT) {
    memzero(cred_desc, max_count * sizeof(*cred_desc));
  }

done:
  memzero(indexes, sizeof(indexes));
  memzero(plaintext, sizeof(plaintext));
  return count;
}

bool resident_credential_store(const uint8_t *rp_id_hash,
                               const uint8_t *user_id, uint32_t user_id_len,
                               const uint8_t *cred_id, uint32_t cred_id_len) {
  uint8_t slot_index = 0;
  uint8_t action = 0;
  bool result = false;

  if (rp_id_hash == NULL || user_id == NULL || cred_id == NULL ||
      cred_id_len < SE_FIDO_CREDENTIAL_ID_MIN_LEN ||
      cred_id_len > SE_FIDO_RESIDENT_CREDENTIAL_ID_MAX_LEN ||
      user_id_len == 0 || user_id_len > USER_ID_MAX_SIZE) {
    goto cleanup;
  }
  if (se_fido_resident_import(cred_id, (uint16_t)cred_id_len, &slot_index,
                              &action) == sectrue &&
      slot_index < FIDO2_RESIDENT_CREDENTIALS_COUNT &&
      (action == SE_FIDO_CREDENTIAL_ACTION_CREATED ||
       action == SE_FIDO_CREDENTIAL_ACTION_REPLACED)) {
    result = true;
  }

cleanup:
  memzero(&slot_index, sizeof(slot_index));
  memzero(&action, sizeof(action));
  layoutHome();
  return result;
}

// progress_ratio: 0-100
int resident_credential_info(uint8_t indexs[FIDO2_RESIDENT_CREDENTIALS_COUNT],
                             int progress_ratio) {
  UI_WAIT_CALLBACK ui_callback = se_get_ui_callback();
  uint8_t count = FIDO2_RESIDENT_CREDENTIALS_COUNT;

  if (indexs == NULL || !se_fido_resident_list(indexs, &count)) {
    if (indexs != NULL) memzero(indexs, FIDO2_RESIDENT_CREDENTIALS_COUNT);
    return -1;
  }
  if (ui_callback != NULL) {
    ui_callback(_(C__PROCESSING_ETC), progress_ratio);
  }
  return count;
}

int resident_credential_get_desc(uint8_t index,
                                 CTAP_credentialDescriptor *cred_desc) {
  uint8_t plaintext[SE_FIDO_RESIDENT_CREDENTIAL_PLAINTEXT_MAX_LEN] = {0};
  uint16_t credential_id_len;
  uint16_t plaintext_len = sizeof(plaintext);

  if (cred_desc == NULL) goto cleanup;
  memzero(cred_desc, sizeof(*cred_desc));
  credential_id_len = sizeof(cred_desc->cred_id);
  if (!se_fido_resident_read(index, cred_desc->cred_id, &credential_id_len,
                             plaintext, &plaintext_len) ||
      ctap_parse_credential_id(&cred_desc->credential, plaintext,
                               plaintext_len) != CTAP1_ERR_SUCCESS) {
    goto cleanup;
  }
  cred_desc->type = PUB_KEY_CRED_PUB_KEY;
  cred_desc->cred_id_len = credential_id_len;
  memzero(plaintext, sizeof(plaintext));
  return SE_FIDO2_SLOT_DATA_OK;

cleanup:
  if (cred_desc != NULL) memzero(cred_desc, sizeof(*cred_desc));
  memzero(plaintext, sizeof(plaintext));
  return SE_FIDO2_SLOT_DATA_INVALID;
}

bool resident_credential_delete(uint8_t index) {
  return se_fido_resident_delete(index) == sectrue;
}
