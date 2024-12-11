
#include "resident_credential.h"
#include "se_chip.h"

uint32_t resident_credential_get_count(void) { return 0; }

uint32_t resident_credential_find_by_rp_id_hash(
    const uint8_t *rp_id_hash, CTAP_credentialDescriptor *cred_desc,
    uint32_t max_count) {
  CTAP_credential_id_storage cred_id_storage = {0};
  uint16_t len =
      sizeof(cred_id_storage) - FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN;
  uint32_t count = 0;
  for (uint32_t i = 0;
       i < FIDO2_RESIDENT_CREDENTIALS_COUNT && count < max_count; i++) {
    len = sizeof(cred_id_storage) - FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN;
    if (se_get_fido2_resident_credentials(i, cred_id_storage.rp_id_hash,
                                          &len) == SE_FIDO2_SLOT_DATA_OK) {
      ctap_printf("get resident credential %d\n", i);
      dump_hex1(NULL, cred_id_storage.rp_id_hash, len);
      if (memcmp(cred_id_storage.rp_id_hash, rp_id_hash, RP_ID_HASH_LENGTH) ==
          0) {
        ctap_printf("find same rp id hash\n");
        memcpy(cred_desc[count].cred_id, cred_id_storage.credential_id,
               len - RP_ID_HASH_LENGTH);
        cred_desc[count].cred_id_len = len - RP_ID_HASH_LENGTH;
        cred_desc[count].type = PUB_KEY_CRED_PUB_KEY;
        ctap_authenticate_credential_data(rp_id_hash, &cred_desc[count]);
        count++;
      }
    }
  }
  return count;
}

bool resident_credential_store(const uint8_t *rp_id_hash,
                               const uint8_t *user_id, const uint8_t *cred_id,
                               uint32_t cred_id_len) {
  CTAP_credentialDescriptor cred_id_desc = {0};
  CTAP_credential_id_storage cred_id_storage = {0};
  uint16_t len =
      sizeof(cred_id_storage) - FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN;

  int slot = -1;
  uint8_t status;

  for (uint32_t i = 0; i < FIDO2_RESIDENT_CREDENTIALS_COUNT; i++) {
    len = sizeof(cred_id_storage) - FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN;
    status =
        se_get_fido2_resident_credentials(i, cred_id_storage.rp_id_hash, &len);
    if (status == SE_FIDO2_SLOT_DATA_NULL) {
      if (slot == -1) {
        slot = i;
      }
      continue;
    } else if (status == SE_FIDO2_SLOT_DATA_OK) {
      if (memcmp(cred_id_storage.rp_id_hash, rp_id_hash, RP_ID_HASH_LENGTH) ==
          0) {
        cred_id_desc.type = PUB_KEY_CRED_PUB_KEY;
        cred_id_desc.cred_id_len = len - RP_ID_HASH_LENGTH;
        memcpy(cred_id_desc.cred_id, cred_id_storage.credential_id,
               len - RP_ID_HASH_LENGTH);
        ctap_authenticate_credential_data(rp_id_hash, &cred_id_desc);
        if (memcmp(cred_id_desc.credential.user.id, user_id,
                   cred_id_desc.credential.user.id_size) == 0) {
          ctap_printf("find same user id, override\n");
          slot = i;
          break;
        }
      }
    }
  }
  if (slot == -1) {
    return false;
  }
  memcpy(cred_id_storage.rp_id_hash, rp_id_hash, RP_ID_HASH_LENGTH);
  memcpy(cred_id_storage.credential_id, cred_id, cred_id_len);
  ctap_printf("store credential to slot %d\n", slot);
  dump_hex1(NULL, cred_id_storage.rp_id_hash, RP_ID_HASH_LENGTH + cred_id_len);
  if (!se_set_fido2_resident_credentials(slot, cred_id_storage.rp_id_hash,
                                         cred_id_len + RP_ID_HASH_LENGTH)) {
    return false;
  }
  ctap_printf("store credential to slot %d success\n", slot);
  return true;
}
