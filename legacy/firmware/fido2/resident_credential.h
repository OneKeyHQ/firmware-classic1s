#ifndef _RESIDENT_CREDENTIAL_H
#define _RESIDENT_CREDENTIAL_H

#include <stdbool.h>
#include <stdint.h>

#include "ctap.h"

#define MAX_RESIDENT_CREDENTIALS 60
#define RP_ID_HASH_LENGTH 32

#define FIDO2_RESIDENT_CREDENTIALS_COUNT 60

uint32_t resident_credential_find_by_rp_id_hash(
    const uint8_t *rp_id_hash, CTAP_credentialDescriptor *cred_desc,
    uint32_t max_count);
bool resident_credential_store(const uint8_t *rp_id_hash,
                               const uint8_t *user_id, uint32_t user_id_len,
                               const uint8_t *cred_id, uint32_t cred_id_len);
int resident_credential_info(uint8_t indexs[FIDO2_RESIDENT_CREDENTIALS_COUNT],
                             int progress_ratio);
int resident_credential_get_desc(uint8_t index,
                                 CTAP_credentialDescriptor *cred_desc);
bool resident_credential_delete(uint8_t index);
#endif
