#ifndef _RESIDENT_CREDENTIAL_H
#define _RESIDENT_CREDENTIAL_H

#include <stdbool.h>
#include <stdint.h>

#include "ctap.h"

#define MAX_RESIDENT_CREDENTIALS 60
#define RP_ID_HASH_LENGTH 32

#define FIDO2_RESIDENT_CREDENTIALS_SIZE (512)
#define FIDO2_RESIDENT_CREDENTIALS_COUNT 60
#define FIDO2_RESIDENT_CREDENTIALS_HEADER_LEN (6)
#define FIDO2_RESIDENT_CREDENTIALS_FLAGS "\x66\x69\x64\x6F"  // "fido"

typedef struct {
  uint8_t credential_id_flag[4];
  uint16_t credential_length;
  uint8_t rp_id_hash[32];
  uint8_t credential_id[474];
} __attribute__((packed)) CTAP_credential_id_storage;
_Static_assert(sizeof(CTAP_credential_id_storage) ==
                   FIDO2_RESIDENT_CREDENTIALS_SIZE,
               "CTAP_credential_id_storage size must be flash page size");

#if !EMULATOR
uint32_t resident_credential_find_by_rp_id_hash(
    const uint8_t *rp_id_hash, CTAP_credentialDescriptor *cred_desc,
    uint32_t max_count);
bool resident_credential_store(const uint8_t *rp_id_hash,
                               const uint8_t *user_id, const uint8_t *cred_id,
                               uint32_t cred_id_len);
int resident_credential_info(uint8_t indexs[FIDO2_RESIDENT_CREDENTIALS_COUNT],
                             int progress_ratio);
int resident_credential_get_desc(uint8_t index,
                                 CTAP_credentialDescriptor *cred_desc);
bool resident_credential_delete(uint8_t index);
#else
#define resident_credential_find_by_rp_id_hash(...) 0
#define resident_credential_store(...) true
#define resident_credential_info(...) 0
#define resident_credential_get_desc(...) 0
#define resident_credential_delete(...) true
#endif

#endif
