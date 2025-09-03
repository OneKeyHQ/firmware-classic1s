#ifndef EIP7702_DELEGATORS_H
#define EIP7702_DELEGATORS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define REVOKE_DELEGATOR                                                     \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00"

typedef struct {
  const char *name;
  const uint8_t address[20];
  const uint8_t initial_data_size;
  const uint8_t initial_data[4];
} Delegator;

static const Delegator registered_delegators[] = {
    {.name = "Revoke",
     .address = REVOKE_DELEGATOR,
     .initial_data_size = 0,
     .initial_data = ""},
    {.name = "OKX",
     .address = "\x80\x29\x6F\xF8\xD1\xED\x46\xf8\xe3\xC7\x99\x26\x64\xD1\x3B"
                "\x83\x35\x04\xc2\xBB",
     .initial_data_size = 4,
     .initial_data = "\x81\x29\xfc\x1c"},
    {.name = "MetaMask",
     .address = "\x63\xc0\xc1\x9a\x28\x2a\x1b\x52\xb0\x7d\xd5\xa6\x5b\x58\x94"
                "\x8a\x07\xda\xe3\x2b",
     .initial_data_size = 0,
     .initial_data = ""},
    {.name = "Simple",
     .address = "\x4C\xd2\x41\xe8\xd1\x51\x0e\x30\xb2\x07\x63\x97\xaf\xc7\x50"
                "\x8a\xe5\x9c\x66\xc9",
     .initial_data_size = 0,
     .initial_data = ""},
};
#define REGISTERED_DELEGATORS_COUNT \
  (sizeof(registered_delegators) / sizeof(registered_delegators[0]))

bool is_revoke_delegator(const uint8_t *address) {
  return memcmp(address, REVOKE_DELEGATOR, 20) == 0;
}

bool is_registered_delegator(uint64_t chain_id, const uint8_t *address) {
  (void)chain_id;
  for (size_t i = 0; i < REGISTERED_DELEGATORS_COUNT; i++) {
    if (memcmp(registered_delegators[i].address, address, 20) == 0) {
      return true;
    }
  }
  return false;
}

const Delegator *get_delegator_by_address(uint64_t chain_id,
                                          const uint8_t *address) {
  (void)chain_id;
  for (size_t i = 0; i < REGISTERED_DELEGATORS_COUNT; i++) {
    if (memcmp(registered_delegators[i].address, address, 20) == 0) {
      return &registered_delegators[i];
    }
  }
  return NULL;
}
#endif
