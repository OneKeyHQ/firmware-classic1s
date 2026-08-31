#ifndef BABYLON_H
#define BABYLON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BABYLON_APP_NAME_MAX_LEN 64
#define BABYLON_CONTEXT_MAX_LEN 1024
#define BABYLON_CONTEXT_HASH_LEN 32

bool babylon_derive_context_hash(const uint8_t connected_public_key[33],
                                 const uint8_t *app_name, size_t app_name_len,
                                 uint8_t network, const uint8_t *context,
                                 size_t context_len,
                                 uint8_t out[BABYLON_CONTEXT_HASH_LEN]);

#endif
