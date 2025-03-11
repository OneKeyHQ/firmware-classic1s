#ifndef __NEO_TOKENS_H__
#define __NEO_TOKENS_H__

#include <stdbool.h>
#include <stdint.h>
typedef struct {
  uint8_t contract_script_hash[20];
  uint32_t decimals;
  char symbol[32];
} NeoToken;

extern const NeoToken UNK_TOKEN;
const NeoToken *neo_token_by_contract_script_hash(
    const uint8_t *contract_script_hash);
bool neo_is_unknown_token(const NeoToken *token);
#endif  // __NEO_TOKENS_H__
