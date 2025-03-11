#include "neo_tokens.h"
#include <string.h>

#define NEO_TOKENS_COUNT 3

static const NeoToken neo_tokens[NEO_TOKENS_COUNT] = {
    {
        .contract_script_hash = {0xf5, 0x63, 0xea, 0x40, 0xbc, 0x28, 0x3d,
                                 0x4d, 0x0e, 0x05, 0xc4, 0x8e, 0xa3, 0x05,
                                 0xb3, 0xf2, 0xa0, 0x73, 0x40, 0xef},
        .decimals = 0,
        .symbol = "NEO",
    },
    {
        .contract_script_hash = {0xcf, 0x76, 0xe2, 0x8b, 0xd0, 0x06, 0x2c,
                                 0x4a, 0x47, 0x8e, 0xe3, 0x55, 0x61, 0x01,
                                 0x13, 0x19, 0xf3, 0xcf, 0xa4, 0xd2},
        .decimals = 8,
        .symbol = "GAS",
    },
    {
        .contract_script_hash = {0x28, 0xab, 0x18, 0x74, 0xda, 0x47, 0xaa,
                                 0xd8, 0x2c, 0x9c, 0xb3, 0x51, 0x88, 0x55,
                                 0x27, 0x81, 0x52, 0x1f, 0x15, 0xf0},
        .decimals = 8,
        .symbol = "FLM",
    },
};

const NeoToken UNK_TOKEN = {
    .contract_script_hash = {0},
    .decimals = 0,
    .symbol = "UNK",
};

const NeoToken *neo_token_by_contract_script_hash(
    const uint8_t *contract_script_hash) {
  for (size_t i = 0; i < NEO_TOKENS_COUNT; i++) {
    if (memcmp(neo_tokens[i].contract_script_hash, contract_script_hash, 20) ==
        0) {
      return &neo_tokens[i];
    }
  }
  return &UNK_TOKEN;
}

bool neo_is_unknown_token(const NeoToken *token) { return token == &UNK_TOKEN; }
