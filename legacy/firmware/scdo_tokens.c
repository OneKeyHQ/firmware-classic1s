#include "scdo_tokens.h"
#include <string.h>

const ScdoTokenType scdo_tokens[TOKENS_COUNT] = {
    {"1S01dc515d287d1dbdc98abe9c397e73c4680f0022", " TEST", 8},
    {"1S01f0daaf7a59fb5eb90256112bf5d080ff290022", " TEST0", 8},
    {"1S01f4fb4ae0d3c043ac0cdc93a3c54b9c62600022", " TEST1", 8},
    {"1S019829e1a6658054c03113678c52ca1510330002", " TEST2", 8},
    {"1S015acd40eb8e0dc87018926aed6bdae91c7d0012", " TEST3", 8},
    {"1S016f5d94e7050ba8281cf1b67306a1a7d7070002", " TEST4", 8},
    {"1S01f61937dfa9a1fb568454c43ce65cf164c60012", " TEST5", 8},
    {"1S01aaab0a1d03eb075e63ee02b8d4a126e20e0022", " TEST6", 8},
    {"1S014fe934f2383aa9d3bf1d57f35fd6735b600022", " TEST7", 8},
    {"1S01e21b02c41f23638fbffccc81ffccd2a5d70012", " TEST8", 8},
    {"1S01b85c9f5e8e8d2762586d5673e55d033f350012", " TEST9", 8},
    {"1S0140a5ba0d07a99492034beff9707d7c73040012", " USDO TEST", 8},
    {"1S017b992068ae58386922056a01c792cb4e0a0032", " WIN", 8},
};

static const ScdoTokenType _UnknownToken = {
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff",
    " UNKN", 0};
const ScdoTokenType *ScdoUnknownToken = &_UnknownToken;

const ScdoTokenType *getTokenByAddress(const char *address) {
  if (!address) return 0;
  for (int i = 0; i < TOKENS_COUNT; i++) {
    if (memcmp(address, scdo_tokens[i].address, 20) == 0) {
      return &(scdo_tokens[i]);
    }
  }
  return ScdoUnknownToken;
}
