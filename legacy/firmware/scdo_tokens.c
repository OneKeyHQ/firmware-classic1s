#include "scdo_tokens.h"
#include <string.h>

const ScdoTokenType scdo_tokens[TOKENS_COUNT] = {
    {"1S01dc515d287d1dbdc98abe9c397e73c4680f0022", " TEST Coin", 8},
    {"1S01c54d686a193d4824a38960cfd1d47430f60022", " CRY Coin", 8},
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
