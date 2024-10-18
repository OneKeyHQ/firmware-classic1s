#ifndef __SCDO_TOKENS_H__
#define __SCDO_TOKENS_H__

#include <stdint.h>

#define TOKENS_COUNT 13

typedef struct {
  const char *const address;
  const char *const symbol;
  int decimals;
} ScdoTokenType;

extern const ScdoTokenType scdo_tokens[TOKENS_COUNT];

extern const ScdoTokenType *ScdoUnknownToken;

const ScdoTokenType *getTokenByAddress(const char *address);

#endif
