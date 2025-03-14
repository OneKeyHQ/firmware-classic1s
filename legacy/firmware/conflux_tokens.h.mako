// This file is automatically generated from conflux_tokens.h.mako
// DO NOT EDIT

#ifndef __CONFLUX_TOKENS_H__
#define __CONFLUX_TOKENS_H__

#include <stdint.h>

<% crc20_list = list(supported_on("trezor1", conflux)) %>\
#define TOKENS_COUNT ${len(crc20_list)}

typedef struct {
	const char * const address;
	const char * const symbol;
	int decimals;
} ConfluxTokenType;

extern const ConfluxTokenType conflux_tokens[TOKENS_COUNT];

extern const ConfluxTokenType *ConfluxUnknownToken;

const ConfluxTokenType *tokenByAddress(const char *address);

#endif
