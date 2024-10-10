// This file is automatically generated from ethereum_tokens_onekey.c.mako
// DO NOT EDIT

#include <string.h>
#include "ethereum_tokens_onekey.h"

const TokenType tokens[TOKENS_COUNT] = {
% for t in sorted(erc20, key=lambda t: t.chain_id):
	{${"{:>2}".format(t.chain_id)}, ${c_str(t.address_bytes)}, " ${ascii(t.symbol)}", ${t.decimals}}, // ${t.chain} / ${t.name}
% endfor
};

static const TokenType _UnknownToken = { 0, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", " UNKN", 0 };
const TokenType *UnknownToken = &_UnknownToken;

const TokenType *tokenByChainAddress(uint64_t chain_id, const uint8_t *address)
{
	if (!address) return 0;
	for (int i = 0; i < TOKENS_COUNT; i++) {
		if (chain_id == tokens[i].chain_id && memcmp(address, tokens[i].address, 20) == 0) {
			return &(tokens[i]);
		}
	}
	return UnknownToken;
}
