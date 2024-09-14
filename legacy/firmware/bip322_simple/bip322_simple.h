#ifndef BIP322_SIMPLE_H
#define BIP322_SIMPLE_H

#include <stdint.h>
#include "../coins.h"
#include "bip32.h"

bool sign_bip322_simple_taproot(const HDNode *node, const uint8_t *message,
                                size_t message_len, uint8_t *signature_out,
                                size_t *signature_size_out);
bool sign_bip322_simple_segwit(const HDNode *node, const CoinInfo *coin,
                               const uint8_t *message, size_t message_len,
                               uint8_t *signature_out,
                               size_t *signature_size_out);
#endif  // BIP322_SIMPLE_H
