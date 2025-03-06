#ifndef __NEO_H__
#define __NEO_H__

#include "bip32.h"
#include "messages-neo.pb.h"

bool neo_address_from_pubkey(const uint8_t *public_key, char *address);
bool neo_sign_tx(const NeoSignTx *msg, HDNode *node, NeoSignedTx *resp);

#endif  // __NEO_H__
