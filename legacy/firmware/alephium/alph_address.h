#ifndef __ALPH_ADDRESS_H__
#define __ALPH_ADDRESS_H__

#include <stdbool.h>
#include "base58.h"
#include "bip32.h"
#include "blake2b.h"
#include "curves.h"
#include "messages-alephium.pb.h"
extern HDNode *fsm_getDerivedNode(const char *curve, const uint32_t *address_n,
                                  size_t address_n_count,
                                  uint32_t *fingerprint);
bool alph_get_address(const AlephiumGetAddress *msg, AlephiumAddress *resp);

#endif  // __ALPH_ADDRESS_H__