#ifndef __ALPH_ADDRESS_H__
#define __ALPH_ADDRESS_H__

#include <stdbool.h>
#include "base58.h"
#include "bip32.h"
#include "blake2b.h"
#include "curves.h"
#include "messages-alephium.pb.h"

bool alph_get_address(const AlephiumGetAddress *msg, AlephiumAddress *resp);

#endif  // __ALPH_ADDRESS_H__