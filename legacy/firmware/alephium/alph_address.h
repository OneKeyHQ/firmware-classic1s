#ifndef __ALPH_ADDRESS_H__
#define __ALPH_ADDRESS_H__

#include <stdbool.h>
#include "../fsm.h"
#include "../layout2.h"
#include "../protect.h"
#include "base58.h"
#include "bip32.h"
#include "blake2b.h"
#include "messages-alephium.pb.h"

bool alph_get_address(const HDNode *node, const AlephiumGetAddress *msg,
                      AlephiumAddress *resp);

#endif