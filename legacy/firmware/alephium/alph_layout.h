#ifndef __ALEPHIUM_LAYOUT_H__
#define __ALEPHIUM_LAYOUT_H__

#include <stdio.h>
#include "../gettext.h"
#include "../layout2.h"
#include "../protect.h"
#include "SEGGER_RTT.h"
#include "buttons.h"

bool layoutFee(const char *fee);
bool layoutFinal(void);
bool layoutOutput(const char *chain_name, const char *amount,
                  const char *to_address, const char *token_id,
                  const char *token_amount, const uint8_t *bytecode,
                  size_t bytecode_size);

#endif  // __ALEPHIUM_LAYOUT_H__