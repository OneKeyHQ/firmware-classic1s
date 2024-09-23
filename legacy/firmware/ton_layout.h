#ifndef __TON_LAYOUT_H__
#define __TON_LAYOUT_H__

#include <stdio.h>
#include "buttons.h"
#include "gettext.h"
#include "layout2.h"
#include "protect.h"

bool layoutTonSign(const char *chain_name, bool token_transfer,
                   const char *amount, const char *to_str, const char *signer,
                   const char *recipient, const char *token_id,
                   const uint8_t *data, uint16_t len, const char *memo);

bool confirmFinal(void);

#endif  // __TON_LAYOUT_H__
