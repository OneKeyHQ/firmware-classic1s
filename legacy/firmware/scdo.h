/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2023 OneKey Team <core@onekey.so>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SCDO_H__
#define __SCDO_H__

#include <stdbool.h>
#include <stdint.h>
#include "bip32.h"
#include "messages-scdo.pb.h"

typedef struct {
  const char *const address;
  const char *const symbol;
  int decimals;
} ScdoTokenType;

void scdo_eth_2_address(const uint8_t *pubkey, char *scdo_address,
                        size_t scdo_address_size);

void scdo_sign_tx(ScdoSignTx *msg, const HDNode *node, char *scdo_address);
void scdo_signing_txack(const ScdoTxAck *tx);
void scdo_signing_abort(void);

void scdo_sign_message(const ScdoSignMessage *msg, const HDNode *node,
                       ScdoSignedMessage *resp);

#endif
