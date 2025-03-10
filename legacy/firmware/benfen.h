/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2021 OneKey Team <core@onekey.so>
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

#ifndef __BENFEN_H__
#define __BENFEN_H__
#include <stdint.h>
#include "bip32.h"
#include "messages-benfen.pb.h"

#define BFC_ADDR_LENGTH 71
#define BFC_ADDR_SIZE 72
#define BFC_PREFIX "BFC"
#define BFC_PREFIX_LEN 3
#define BFC_HEX_LEN 64
#define BFC_CHECKSUM_LEN 4

void benfen_get_address_from_public_key(const uint8_t *public_key,
                                        char *address);
void benfen_sign_tx(const BenfenSignTx *msg, const HDNode *node,
                    BenfenSignedTx *resp);
void benfen_message_sign(const BenfenSignMessage *msg, const HDNode *node,
                         BenfenMessageSignature *resp);
void benfen_signing_init(const BenfenSignTx *msg, const HDNode *node);
void benfen_signing_txack(BenfenTxAck *msg);
void convert_to_bfc_address(const char *hex_addr, char *bfc_addr,
                            size_t bfc_addr_size);
#endif  // __BENFEN_H__
