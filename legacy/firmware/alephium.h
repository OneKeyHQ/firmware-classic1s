#ifndef __ALEPHIUM_H__
#define __ALEPHIUM_H__

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alephium/alph_address.h"
#include "alephium/alph_decode.h"
#include "alephium/alph_layout.h"
#include "base58.h"
#include "blake2b.h"
#include "debug.h"
#include "fsm.h"
#include "layout2.h"
#include "messages-alephium.pb.h"
#include "messages.h"
#include "protect.h"
#include "util.h"

bool alephium_get_address(const HDNode *node, const AlephiumGetAddress *msg,
                          AlephiumAddress *resp);
void alephium_sign_tx(const HDNode *node, const AlephiumSignTx *msg);
void alephium_signing_txack(const AlephiumTxAck *tx);
void alephium_send_request_chunk(void);
void alephium_handle_bytecode_ack(const AlephiumBytecodeAck *msg);
void alephium_send_request_bytecode(void);
void alephium_signing_abort(void);
void alephium_calculate_total_fee(uint32_t gas_amount, uint64_t gas_price,
                                  char *total_fee, size_t total_fee_size);
void alephium_process_decoded_tx(const AlephiumDecodedTx *decoded_tx,
                                 const uint8_t *bytecode, size_t bytecode_size,
                                 AlephiumSignedTx *resp);
bool alephium_sign_message(const HDNode *node, const AlephiumSignMessage *msg,
                           AlephiumMessageSignature *resp);
bool generate_alephium_address(const uint8_t *public_key, char *address,
                               size_t address_size);
void format_alph_amount_from_string(const char *amount_str, char *formatted,
                                    size_t formatted_size);
void uint64_to_decimal_string(uint64_t value, char *str, size_t str_size);
void hex_string_to_decimal_string(const char *hex, char *decimal,
                                  size_t decimal_size);

#endif  // __ALEPHIUM_H__