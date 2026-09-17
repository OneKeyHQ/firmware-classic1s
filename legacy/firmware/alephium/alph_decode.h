#ifndef __ALPH_DECODE_H__
#define __ALPH_DECODE_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base58.h"

#define ALEPHIUM_MAX_INPUTS 16
#define ALEPHIUM_MAX_OUTPUTS 32
#define ALEPHIUM_MAX_TOKENS 8

#define ALEPHIUM_ADDRESS_SIZE 33
#define ALEPHIUM_HASH_SIZE 32
#define ALEPHIUM_MAX_SCRIPT_SIZE 1024
#define ALEPHIUM_MAX_MESSAGE_SIZE 1024
#define MAX_AMOUNT_STR_LENGTH 65
#define MAX_ADDRESS_LENGTH 50

typedef enum {
  ALEPHIUM_OK = 0,
  ALEPHIUM_ERROR_INVALID_DATA,
  ALEPHIUM_ERROR_BUFFER_OVERFLOW,
  ALEPHIUM_ERROR_UNSUPPORTED_SCRIPT,
  ALEPHIUM_ERROR_TOO_MANY_INPUTS,
  ALEPHIUM_ERROR_TOO_MANY_OUTPUTS,
  ALEPHIUM_ERROR_TOO_MANY_TOKENS,
  ALEPHIUM_ERROR_EXTRA_DATA
} AlephiumError;

typedef struct {
  uint8_t id[32];
  char amount[MAX_AMOUNT_STR_LENGTH];
} AlephiumToken;

typedef struct {
  char amount[MAX_AMOUNT_STR_LENGTH];
  uint8_t lockup_script_type;
  uint8_t lockup_script_hash[32];
  char address[MAX_ADDRESS_LENGTH];
  uint32_t lock_time;
  uint32_t message_length;
  AlephiumToken tokens[ALEPHIUM_MAX_TOKENS];
  size_t tokens_count;
} AlephiumTxOutput;

typedef struct {
  uint8_t version;
  uint8_t network_id;
  uint8_t script_opt;
  int32_t gas_amount;
  uint64_t gas_price;
  size_t inputs_count;
  size_t outputs_count;
  const uint8_t *raw_data;
  size_t raw_data_length;
  uint32_t output_offsets[ALEPHIUM_MAX_OUTPUTS];
} AlephiumDecodedTx;

// Function declarations

AlephiumError decode_compact_int(const uint8_t* data, size_t data_length,
                                 uint64_t* value,
                                 size_t* bytes_read);
AlephiumError decode_i32(const uint8_t* data, size_t data_length,
                         int32_t* value,
                         size_t* bytes_read);
AlephiumError decode_u256(const uint8_t* data, size_t data_length,
                          char* value_str,
                          size_t value_str_size, size_t* bytes_read);
AlephiumError decode_unlock_script(const uint8_t* data, size_t data_length,
                                   size_t* bytes_read);
AlephiumError decode_alephium_tx(const uint8_t* data, size_t data_length,
                                 size_t bytecode_skip,
                                 AlephiumDecodedTx* tx);
AlephiumError decode_alephium_output(const AlephiumDecodedTx* tx,
                                     size_t output_index,
                                     AlephiumTxOutput* output);

#endif  // __ALPH_DECODE_H__
