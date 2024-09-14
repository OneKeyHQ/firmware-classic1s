#ifndef __ALEPHIUM_DECODE_H__
#define __ALEPHIUM_DECODE_H__

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SEGGER_RTT.h"
#include "base58.h"
#include "rtt_log.h"

#define SCRIPT_TYPE_P2PKH 0
#define SCRIPT_TYPE_P2MPKH 1
#define SCRIPT_TYPE_P2SH 2

#define ALEPHIUM_VERSION_MAJOR 1
#define ALEPHIUM_VERSION_MINOR 0
#define ALEPHIUM_VERSION_PATCH 0

#define MAX_INPUTS 10
#define MAX_OUTPUTS 50
#define MAX_TOKENS 16

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
} AlephiumError;

typedef struct {
  uint32_t hint;
  uint8_t key[ALEPHIUM_HASH_SIZE];
  uint8_t unlock_script[ALEPHIUM_MAX_SCRIPT_SIZE];
  size_t unlock_script_length;
} AlephiumTxInput;

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
  uint8_t message[ALEPHIUM_MAX_MESSAGE_SIZE];
  AlephiumToken tokens[MAX_TOKENS];
  size_t tokens_count;
} AlephiumTxOutput;

typedef struct {
  uint8_t version;
  uint8_t network_id;
  uint8_t script_opt;
  int32_t gas_amount;
  uint64_t gas_price;
  AlephiumTxInput inputs[MAX_INPUTS];
  size_t inputs_count;
  AlephiumTxOutput outputs[MAX_OUTPUTS];
  size_t outputs_count;
} AlephiumDecodedTx;

// Function declarations
AlephiumError alephium_init(void);
AlephiumError decode_compact_int(const uint8_t* data, uint64_t* value,
                                 size_t* bytes_read);
AlephiumError decode_i32(const uint8_t* data, int32_t* value,
                         size_t* bytes_read);
AlephiumError decode_u256(const uint8_t* data, char* value_str,
                          size_t value_str_size, size_t* bytes_read);
AlephiumError decode_unlock_script(const uint8_t* data, uint8_t* script,
                                   size_t max_length, size_t* bytes_read);
AlephiumError decode_alephium_tx(const uint8_t* data, size_t data_length,
                                 AlephiumDecodedTx* tx);
void alephium_debug_log(const char* message, ...);

#endif  // __ALEPHIUM_H__