#ifndef ETHEREUM_TYPED_DATA_TYPES_H
#define ETHEREUM_TYPED_DATA_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "messages-ethereum-eip712-onekey.pb.h"

typedef struct {
  EthereumTypedDataStructAckOneKey type;
  char name[64];
} EthereumTypedDataStruct;

typedef struct {
  char primary_type[64];
  uint8_t primary_type_len;
  bool metamask_v4_compat;
  EthereumTypedDataStruct types[2];
  uint8_t dependent_types_count;
  uint8_t dependent_types_capacity;
  EthereumTypedDataStruct dependent_types[10];
  EthereumFieldTypeOneKey entry_types[24];
  uint8_t entry_types_count;
  uint8_t entry_types_capacity;
  uint8_t current_name_intent;
} TypedDataEnvelope;

#endif  // ETHEREUM_TYPED_DATA_TYPES_H
