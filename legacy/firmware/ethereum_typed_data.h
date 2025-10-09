#ifndef __ETHEREUM_TYPED_DATA_H__
#define __ETHEREUM_TYPED_DATA_H__

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "bignum.h"
#include "bip32.h"
#include "bitmaps.h"
#include "buttons.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages-ethereum-eip712-onekey.pb.h"
#include "messages.h"
#include "messages.pb.h"
#include "protect.h"
#include "sha3.h"
#include "util.h"

#define TYPE_NAME_DOMAIN "EIP712Domain"

static const char *const HIGH_RISK_PRIMARY_TYPES_PERMIT[] = {
    "Permit",       "PermitBatch",        "PermitBatchTransferFrom",
    "PermitSingle", "PermitTransferFrom", "PermitWitnessTransferFrom",
};

static const char *const HIGH_RISK_PRIMARY_TYPES_ORDER[] = {
    "Order",
    "OrderComponents",
};

/**
 * keccak256(
 *      "EIP712Domain(uint256 chainId,address verifyingContract)");
 */
static const char DOMAIN_SEPARATOR_TYPEHASH[] = {
    71,  231, 149, 52,  162, 69,  149, 46,  139, 22,  137,
    58,  51,  107, 133, 163, 217, 234, 159, 168, 197, 115,
    243, 216, 3,   175, 185, 42,  121, 70,  146, 24};

/**
 * keccak256(
 *     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256
 * safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address
 * refundReceiver,uint256 nonce)");
 */
static const char SAFE_TX_TYPEHASH[] = {187, 131, 16,  212, 134, 54,  141, 182,
                                        189, 111, 132, 148, 2,   253, 215, 58,
                                        213, 61,  49,  107, 90,  75,  38,  68,
                                        173, 110, 254, 15,  148, 18,  134, 216};
typedef struct {
  char *name;
  char *value;
  int name_intent;
  size_t name_len;
  size_t value_len;
} DisplayItem;

typedef struct {
  DisplayItem *items;
  uint8_t items_count;
  uint8_t items_capacity;
  uint8_t current_item_index;
} DisplayInfo;
static DisplayInfo display_info = {0};
static bool display_item_init(DisplayItem *item) {
  if (!item) return false;
  item->name = NULL;
  item->value = NULL;
  item->name_len = 0;
  item->value_len = 0;
  item->name_intent = 0;
  return true;
}

static void display_item_cleanup(DisplayItem *item) {
  if (!item) return;
  if (item->name) {
    free(item->name);
    item->name = NULL;
  }
  if (item->value) {
    free(item->value);
    item->value = NULL;
  }
  item->name_len = 0;
  item->value_len = 0;
  item->name_intent = 0;
}

static bool display_item_set_name(DisplayItem *item, const char *name,
                                  int name_intent) {
  if (!item || !name) return false;

  if (item->name) {
    free(item->name);
  }

  size_t len = strlen(name);
  item->name = malloc(len + 1);
  if (!item->name) return false;

  strcpy(item->name, name);
  item->name_len = len;
  item->name_intent = name_intent;
  return true;
}

static bool display_item_set_value(DisplayItem *item, const char *value) {
  if (!item || !value) return false;

  if (item->value) {
    free(item->value);
  }

  size_t len = strlen(value);
  item->value = malloc(len + 1);
  if (!item->value) return false;

  strcpy(item->value, value);
  item->value_len = len;
  return true;
}

static bool display_info_init(DisplayInfo *info, uint8_t initial_capacity) {
  if (!info) return false;

  info->items = malloc(sizeof(DisplayItem) * initial_capacity);
  if (!info->items) return false;

  for (uint8_t i = 0; i < initial_capacity; i++) {
    display_item_init(&info->items[i]);
  }

  info->items_count = 0;
  info->items_capacity = initial_capacity;
  info->current_item_index = 0;

  return true;
}

static void display_info_cleanup(DisplayInfo *info) {
  if (!info) return;

  if (info->items) {
    for (uint8_t i = 0; i < info->items_capacity; i++) {
      display_item_cleanup(&info->items[i]);
    }
    free(info->items);
    info->items = NULL;
  }

  info->items_count = 0;
  info->items_capacity = 0;
  info->current_item_index = 0;
}

static bool display_info_add_item_name(DisplayInfo *info, const char *name,
                                       int name_intent) {
  if (!info || !name) return false;

  if (info->items_count >= info->items_capacity) {
    uint8_t new_capacity = info->items_capacity * 2;
    DisplayItem *new_items =
        realloc(info->items, sizeof(DisplayItem) * new_capacity);
    if (!new_items) return false;

    info->items = new_items;
    info->items_capacity = new_capacity;

    for (uint8_t i = info->items_count; i < new_capacity; i++) {
      display_item_init(&info->items[i]);
    }
  }
  info->current_item_index = info->items_count;
  if (!display_item_set_name(&info->items[info->items_count], name,
                             name_intent))
    return false;
  info->items_count++;
  return true;
}

static bool display_info_set_current_item_value(DisplayInfo *info,
                                                const char *value) {
  if (!info || !value || info->items_count == 0) return false;

  return display_item_set_value(&info->items[info->current_item_index], value);
}

static bool display_info_set_value(DisplayInfo *info, const char *value) {
  if (!display_info_set_current_item_value(info, value)) return false;

  return true;
}

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
  EthereumTypedDataStruct dependent_types[8];
  EthereumFieldTypeOneKey entry_types[8];
  uint8_t entry_types_count;
  uint8_t current_name_intent;
} TypedDataEnvelope;
extern void *call(const MessageType req_type, const void *msg_ptr,
                  const MessageType expected_response_type);

static void TypedDataEnvelope_init(TypedDataEnvelope *envelope,
                                   const char *primary_type,
                                   uint8_t primary_type_len,
                                   bool metamask_v4_compat) {
  memset(envelope, 0, sizeof(TypedDataEnvelope));
  strncpy(envelope->primary_type, primary_type, primary_type_len);
  envelope->metamask_v4_compat = metamask_v4_compat;
  envelope->dependent_types_capacity =
      sizeof(envelope->dependent_types) / sizeof(EthereumTypedDataStruct);
  envelope->dependent_types_count = 0;
  envelope->primary_type_len = primary_type_len;
  envelope->entry_types_count = 0;
  envelope->current_name_intent = 0;
  memset(envelope->entry_types, 0, sizeof(envelope->entry_types));
}

static const EthereumTypedDataStruct *TypedDataEnvelope_find_dependent_type(
    const TypedDataEnvelope *envelope, const char *type_name,
    uint8_t type_name_len) {
  for (uint8_t i = 0; i < envelope->dependent_types_count; i++) {
    if (strncmp(envelope->dependent_types[i].name, type_name, type_name_len) ==
        0) {
      return &envelope->dependent_types[i];
    }
  }
  return NULL;
}

static bool TypedDataEnvelope_add_dependent_type(
    TypedDataEnvelope *envelope, const char *type_name, uint8_t type_name_len,
    const EthereumTypedDataStructAckOneKey *type) {
  if (envelope->dependent_types_count >= envelope->dependent_types_capacity) {
    return false;
  }
  const EthereumTypedDataStruct *dependent_type =
      TypedDataEnvelope_find_dependent_type(envelope, type_name, type_name_len);
  if (dependent_type == NULL) {
    strncpy(envelope->dependent_types[envelope->dependent_types_count].name,
            type_name, type_name_len);
    envelope->dependent_types[envelope->dependent_types_count]
        .name[type_name_len] = '\0';
    envelope->dependent_types[envelope->dependent_types_count].type = *type;
    for (uint8_t i = 0; i < type->members_count; i++) {
      const EthereumStructMemberOneKey *member = &type->members[i];
      const EthereumFieldTypeOneKey *member_type = &member->type;
      while (member_type->data_type == EthereumDataTypeOneKey_ARRAY) {
        member_type = member_type->entry_type;
        if (member_type != NULL) {
          envelope->entry_types[envelope->entry_types_count] = *member_type;
          envelope->entry_types[envelope->entry_types_count].entry_type = NULL;
          envelope->dependent_types[envelope->dependent_types_count]
              .type.members[i]
              .type.entry_type =
              &envelope->entry_types[envelope->entry_types_count];
          envelope->entry_types_count++;
        }
      }
    }
    envelope->dependent_types_count++;
  }
  return true;
}

static bool TypedDataEnvelope_add_domain_type(
    TypedDataEnvelope *envelope,
    const EthereumTypedDataStructAckOneKey *domain_type) {
  envelope->types[0].type = *domain_type;
  strncpy(envelope->types[0].name, TYPE_NAME_DOMAIN, strlen(TYPE_NAME_DOMAIN));
  envelope->types[0].name[strlen(TYPE_NAME_DOMAIN)] = '\0';
  for (uint8_t i = 0; i < domain_type->members_count; i++) {
    const EthereumStructMemberOneKey *member = &domain_type->members[i];
    const EthereumFieldTypeOneKey *member_type = &member->type;
    while (member_type->data_type == EthereumDataTypeOneKey_ARRAY) {
      member_type = member_type->entry_type;
      if (member_type != NULL) {
        envelope->entry_types[envelope->entry_types_count] = *member_type;
        envelope->entry_types[envelope->entry_types_count].entry_type = NULL;
        envelope->types[0].type.members[i].type.entry_type =
            &envelope->entry_types[envelope->entry_types_count];
        envelope->entry_types_count++;
      }
    }
  }
  return true;
}

static bool TypedDataEnvelope_add_primary_type(
    TypedDataEnvelope *envelope,
    const EthereumTypedDataStructAckOneKey *primary_type) {
  envelope->types[1].type = *primary_type;
  strncpy(envelope->types[1].name, envelope->primary_type,
          envelope->primary_type_len);
  envelope->types[1].name[envelope->primary_type_len] = '\0';
  for (uint8_t i = 0; i < primary_type->members_count; i++) {
    const EthereumStructMemberOneKey *member = &primary_type->members[i];
    const EthereumFieldTypeOneKey *member_type = &member->type;
    while (member_type->data_type == EthereumDataTypeOneKey_ARRAY) {
      member_type = member_type->entry_type;
      if (member_type != NULL) {
        envelope->entry_types[envelope->entry_types_count] = *member_type;
        envelope->entry_types[envelope->entry_types_count].entry_type = NULL;
        envelope->types[1].type.members[i].type.entry_type =
            &envelope->entry_types[envelope->entry_types_count];
        envelope->entry_types_count++;
      }
    }
  }
  return true;
}
static const EthereumTypedDataStruct *TypedDataEnvelope_find_type(
    const TypedDataEnvelope *envelope, const char *type_name,
    uint8_t type_name_len) {
  if (strncmp(type_name, TYPE_NAME_DOMAIN, strlen(TYPE_NAME_DOMAIN)) == 0) {
    return &envelope->types[0];
  } else if (strncmp(type_name, envelope->primary_type,
                     envelope->primary_type_len) == 0) {
    return &envelope->types[1];
  }
  return TypedDataEnvelope_find_dependent_type(envelope, type_name,
                                               type_name_len);
}
static bool TypedDataEnvelope_add_type(
    TypedDataEnvelope *envelope, const char *type_name, uint8_t type_name_len,
    const EthereumTypedDataStructAckOneKey *type) {
  if (strncmp(type_name, TYPE_NAME_DOMAIN, strlen(TYPE_NAME_DOMAIN)) == 0) {
    return TypedDataEnvelope_add_domain_type(envelope, type);
  } else if (strncmp(type_name, envelope->primary_type, type_name_len) == 0) {
    return TypedDataEnvelope_add_primary_type(envelope, type);
  } else {
    return TypedDataEnvelope_add_dependent_type(envelope, type_name,
                                                type_name_len, type);
  }
  return false;
}
static void write_rightpad32(BufferWriter *w, const uint8_t *value,
                             const uint8_t value_len) {
  uint8_t padding[32] = {0};
  memcpy(padding, value, value_len);
  write_bytes(padding, 32, w);
}

static void write_leftpad32(BufferWriter *w, const uint8_t *value,
                            const uint8_t value_len, bool is_signed) {
  uint8_t padding[32];
  if (is_signed && value[0] & 0x80) {
    memset(padding, 0xFF, 32);
  } else {
    memset(padding, 0x00, 32);
  }
  memcpy(padding + (32 - value_len), value, value_len);
  write_bytes(padding, 32, w);
}
static bool encode_field(BufferWriter *w, const EthereumFieldTypeOneKey *field,
                         const uint8_t *value, const uint16_t value_len) {
  EthereumDataTypeOneKey data_type = field->data_type;
  bool has_size = field->has_size;
  // uint32_t size = field->size;
  if (data_type == EthereumDataTypeOneKey_BYTES) {
    if (has_size) {
      write_rightpad32(w, value, value_len);
    } else {
      keccak_256(value, value_len, w->buffer + w->position);
      w->position += 32;
    }
  } else if (data_type == EthereumDataTypeOneKey_STRING) {
    keccak_256(value, value_len, w->buffer + w->position);
    w->position += 32;
  } else if (data_type == EthereumDataTypeOneKey_INT) {
    write_leftpad32(w, value, value_len, true);
  } else if (data_type == EthereumDataTypeOneKey_UINT ||
             data_type == EthereumDataTypeOneKey_BOOL ||
             data_type == EthereumDataTypeOneKey_ADDRESS) {
    write_leftpad32(w, value, value_len, false);
  } else {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Unsupported data type for field encoding");
    return false;
  }
  return true;
}
static bool validate_value(const EthereumFieldTypeOneKey *field,
                           const uint8_t *value, uint8_t value_len) {
  if (field->has_size && field->size != value_len) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid length");
    return false;
  }

  if (field->data_type == EthereumDataTypeOneKey_BOOL) {
    if (value_len != 1 || (value[0] != 0 && value[0] != 1)) {
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid boolean value");
      return false;
    }
  } else if (field->data_type == EthereumDataTypeOneKey_ADDRESS) {
    if (value_len != 20) {
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid address");
      return false;
    }
  } else if (field->data_type == EthereumDataTypeOneKey_STRING) {
    if (!is_valid_utf8(value, value_len)) {
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid UTF-8");
      return false;
    }
  }
  return true;
}

static bool get_value(const EthereumFieldTypeOneKey *field,
                      const uint32_t *member_value_path,
                      uint8_t member_value_path_len, uint8_t *value,
                      uint16_t *value_len) {
  EthereumTypedDataValueRequestOneKey req = {0};
  memcpy(req.member_path, member_value_path,
         member_value_path_len * sizeof(uint32_t));
  req.member_path_count = member_value_path_len;
  void *response_ptr =
      call(MessageType_MessageType_EthereumTypedDataValueRequestOneKey, &req,
           MessageType_MessageType_EthereumTypedDataValueAckOneKey);
  if (response_ptr == NULL) {
    return false;
  }
  EthereumTypedDataValueAckOneKey resp =
      *(EthereumTypedDataValueAckOneKey *)response_ptr;
  if (!validate_value(field, resp.value.bytes, resp.value.size)) {
    return false;
  }
  memcpy(value, resp.value.bytes, resp.value.size);
  *value_len = resp.value.size;
  return true;
}

static bool get_array_size(const uint32_t *member_value_path,
                           uint8_t member_value_path_len,
                           uint16_t *array_size) {
  EthereumFieldTypeOneKey array_length_type = {
      .data_type = EthereumDataTypeOneKey_UINT,
      .size = 2,
  };
  uint8_t value[2] = {0};
  uint16_t value_len;
  if (!get_value(&array_length_type, member_value_path, member_value_path_len,
                 value, &value_len)) {
    return false;
  }
  *array_size = (value[0] << 8) | value[1];
  return true;
}
static bool hash_struct(const TypedDataEnvelope *envelope,
                        const char *type_name, uint8_t type_name_len,
                        const uint32_t *member_path, uint8_t member_path_len,
                        uint8_t name_intent, const char (*parent_objects)[64],
                        uint8_t parent_objects_len, uint8_t *digest);

static int compare_strings(const void *a, const void *b) {
  return strcmp((const char *)a, (const char *)b);
}
static const char *const TYPE_TRANSLATION_DICT[] = {
    "uint", "int", "bytes", "string", "bool", "address",
};
static bool get_type_name(const EthereumFieldTypeOneKey *field, char *type_name,
                          uint8_t *type_name_len) {
  EthereumDataTypeOneKey data_type = field->data_type;
  bool has_size = field->has_size;
  uint32_t size = field->size;
  int len = 0;
  if (data_type == EthereumDataTypeOneKey_STRUCT) {
    if (!field->has_struct_name || strlen(field->struct_name) == 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Missing struct_name in struct");
      return false;
    }
    uint8_t struct_name_len = strlen(field->struct_name);
    if (*type_name_len < struct_name_len) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Type name buffer overflow");
      return false;
    }
    strncpy(type_name, field->struct_name, struct_name_len);
    len = struct_name_len;
  } else if (data_type == EthereumDataTypeOneKey_ARRAY) {
    if (!field->entry_type) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Missing entry_type in array");
      return false;
    }
    char entry_type_name[68] = {0};
    uint8_t entry_type_name_len = sizeof(entry_type_name);
    if (!get_type_name(field->entry_type, entry_type_name,
                       &entry_type_name_len)) {
      return false;
    }
    if (has_size) {
      char temp_type_name[80] = {0};
      len = snprintf(temp_type_name, sizeof(temp_type_name), "%s[%" PRIu32 "]",
                     entry_type_name, size);
      strncpy(type_name, temp_type_name, len);
    } else {
      len =
          snprintf(type_name, entry_type_name_len + 3, "%s[]", entry_type_name);
    }
  } else if (data_type == EthereumDataTypeOneKey_UINT ||
             data_type == EthereumDataTypeOneKey_INT) {
    if (!has_size) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Missing size in int/uint");
      return false;
    }
    len = snprintf(type_name, 8, "%s%" PRIu32,
                   TYPE_TRANSLATION_DICT[data_type - 1], size * 8);
  } else if (data_type == EthereumDataTypeOneKey_BYTES) {
    if (has_size) {
      len = snprintf(type_name, 8, "%s%" PRIu32,
                     TYPE_TRANSLATION_DICT[data_type - 1], size);
    } else {
      len = snprintf(type_name, 6, "%s", TYPE_TRANSLATION_DICT[data_type - 1]);
    }
  } else {
    len = snprintf(type_name, 8, "%s", TYPE_TRANSLATION_DICT[data_type - 1]);
  }
  *type_name_len = len;
  return true;
}
static char *decode_typed_data(const uint8_t *data, uint16_t data_len,
                               const char *type_name) {
  char *result = NULL;
  if (strncmp(type_name, "bytes", 5) == 0) {
    result = malloc(48);
    if (!result) return NULL;
    result[0] = '0';
    result[1] = 'x';
    if (data_len >= 31) {
      data2hex(data, 10, result + 2);
      result[21] = '\n';
      result[22] = '.';
      result[23] = '.';
      result[24] = '.';
      data2hex(data + data_len - 9, 9, result + 25);
    } else {
      data2hex(data, data_len, result + 2);
    }
  } else if (strncmp(type_name, "string", 6) == 0) {
    result = malloc(data_len + 1);
    if (!result) return NULL;
    strncpy(result, (char *)data, data_len);
    result[data_len] = '\0';
  } else if (strncmp(type_name, "address", 7) == 0) {
    result = malloc(data_len * 2 + 1);
    if (!result) return NULL;
    result[0] = '0';
    result[1] = 'x';
    data2hexaddr(data, data_len, result + 2);
  } else if (strncmp(type_name, "bool", 4) == 0) {
    result = calloc(6, sizeof(char));
    if (!result) return NULL;
    strncpy(result, data[0] == 1 ? "true" : "false", 6);
  } else if (strncmp(type_name, "uint", 4) == 0) {
    result = malloc(80);
    if (!result) return NULL;
    if (data_len <= 4) {
      uint32_t num = 0;
      for (uint8_t i = 0; i < data_len; i++) {
        num = (num << 8) | data[i];
      }
      int len = snprintf(result, 80, "%" PRIu32, num);
      result[len] = '\0';
    } else {
      bignum256 num = {0};
      uint8_t padding[32] = {0};
      memcpy(padding + (32 - data_len), data, data_len);
      bn_read_be(padding, &num);
      bn_format(&num, NULL, NULL, 0, 0, false, 0, result, 80);
    }
  } else if (strncmp(type_name, "int", 3) == 0) {
    result = malloc(80);
    if (!result) return NULL;
    if (data_len <= 4) {
      int32_t num = 0;
      for (uint8_t i = 0; i < data_len; i++) {
        num = (num << 8) | data[i];
      }
      if (data_len < 4) {
        if (data[0] & 0x80) {
          int32_t mask = ~((1 << (data_len * 8)) - 1);
          num |= mask;
        }
      }
      int len = snprintf(result, 80, "%" PRIi32, num);
      result[len] = '\0';
    } else {
      bignum256 num = {0};
      uint8_t padding[32] = {0};
      memcpy(padding + (32 - data_len), data, data_len);
      bn_read_be(padding, &num);

      if (data[0] & 0x80) {
        bignum256 max_val = {0};
        bn_setbit(&max_val, 256);
        bn_subtract(&max_val, &num, &num);
        bn_format(&num, "-", NULL, 0, 0, false, 0, result, 80);
      } else {
        bn_format(&num, NULL, NULL, 0, 0, false, 0, result, 80);
      }
    }
  }
  return result;
}
static bool get_and_encode_data(const TypedDataEnvelope *envelope,
                                BufferWriter *w, const char *type_name,
                                uint8_t type_name_len,
                                const uint32_t *member_path,
                                uint8_t member_path_len, uint8_t name_intent,
                                const char (*parent_objects)[64],
                                uint8_t parent_objects_len) {
  const EthereumTypedDataStruct *type =
      TypedDataEnvelope_find_type(envelope, type_name, type_name_len);
  if (type == NULL) {
    fsm_sendFailure(FailureType_Failure_DataError, "Failed to find type");
    return false;
  }
  uint32_t member_value_path[16] = {0};
  memcpy(member_value_path, member_path, member_path_len * sizeof(uint32_t));
  member_path_len++;
  char current_parent_objects[16][64] = {0};
  for (uint8_t i = 0; i < parent_objects_len; i++) {
    strncpy(current_parent_objects[i], parent_objects[i],
            strlen(parent_objects[i]));
  }
  parent_objects_len++;
  for (uint8_t i = 0; i < type->type.members_count; i++) {
    const EthereumStructMemberOneKey *member = &type->type.members[i];
    member_value_path[member_path_len - 1] = i;
    char *field_name = (char *)member->name;
    const EthereumFieldTypeOneKey *field_type = &member->type;
    if (name_intent != 0) {
      char temp_field_name[68] = {0};
      snprintf(temp_field_name, 68, "[%s]", field_name);
      field_name = temp_field_name;
    }
    display_info_add_item_name(&display_info, field_name, name_intent);
    if (field_type->data_type == EthereumDataTypeOneKey_STRUCT) {
      strncpy(current_parent_objects[parent_objects_len - 1], field_name,
              strlen(field_name));
      display_info_set_value(&display_info, field_type->struct_name);
      if (!hash_struct(envelope, field_type->struct_name,
                       strlen(field_type->struct_name), member_value_path,
                       member_path_len, name_intent + 4, current_parent_objects,
                       parent_objects_len, w->buffer + w->position)) {
        fsm_sendFailure(FailureType_Failure_DataError, "Failed to hash struct");
        return false;
      }
      w->position += 32;
    } else if (field_type->data_type == EthereumDataTypeOneKey_ARRAY) {
      const EthereumFieldTypeOneKey *entry_type = field_type->entry_type;
      uint32_t array_size;
      if (field_type->has_size) {
        array_size = field_type->size;
      } else {
        if (!get_array_size(member_value_path, member_path_len,
                            (uint16_t *)&array_size)) {
          return false;
        }
      }
      char field_type_str[68] = {0};
      uint8_t field_type_str_len = 68;
      if (!get_type_name(field_type, field_type_str, &field_type_str_len)) {
        return false;
      }
      display_info_set_value(&display_info, field_type_str);
      strncpy(current_parent_objects[parent_objects_len - 1], field_name,
              strlen(field_name));
      BufferWriter arr_w = {0};
      uint8_t arr_buffer[256] = {0};
      init_buffer_writer(&arr_w, arr_buffer, sizeof(arr_buffer));
      uint32_t el_member_value_path[16] = {0};
      uint8_t el_member_value_path_len = member_path_len;
      memcpy(el_member_value_path, member_value_path,
             el_member_value_path_len * sizeof(uint32_t));
      el_member_value_path_len++;
      for (uint32_t j = 0; j < array_size; j++) {
        el_member_value_path[el_member_value_path_len - 1] = j;
        if (entry_type->data_type == EthereumDataTypeOneKey_STRUCT) {
          if (envelope->metamask_v4_compat) {
            if (!hash_struct(envelope, entry_type->struct_name,
                             strlen(entry_type->struct_name),
                             el_member_value_path, el_member_value_path_len,
                             name_intent + 8, current_parent_objects,
                             parent_objects_len,
                             arr_w.buffer + arr_w.position)) {
              return false;
            }
            arr_w.position += 32;
          } else {
            if (!get_and_encode_data(
                    envelope, &arr_w, entry_type->struct_name,
                    strlen(entry_type->struct_name), el_member_value_path,
                    el_member_value_path_len, name_intent + 8,
                    current_parent_objects, parent_objects_len)) {
              return false;
            }
          }
        } else {
          uint8_t value[1536] = {0};
          uint16_t value_len;
          if (!get_value(entry_type, el_member_value_path,
                         el_member_value_path_len, value, &value_len)) {
            return false;
          }
          if (!encode_field(&arr_w, entry_type, value, value_len)) {
            return false;
          }
          char array_item_str[80] = {0};
          snprintf(array_item_str, 80, "%s[%" PRIu32 "]", field_name, j);
          display_info_add_item_name(&display_info, array_item_str,
                                     name_intent + 4);
          char *array_item_value_str = decode_typed_data(
              value, value_len,
              TYPE_TRANSLATION_DICT[entry_type->data_type - 1]);
          display_info_set_value(&display_info, array_item_value_str);
          free(array_item_value_str);
        }
      }
      keccak_256(arr_w.buffer, arr_w.position, w->buffer + w->position);
      w->position += 32;
    } else {
      uint8_t value[1536] = {0};
      uint16_t value_len;
      if (!get_value(field_type, member_value_path, member_path_len, value,
                     &value_len)) {
        return false;
      }
      if (!encode_field(w, field_type, value, value_len)) {
        return false;
      }
      char *field_value_str = decode_typed_data(
          value, value_len, TYPE_TRANSLATION_DICT[field_type->data_type - 1]);
      display_info_set_value(&display_info, field_value_str);
      free(field_value_str);
    }
  }
  return true;
}
static void find_typed_dependencies(const TypedDataEnvelope *envelope,
                                    const char *type_name,
                                    uint8_t type_name_len, char (*results)[64],
                                    uint8_t *results_count) {
  const EthereumTypedDataStruct *type =
      TypedDataEnvelope_find_type(envelope, type_name, type_name_len);
  if (type == NULL) {
    return;
  }
  for (uint8_t i = 0; i < *results_count; i++) {
    if (strncmp(results[i], type_name, type_name_len) == 0) {
      return;
    }
  }
  strncpy(results[*results_count], type_name, type_name_len);
  results[*results_count][type_name_len] = '\0';
  (*results_count)++;
  for (uint8_t i = 0; i < type->type.members_count; i++) {
    const EthereumStructMemberOneKey *member = &type->type.members[i];
    const EthereumFieldTypeOneKey *member_type = &member->type;
    while (member_type->data_type == EthereumDataTypeOneKey_ARRAY) {
      member_type = member_type->entry_type;
    }
    if (member_type->data_type == EthereumDataTypeOneKey_STRUCT) {
      find_typed_dependencies(envelope, member_type->struct_name,
                              strlen(member_type->struct_name), results,
                              results_count);
    }
  }
}
static bool encode_type(const TypedDataEnvelope *envelope, BufferWriter *w,
                        const char *type_name, uint8_t type_name_len) {
  char deps[16][64] = {0};
  uint8_t deps_count = 0;

  find_typed_dependencies(envelope, type_name, type_name_len, deps,
                          &deps_count);
  if (deps_count > 1) {
    qsort(deps + 1, deps_count - 1, 64, compare_strings);
  }
  for (uint8_t i = 0; i < deps_count; i++) {
    uint8_t type_len = strlen(deps[i]);
    if (!write_bytes((const uint8_t *)deps[i], type_len, w)) {
      return false;
    }
    const char left_bracket = '(';
    if (!write_bytes((const uint8_t *)&left_bracket, 1, w)) {
      return false;
    }
    const EthereumTypedDataStruct *type =
        TypedDataEnvelope_find_type(envelope, deps[i], type_len);
    if (type == NULL) {
      return false;
    }
    bool first = true;
    for (uint8_t j = 0; j < type->type.members_count; j++) {
      const EthereumStructMemberOneKey *member = &type->type.members[j];
      if (!first) {
        const char comma = ',';
        if (!write_bytes((const uint8_t *)&comma, 1, w)) {
          return false;
        }
      }
      first = false;

      char member_type_name[64] = {0};
      uint8_t member_type_name_len = sizeof(member_type_name);
      if (!get_type_name(&member->type, member_type_name,
                         &member_type_name_len)) {
        return false;
      }
      if (!write_bytes((const uint8_t *)member_type_name, member_type_name_len,
                       w)) {
        return false;
      }
      const char space = ' ';
      if (!write_bytes((const uint8_t *)&space, 1, w)) {
        return false;
      }
      if (!write_bytes((const uint8_t *)member->name, strlen(member->name),
                       w)) {
        return false;
      }
    }
    const char right_bracket = ')';
    if (!write_bytes((const uint8_t *)&right_bracket, 1, w)) {
      return false;
    }
  }
  return true;
}
static bool hash_type(const TypedDataEnvelope *envelope, BufferWriter *w,
                      const char *type_name, uint8_t type_name_len) {
  BufferWriter type_w = {0};
  uint8_t buffer[1024] = {0};
  init_buffer_writer(&type_w, buffer, sizeof(buffer));
  if (!encode_type(envelope, &type_w, type_name, type_name_len)) {
    return false;
  }
  keccak_256(type_w.buffer, type_w.position, w->buffer + w->position);
  w->position += 32;
  return true;
}
static bool hash_struct(const TypedDataEnvelope *envelope,
                        const char *type_name, uint8_t type_name_len,
                        const uint32_t *member_path, uint8_t member_path_len,
                        uint8_t name_intent, const char (*parent_objects)[64],
                        uint8_t parent_objects_len, uint8_t *digest) {
  BufferWriter w = {0};
  uint8_t struct_buffer[1024] = {0};
  init_buffer_writer(&w, struct_buffer, sizeof(struct_buffer));
  if (!hash_type(envelope, &w, type_name, type_name_len)) {
    return false;
  }
  if (!get_and_encode_data(envelope, &w, type_name, type_name_len, member_path,
                           member_path_len, name_intent, parent_objects,
                           parent_objects_len)) {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Failed to get and encode data");
    return false;
  }
  keccak_256(w.buffer, w.position, digest);
  return true;
}

static bool validate_field_type(const EthereumFieldTypeOneKey *field) {
  EthereumDataTypeOneKey data_type = field->data_type;

  if (data_type == EthereumDataTypeOneKey_ARRAY) {
    if (!field->entry_type) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Missing entry_type in array");
      return false;
    }
    if (!validate_field_type(field->entry_type)) {
      return false;
    }
  } else {
    if (field->entry_type) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Unexpected entry_type in nonarray");
      return false;
    }
  }

  if (data_type == EthereumDataTypeOneKey_STRUCT) {
    if (!field->has_struct_name) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Missing struct_name in struct");
      return false;
    }
  } else {
    if (field->has_struct_name) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Unexpected struct_name in nonstruct");
      return false;
    }
  }

  if (data_type == EthereumDataTypeOneKey_STRUCT) {
    if (!field->has_size) {
      fsm_sendFailure(FailureType_Failure_DataError, "Missing size in struct");
      return false;
    }
  } else if (data_type == EthereumDataTypeOneKey_BYTES) {
    if (field->has_size && (field->size < 1 || field->size > 32)) {
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid size in bytes");
      return false;
    }
  } else if (data_type == EthereumDataTypeOneKey_UINT ||
             data_type == EthereumDataTypeOneKey_INT) {
    if (!field->has_size || (field->size < 1 || field->size > 32)) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid size in int/uint");
      return false;
    }
  } else if (data_type == EthereumDataTypeOneKey_STRING ||
             data_type == EthereumDataTypeOneKey_BOOL ||
             data_type == EthereumDataTypeOneKey_ADDRESS) {
    if (field->has_size) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Unexpected size in str/bool/addr");
      return false;
    }
  }

  return true;
}
static bool _collect_types(TypedDataEnvelope *envelope, const char *type_name,
                           uint8_t type_name_len) {
  EthereumTypedDataStructRequestOneKey req = {0};
  strncpy(req.name, type_name, type_name_len);
  void *response_ptr =
      call(MessageType_MessageType_EthereumTypedDataStructRequestOneKey, &req,
           MessageType_MessageType_EthereumTypedDataStructAckOneKey);
  if (response_ptr == NULL) {
    return false;
  }
  EthereumTypedDataStructAckOneKey current_type =
      *(EthereumTypedDataStructAckOneKey *)response_ptr;
  if (!TypedDataEnvelope_add_type(envelope, type_name, type_name_len,
                                  &current_type)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Failed to add type");
    return false;
  }
  for (uint8_t i = 0; i < current_type.members_count; i++) {
    const EthereumStructMemberOneKey *member = &current_type.members[i];
    const EthereumFieldTypeOneKey *member_type = &member->type;
    if (!validate_field_type(member_type)) {
      return false;
    }
    while (member_type->data_type == EthereumDataTypeOneKey_ARRAY) {
      member_type = member_type->entry_type;
    }
    if (member_type->data_type == EthereumDataTypeOneKey_STRUCT &&
        TypedDataEnvelope_find_type(envelope, member_type->struct_name,
                                    strlen(member_type->struct_name)) == NULL) {
      _collect_types(envelope, member_type->struct_name,
                     strlen(member_type->struct_name));
    }
  }
  return true;
}

static bool collect_types(TypedDataEnvelope *envelope) {
  if (!_collect_types(envelope, TYPE_NAME_DOMAIN, strlen(TYPE_NAME_DOMAIN))) {
    return false;
  }
  if (!_collect_types(envelope, envelope->primary_type,
                      envelope->primary_type_len)) {
    return false;
  }
  return true;
}

extern void layout_index_count(int index, int count);
extern void drawScrollbar(int pages, int index);
static const char *truncate_text_for_display(const char *text,
                                             uint8_t max_lines) {
  if (!text || max_lines == 0) return "";

  size_t text_len = strlen(text);
  size_t chars_per_line = 21;
  size_t max_chars = max_lines * chars_per_line;

  static char truncated_value[64];
  memzero(truncated_value, sizeof(truncated_value));

  if (text_len > max_chars) {
    size_t full_lines = max_lines - 1;
    size_t full_chars = full_lines * chars_per_line;
    strncpy(truncated_value, text, full_chars);
    truncated_value[full_chars] = '\n';
    memcpy(truncated_value + full_chars + 1, "...", 3);
    size_t remaining_chars = chars_per_line - 3;
    size_t start_pos = text_len - remaining_chars;
    strncpy(truncated_value + full_chars + 4, text + start_pos,
            remaining_chars);
  } else {
    return text;
  }

  return truncated_value;
}
static bool layoutTypedData(DisplayInfo *display_context,
                            const char *primary_type) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t bubble_key;
  int detail_index = 0;
  int max_index = 1;
  int detail_total_index = display_context->items_count;

refresh_menu:
  layoutSwipe();
  oledClear();
  bubble_key = KEY_NULL;
  y = 13;
  if (index == 0) {
    layoutHeader(_(T_CONFIRM_TYPED_DATA));
    oledDrawStringAdapter(0, y, _(I_REVIEW_STRUCT), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, primary_type, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else {  // details
    detail_index = 0;
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(_(T__TRANSACTION_DETAILS));
      if (detail_index < detail_total_index) {
        const DisplayItem *item = &display_context->items[detail_index];
        const char *name = item->name;
        const char *value = item->value;
        int name_intent = item->name_intent;

        if (name && value) {
          uint8_t line_count =
              oledDrawStringAdapter(name_intent, y, name, FONT_STANDARD);
          const char *display_value =
              truncate_text_for_display(value, 4 - line_count);
          oledDrawStringAdapter(0, y + 10 * line_count, display_value,
                                FONT_STANDARD);
        }
      }
      // scrollbar
      drawScrollbar(detail_total_index, detail_index);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);

      layout_index_count(detail_index + 1, detail_total_index);
      if (detail_total_index > 1) {
        if (detail_index == 0) {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
        } else if (detail_index == detail_total_index - 1) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_down);
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                         &bmp_bottom_middle_arrow_up);
        }
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        break;
      } else if (bubble_key == KEY_CONFIRM) {
        break;
      } else if (bubble_key == KEY_UP) {
        if (detail_index > 0) {
          detail_index--;
        }
      } else if (bubble_key == KEY_DOWN) {
        if (detail_index < detail_total_index - 1) {
          detail_index++;
        }
      }
    }
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
  return true;
}
static bool layoutSafeTx(bool is_delegate_call, const uint8_t *domain_hash,
                         const uint8_t *message_hash,
                         const uint8_t *safe_tx_hash) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t bubble_key;
  int max_index = 2;
  if (is_delegate_call) {
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                                NULL, NULL, _(I_SAFE_DELEGATE_WARNING));
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      return false;
    }
  }
  char domain_hash_str[67] = {'0', 'x'};
  char message_hash_str[67] = {'0', 'x'};
  char safe_tx_hash_str[67] = {'0', 'x'};
  data2hex(domain_hash, 32, domain_hash_str + 2);
  data2hex(message_hash, 32, message_hash_str + 2);
  data2hex(safe_tx_hash, 32, safe_tx_hash_str + 2);
refresh_menu:
  layoutSwipe();
  oledClear();
  layoutHeader(_(T_CONFIRM_SAFE_TX));
  bubble_key = KEY_NULL;
  y = 13;
  if (index == 0) {
    oledDrawStringAdapter(0, y, "Domain Hash", FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, domain_hash_str, FONT_STANDARD, &bmp_bottom_left_close,
        &bmp_bottom_right_arrow);
  } else if (index == 1) {
    oledDrawStringAdapter(0, y, "Message Hash", FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, message_hash_str, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  } else {
    oledDrawStringAdapter(0, y, "SafeTx Hash", FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, safe_tx_hash_str, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
  return true;
}
static void prepare_domain_items(DisplayInfo *info,
                                 const EthereumGnosisSafeTxAck *ack) {
  display_info_add_item_name(info, "chainId", 0);
  uint8_t chain_id_bytes[8] = {0};
  for (int i = 0; i < 8; i++) {
    chain_id_bytes[7 - i] = (ack->chain_id >> (i * 8)) & 0xFF;
  }
  char *chain_id_str = decode_typed_data(chain_id_bytes, 8, "uint");
  display_info_set_value(info, chain_id_str);
  free(chain_id_str);
  display_info_add_item_name(info, "verifyingContract", 0);
  uint8_t verifying_contract_bytes[20] = {0};
  ethereum_parse_onekey(ack->verifyingContract, verifying_contract_bytes);
  char *verifying_contract_str =
      decode_typed_data(verifying_contract_bytes, 20, "address");
  display_info_set_value(info, verifying_contract_str);
  free(verifying_contract_str);
}
static void prepare_safe_items(DisplayInfo *info,
                               const EthereumGnosisSafeTxAck *ack) {
  display_info_add_item_name(info, "to", 0);
  uint8_t to_bytes[20] = {0};
  ethereum_parse_onekey(ack->to, to_bytes);
  char *to_str = decode_typed_data(to_bytes, 20, "address");
  display_info_set_value(info, to_str);
  free(to_str);
  display_info_add_item_name(info, "value", 0);
  char *value_str =
      decode_typed_data(ack->value.bytes, ack->value.size, "uint");
  display_info_set_value(info, value_str);
  free(value_str);
  display_info_add_item_name(info, "data", 0);
  char *data_str = decode_typed_data(ack->data.bytes, ack->data.size, "bytes");
  display_info_set_value(info, data_str);
  free(data_str);
  display_info_add_item_name(info, "operation", 0);
  if (ack->operation == EthereumGnosisSafeTxOperation_DELEGATE_CALL) {
    display_info_set_value(info, "1(DELEGATECALL)");
  } else {
    display_info_set_value(info, "0(CALL)");
  }
  display_info_add_item_name(info, "safeTxGas", 0);
  char *safeTxGas_str =
      decode_typed_data(ack->safeTxGas.bytes, ack->safeTxGas.size, "uint");
  display_info_set_value(info, safeTxGas_str);
  free(safeTxGas_str);
  display_info_add_item_name(info, "baseGas", 0);
  char *baseGas_str =
      decode_typed_data(ack->baseGas.bytes, ack->baseGas.size, "uint");
  display_info_set_value(info, baseGas_str);
  free(baseGas_str);
  display_info_add_item_name(info, "gasPrice", 0);
  char *gasPrice_str =
      decode_typed_data(ack->gasPrice.bytes, ack->gasPrice.size, "uint");
  display_info_set_value(info, gasPrice_str);
  free(gasPrice_str);
  display_info_add_item_name(info, "gasToken", 0);
  uint8_t gas_token_bytes[20] = {0};
  ethereum_parse_onekey(ack->gasToken, gas_token_bytes);
  char *gasToken_str = decode_typed_data(gas_token_bytes, 20, "address");
  display_info_set_value(info, gasToken_str);
  free(gasToken_str);
  display_info_add_item_name(info, "refundReceiver", 0);
  uint8_t refund_receiver_bytes[20] = {0};
  ethereum_parse_onekey(ack->refundReceiver, refund_receiver_bytes);
  char *refundReceiver_str =
      decode_typed_data(refund_receiver_bytes, 20, "address");
  display_info_set_value(info, refundReceiver_str);
  free(refundReceiver_str);
  display_info_add_item_name(info, "nonce", 0);
  char *nonce_str =
      decode_typed_data(ack->nonce.bytes, ack->nonce.size, "uint");
  display_info_set_value(info, nonce_str);
  free(nonce_str);
}
#endif /* __ETHEREUM_TYPED_DATA_H__ */
