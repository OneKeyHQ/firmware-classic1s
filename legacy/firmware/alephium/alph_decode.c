#include "alph_decode.h"

#define U256_SINGLE_BYTE_LIMIT 0x40
#define U256_TWO_BYTE_LIMIT 0x80
#define U256_MULTI_BYTE_LIMIT 0xC0
#define I32_PREFIX_MASK 0xC0
#define I32_PREFIX_SINGLE_BYTE 0x00
#define I32_PREFIX_TWO_BYTES 0x40
#define I32_PREFIX_FOUR_BYTES 0x80
#define I32_PREFIX_MULTI_BYTES 0xC0
#define I32_SIGN_BIT 0x20
#define I32_VALUE_MASK 0x3F
#define I32_MAX_VALUE_1BYTE 64
#define I32_MAX_VALUE_2BYTES 16384
#define I32_MAX_VALUE_4BYTES 1073741824
#define COMPACT_INT_16BIT_FLAG 0xFD
#define COMPACT_INT_32BIT_FLAG 0xFE
#define MAX_DECIMAL_LEN 256
#define SCRIPT_TYPE_P2PKH 0
#define SCRIPT_TYPE_P2MPKH 1
#define SCRIPT_TYPE_P2SH 2

static bool has_bytes(size_t data_length, size_t offset, size_t count) {
  return offset <= data_length && count <= data_length - offset;
}

AlephiumError decode_compact_int(const uint8_t* data, size_t data_length,
                                 uint64_t* value, size_t* bytes_read) {
  if (!data || !value || !bytes_read || data_length == 0) return ALEPHIUM_ERROR_INVALID_DATA;
  uint8_t first_byte = data[0];
  size_t length = first_byte < COMPACT_INT_16BIT_FLAG ? 1 :
                  first_byte == COMPACT_INT_16BIT_FLAG ? 3 :
                  first_byte == COMPACT_INT_32BIT_FLAG ? 5 : 9;
  if (data_length < length) return ALEPHIUM_ERROR_INVALID_DATA;
  if (length == 1) *value = first_byte;
  else if (length == 3) *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8);
  else if (length == 5) *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8) |
                                  ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24);
  else *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8) |
                ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24) |
                ((uint64_t)data[5] << 32) | ((uint64_t)data[6] << 40) |
                ((uint64_t)data[7] << 48) | ((uint64_t)data[8] << 56);
  *bytes_read = length;
  return ALEPHIUM_OK;
}

AlephiumError decode_i32(const uint8_t* data, size_t data_length,
                         int32_t* value, size_t* bytes_read) {
  if (!data || !value || !bytes_read || data_length == 0) return ALEPHIUM_ERROR_INVALID_DATA;
  uint8_t first_byte = data[0];
  switch (first_byte & I32_PREFIX_MASK) {
    case I32_PREFIX_SINGLE_BYTE:
      *value = (first_byte & I32_SIGN_BIT) ? -(I32_MAX_VALUE_1BYTE - first_byte) : first_byte;
      *bytes_read = 1;
      return ALEPHIUM_OK;
    case I32_PREFIX_TWO_BYTES: {
      if (data_length < 2) return ALEPHIUM_ERROR_INVALID_DATA;
      uint16_t val = ((uint16_t)(first_byte & I32_VALUE_MASK) << 8) | data[1];
      *value = (first_byte & I32_SIGN_BIT) ? -(I32_MAX_VALUE_2BYTES - val) : val;
      *bytes_read = 2;
      return ALEPHIUM_OK;
    }
    case I32_PREFIX_FOUR_BYTES: {
      if (data_length < 4) return ALEPHIUM_ERROR_INVALID_DATA;
      uint32_t val = ((uint32_t)(first_byte & I32_VALUE_MASK) << 24) |
                     ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
      *value = (first_byte & I32_SIGN_BIT) ? -(I32_MAX_VALUE_4BYTES - val) : val;
      *bytes_read = 4;
      return ALEPHIUM_OK;
    }
    case I32_PREFIX_MULTI_BYTES: {
      size_t length = (size_t)(first_byte & I32_VALUE_MASK) + 5;
      if (length > 8 || data_length < length) return ALEPHIUM_ERROR_INVALID_DATA;
      uint64_t val = 0;
      for (size_t i = 1; i < length; i++) val = (val << 8) | data[i];
      *value = (first_byte & I32_SIGN_BIT) ? -(int32_t)val : (int32_t)val;
      *bytes_read = length;
      return ALEPHIUM_OK;
    }
    default:
      return ALEPHIUM_ERROR_INVALID_DATA;
  }
}

void format_hex_to_decimal(const char* hex_str, char* decimal_str, size_t decimal_str_size) {
  size_t hex_len = strlen(hex_str), decimal_len = 0;
  char temp[MAX_DECIMAL_LEN] = "0";
  for (size_t i = 0; i < hex_len; i++) {
    int digit = isdigit((unsigned char)hex_str[i]) ? hex_str[i] - '0' :
                tolower((unsigned char)hex_str[i]) - 'a' + 10;
    for (size_t j = 0; j < decimal_len || digit; j++) {
      if (j >= MAX_DECIMAL_LEN - 1) return;
      int value = (j < decimal_len ? temp[j] - '0' : 0) * 16 + digit;
      temp[j] = value % 10 + '0';
      digit = value / 10;
      if (j >= decimal_len) decimal_len++;
    }
  }
  for (size_t i = 0; i < decimal_len / 2; i++) {
    char c = temp[i]; temp[i] = temp[decimal_len - 1 - i]; temp[decimal_len - 1 - i] = c;
  }
  strncpy(decimal_str, temp, decimal_str_size - 1);
  decimal_str[decimal_str_size - 1] = '\0';
}

AlephiumError decode_u256(const uint8_t* data, size_t data_length,
                          char* value_str, size_t value_str_size, size_t* bytes_read) {
  if (!data || !value_str || !bytes_read || data_length == 0) return ALEPHIUM_ERROR_INVALID_DATA;
  uint8_t first_byte = data[0];
  if (first_byte < U256_SINGLE_BYTE_LIMIT) {
    snprintf(value_str, value_str_size, "%u", first_byte); *bytes_read = 1; return ALEPHIUM_OK;
  }
  if (first_byte < U256_TWO_BYTE_LIMIT) {
    if (data_length < 2) return ALEPHIUM_ERROR_INVALID_DATA;
    snprintf(value_str, value_str_size, "%u", ((uint16_t)(first_byte & 0x3F) << 8) | data[1]);
    *bytes_read = 2; return ALEPHIUM_OK;
  }
  size_t length = first_byte < U256_MULTI_BYTE_LIMIT ?
                      (size_t)(first_byte - U256_TWO_BYTE_LIMIT) + 3 :
                      (size_t)(first_byte - U256_MULTI_BYTE_LIMIT) + 4;
  if (length > 32 || !has_bytes(data_length, 1, length) || length * 2 >= value_str_size) {
    return ALEPHIUM_ERROR_BUFFER_OVERFLOW;
  }
  for (size_t i = 1; i <= length; i++) snprintf(value_str + (i - 1) * 2, 3, "%02x", data[i]);
  value_str[length * 2] = '\0';
  char* start = value_str;
  while (*start == '0' && *(start + 1) != '\0') start++;
  if (start != value_str) memmove(value_str, start, strlen(start) + 1);
  *bytes_read = length + 1;
  char decimal_str[MAX_DECIMAL_LEN];
  format_hex_to_decimal(value_str, decimal_str, sizeof(decimal_str));
  strncpy(value_str, decimal_str, value_str_size - 1);
  value_str[value_str_size - 1] = '\0';
  return ALEPHIUM_OK;
}

AlephiumError decode_unlock_script(const uint8_t* data, size_t data_length, size_t* bytes_read) {
  if (!data || !bytes_read || data_length == 0) return ALEPHIUM_ERROR_INVALID_DATA;
  size_t length;
  switch (data[0]) {
    case SCRIPT_TYPE_P2PKH: length = ALEPHIUM_ADDRESS_SIZE + 1; break;
    case SCRIPT_TYPE_P2MPKH: {
      uint64_t count; size_t compact_length;
      AlephiumError err = decode_compact_int(data + 1, data_length - 1, &count, &compact_length);
      if (err != ALEPHIUM_OK) return err;
      if (count > (SIZE_MAX - 1 - compact_length) / 37) return ALEPHIUM_ERROR_BUFFER_OVERFLOW;
      length = 1 + compact_length + (size_t)count * 37;
      break;
    }
    case SCRIPT_TYPE_P2SH: {
      uint64_t script_length, params_length; size_t script_compact_length, params_compact_length;
      AlephiumError err = decode_compact_int(data + 1, data_length - 1, &script_length, &script_compact_length);
      if (err != ALEPHIUM_OK) return err;
      if (script_length > data_length - 1 - script_compact_length) return ALEPHIUM_ERROR_INVALID_DATA;
      size_t params_offset = 1 + script_compact_length + (size_t)script_length;
      err = decode_compact_int(data + params_offset, data_length - params_offset, &params_length, &params_compact_length);
      if (err != ALEPHIUM_OK) return err;
      if (params_length > data_length - params_offset - params_compact_length) return ALEPHIUM_ERROR_INVALID_DATA;
      length = params_offset + params_compact_length + (size_t)params_length;
      break;
    }
    case 3: length = 1; break;
    default: return ALEPHIUM_ERROR_UNSUPPORTED_SCRIPT;
  }
  if (length > ALEPHIUM_MAX_SCRIPT_SIZE) return ALEPHIUM_ERROR_BUFFER_OVERFLOW;
  if (length > data_length) return ALEPHIUM_ERROR_INVALID_DATA;
  *bytes_read = length;
  return ALEPHIUM_OK;
}

AlephiumError generate_address_from_output(uint8_t type, const uint8_t* hash,
                                           char* address, size_t address_size) {
  if (type != SCRIPT_TYPE_P2PKH && type != SCRIPT_TYPE_P2MPKH && type != SCRIPT_TYPE_P2SH) {
    return ALEPHIUM_ERROR_UNSUPPORTED_SCRIPT;
  }
  uint8_t address_bytes[33];
  address_bytes[0] = type;
  memcpy(address_bytes + 1, hash, 32);
  size_t out_len = address_size;
  return b58enc(address, &out_len, address_bytes, sizeof(address_bytes)) == 0 ?
             ALEPHIUM_ERROR_UNSUPPORTED_SCRIPT : ALEPHIUM_OK;
}

void format_alph_amount_from_double(long double amount, char* formatted, size_t formatted_size) {
  snprintf(formatted, formatted_size, "%.18Lf", amount);
  char* end = formatted + strlen(formatted) - 1;
  while (*end == '0' && end > formatted && *(end - 1) != '.') end--;
  if (*end == '.') end--;
  *(end + 1) = '\0';
}

static AlephiumError decode_output(const uint8_t* data, size_t data_length,
                                   AlephiumTxOutput* output, size_t* bytes_read) {
  size_t index = 0, field_length;
  char amount[MAX_AMOUNT_STR_LENGTH];
  AlephiumError err = decode_u256(data, data_length, amount, sizeof(amount), &field_length);
  if (err != ALEPHIUM_OK) return err;
  index += field_length;
  if (!has_bytes(data_length, index, 33)) return ALEPHIUM_ERROR_INVALID_DATA;
  uint8_t type = data[index++];
  const uint8_t* hash = data + index;
  index += 32;
  if (!has_bytes(data_length, index, 8)) return ALEPHIUM_ERROR_INVALID_DATA;
  uint32_t lock_time, message_length;
  memcpy(&lock_time, data + index, sizeof(lock_time)); index += sizeof(lock_time);
  memcpy(&message_length, data + index, sizeof(message_length)); index += sizeof(message_length);
  if (message_length > ALEPHIUM_MAX_MESSAGE_SIZE ||
      !has_bytes(data_length, index, message_length)) return ALEPHIUM_ERROR_INVALID_DATA;
  index += message_length;
  uint64_t tokens_count;
  err = decode_compact_int(data + index, data_length - index, &tokens_count, &field_length);
  if (err != ALEPHIUM_OK) return err;
  index += field_length;
  if (tokens_count > ALEPHIUM_MAX_TOKENS) return ALEPHIUM_ERROR_TOO_MANY_TOKENS;
  if (output) {
    memset(output, 0, sizeof(*output));
    strncpy(output->amount, amount, sizeof(output->amount) - 1);
    output->amount[sizeof(output->amount) - 1] = '\0';
    output->lockup_script_type = type;
    memcpy(output->lockup_script_hash, hash, sizeof(output->lockup_script_hash));
    output->lock_time = lock_time;
    output->message_length = message_length;
    output->tokens_count = (size_t)tokens_count;
    if (generate_address_from_output(type, hash, output->address, sizeof(output->address)) != ALEPHIUM_OK) {
      output->address[0] = '\0';
    }
  }
  for (size_t i = 0; i < (size_t)tokens_count; i++) {
    if (!has_bytes(data_length, index, 32)) return ALEPHIUM_ERROR_INVALID_DATA;
    if (output) memcpy(output->tokens[i].id, data + index, 32);
    index += 32;
    char token_amount[MAX_AMOUNT_STR_LENGTH];
    err = decode_u256(data + index, data_length - index, token_amount, sizeof(token_amount), &field_length);
    if (err != ALEPHIUM_OK) return err;
    if (output) {
      strncpy(output->tokens[i].amount, token_amount,
              sizeof(output->tokens[i].amount) - 1);
      output->tokens[i].amount[sizeof(output->tokens[i].amount) - 1] = '\0';
    }
    index += field_length;
  }
  *bytes_read = index;
  return ALEPHIUM_OK;
}

AlephiumError decode_alephium_tx(const uint8_t* data, size_t data_length,
                                 size_t bytecode_skip, AlephiumDecodedTx* tx) {
  if (!data || !tx || data_length < 3 || bytecode_skip > data_length - 3) return ALEPHIUM_ERROR_INVALID_DATA;
  memset(tx, 0, sizeof(*tx));
  tx->raw_data = data;
  tx->raw_data_length = data_length;
  tx->version = data[0]; tx->network_id = data[1]; tx->script_opt = data[2];
  size_t index = 3 + bytecode_skip, field_length;
  AlephiumError err = decode_i32(data + index, data_length - index, &tx->gas_amount, &field_length);
  if (err != ALEPHIUM_OK) return err;
  index += field_length;
  char gas_price_str[MAX_AMOUNT_STR_LENGTH];
  err = decode_u256(data + index, data_length - index, gas_price_str, sizeof(gas_price_str), &field_length);
  if (err != ALEPHIUM_OK) return err;
  index += field_length;
  tx->gas_price = strtoull(gas_price_str, NULL, 10);
  uint64_t inputs_count;
  err = decode_compact_int(data + index, data_length - index, &inputs_count, &field_length);
  if (err != ALEPHIUM_OK) return err;
  index += field_length;
  if (inputs_count > ALEPHIUM_MAX_INPUTS) return ALEPHIUM_ERROR_TOO_MANY_INPUTS;
  tx->inputs_count = (size_t)inputs_count;
  for (size_t i = 0; i < tx->inputs_count; i++) {
    if (!has_bytes(data_length, index, 36)) return ALEPHIUM_ERROR_INVALID_DATA;
    index += 36;
    err = decode_unlock_script(data + index, data_length - index, &field_length);
    if (err != ALEPHIUM_OK) return err;
    index += field_length;
  }
  uint64_t outputs_count;
  err = decode_compact_int(data + index, data_length - index, &outputs_count, &field_length);
  if (err != ALEPHIUM_OK) return err;
  index += field_length;
  if (outputs_count > ALEPHIUM_MAX_OUTPUTS) return ALEPHIUM_ERROR_TOO_MANY_OUTPUTS;
  tx->outputs_count = (size_t)outputs_count;
  for (size_t i = 0; i < tx->outputs_count; i++) {
    if (index >= data_length) return ALEPHIUM_ERROR_INVALID_DATA;
    if (i > 0 && (data[index] == 0x00 || data[index] == 0x01)) index++;
    if (index >= data_length) return ALEPHIUM_ERROR_INVALID_DATA;
    tx->output_offsets[i] = (uint32_t)index;
    err = decode_output(data + index, data_length - index, NULL, &field_length);
    if (err != ALEPHIUM_OK) return err;
    index += field_length;
  }
  return ALEPHIUM_OK;
}

AlephiumError decode_alephium_output(const AlephiumDecodedTx* tx, size_t output_index,
                                     AlephiumTxOutput* output) {
  if (!tx || !output || !tx->raw_data || output_index >= tx->outputs_count) return ALEPHIUM_ERROR_INVALID_DATA;
  size_t offset = tx->output_offsets[output_index];
  if (offset >= tx->raw_data_length) return ALEPHIUM_ERROR_INVALID_DATA;
  size_t bytes_read;
  return decode_output(tx->raw_data + offset, tx->raw_data_length - offset, output, &bytes_read);
}
