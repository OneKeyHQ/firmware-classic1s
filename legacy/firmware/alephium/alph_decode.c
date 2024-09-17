#include "alph_decode.h"

#define SINGLE_BYTE_LIMIT 0x40
#define TWO_BYTE_LIMIT 0x80
#define MULTI_BYTE_LIMIT 0xC0

#define PREFIX_SINGLE_BYTE 0x00
#define PREFIX_TWO_BYTES 0x40
#define PREFIX_FOUR_BYTES 0x80
#define PREFIX_MULTI_BYTES 0xC0

#define SIGN_BIT 0x20
#define VALUE_MASK 0x3F

AlephiumError decode_compact_int(const uint8_t* data, uint64_t* value,
                                 size_t* bytes_read) {
  if (!data || !value || !bytes_read) {
    return ALEPHIUM_ERROR_INVALID_DATA;
  }

  uint8_t first_byte = data[0];
  if (first_byte < 0xFD) {
    *value = first_byte;
    *bytes_read = 1;
    return ALEPHIUM_OK;
  } else if (first_byte == 0xFD) {
    *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8);
    *bytes_read = 3;
    return ALEPHIUM_OK;
  } else if (first_byte == 0xFE) {
    *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8) |
             ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24);
    *bytes_read = 5;
    return ALEPHIUM_OK;
  } else {
    *value = (uint64_t)data[1] | ((uint64_t)data[2] << 8) |
             ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24) |
             ((uint64_t)data[5] << 32) | ((uint64_t)data[6] << 40) |
             ((uint64_t)data[7] << 48) | ((uint64_t)data[8] << 56);
    *bytes_read = 9;
    return ALEPHIUM_OK;
  }
}

AlephiumError decode_i32(const uint8_t* data, int32_t* value,
                         size_t* bytes_read) {
  if (!data || !value || !bytes_read) {
    return ALEPHIUM_ERROR_INVALID_DATA;
  }

  uint8_t first_byte = data[0];
  uint8_t prefix = first_byte & PREFIX_MULTI_BYTES;

  if (prefix == PREFIX_SINGLE_BYTE) {
    *value = (first_byte & SIGN_BIT) ? -(64 - first_byte) : first_byte;
    *bytes_read = 1;
  } else if (prefix == PREFIX_TWO_BYTES) {
    uint16_t val = ((uint16_t)(first_byte & VALUE_MASK) << 8) | data[1];
    *value = (first_byte & SIGN_BIT) ? -(16384 - val) : val;
    *bytes_read = 2;
  } else if (prefix == PREFIX_FOUR_BYTES) {
    uint32_t val = ((uint32_t)(first_byte & VALUE_MASK) << 24) |
                   ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) |
                   data[3];
    *value = (first_byte & SIGN_BIT) ? -(1073741824 - val) : val;
    *bytes_read = 4;
  } else {
    size_t length = (first_byte & VALUE_MASK) + 5;
    uint64_t val = 0;
    for (size_t i = 1; i < length; i++) {
      val = (val << 8) | data[i];
    }
    *value = (first_byte & SIGN_BIT) ? -val : val;
    *bytes_read = length;
  }

  return ALEPHIUM_OK;
}

void format_hex_to_decimal(const char* hex_str, char* decimal_str,
                           size_t decimal_str_size) {
  size_t hex_len = strlen(hex_str);
  size_t decimal_len = 0;
  char temp[256] = "0";

  for (size_t i = 0; i < hex_len; i++) {
    int digit;
    if (isdigit((unsigned char)hex_str[i])) {
      digit = hex_str[i] - '0';
    } else {
      digit = tolower((unsigned char)hex_str[i]) - 'a' + 10;
    }

    for (size_t j = 0; j < decimal_len || digit; j++) {
      int value = (j < decimal_len ? temp[j] - '0' : 0) * 16 + digit;
      temp[j] = value % 10 + '0';
      digit = value / 10;
      if (j >= decimal_len) decimal_len++;
    }
  }

  for (size_t i = 0; i < decimal_len / 2; i++) {
    char c = temp[i];
    temp[i] = temp[decimal_len - 1 - i];
    temp[decimal_len - 1 - i] = c;
  }

  strncpy(decimal_str, temp, decimal_str_size - 1);
  decimal_str[decimal_str_size - 1] = '\0';
}

AlephiumError decode_u256(const uint8_t* data, char* value_str,
                          size_t value_str_size, size_t* bytes_read) {
  if (!data || !value_str || !bytes_read) {
    return ALEPHIUM_ERROR_INVALID_DATA;
  }

  uint8_t first_byte = data[0];
  size_t length = 0;

  if (first_byte < SINGLE_BYTE_LIMIT) {
    snprintf(value_str, value_str_size, "%u", first_byte);
    *bytes_read = 1;
    return ALEPHIUM_OK;
  } else if (first_byte < TWO_BYTE_LIMIT) {
    uint16_t value = ((uint16_t)(first_byte & 0x3F) << 8) | data[1];
    snprintf(value_str, value_str_size, "%u", value);
    *bytes_read = 2;
  } else if (first_byte < MULTI_BYTE_LIMIT) {
    length = (first_byte - TWO_BYTE_LIMIT) + 3;
  } else {
    length = (first_byte - MULTI_BYTE_LIMIT) + 4;
  }

  if (first_byte >= TWO_BYTE_LIMIT) {
    if (length > 32 || length * 2 >= value_str_size) {
      return ALEPHIUM_ERROR_BUFFER_OVERFLOW;
    }
    for (size_t i = 1; i <= length; i++) {
      snprintf(value_str + (i - 1) * 2, 3, "%02x", data[i]);
    }
    value_str[length * 2] = '\0';
    char* start = value_str;
    while (*start == '0' && *(start + 1) != '\0') {
      start++;
    }
    if (start != value_str) {
      memmove(value_str, start, strlen(start) + 1);
    }
    *bytes_read = length + 1;

    char decimal_str[256];
    format_hex_to_decimal(value_str, decimal_str, sizeof(decimal_str));
    strncpy(value_str, decimal_str, value_str_size - 1);
    value_str[value_str_size - 1] = '\0';
  }

  return ALEPHIUM_OK;
}

AlephiumError decode_unlock_script(const uint8_t* data, uint8_t* script,
                                   size_t max_length, size_t* bytes_read) {
  if (!data || !script || !bytes_read) {
    return ALEPHIUM_ERROR_INVALID_DATA;
  }

  uint8_t script_type = data[0];
  size_t length = 0;

  if (script_type == 0) {
    length = 34;
  } else if (script_type == 1) {
    uint64_t mpk_count;
    size_t bytes_read_inner;
    AlephiumError err =
        decode_compact_int(data + 1, &mpk_count, &bytes_read_inner);
    if (err != ALEPHIUM_OK) return err;
    length = 1 + bytes_read_inner + mpk_count * 37;
  } else if (script_type == 2) {
    uint64_t script_length, params_length;
    size_t bytes_read_inner1, bytes_read_inner2;
    AlephiumError err =
        decode_compact_int(data + 1, &script_length, &bytes_read_inner1);
    if (err != ALEPHIUM_OK) return err;
    err = decode_compact_int(data + 1 + bytes_read_inner1 + script_length,
                             &params_length, &bytes_read_inner2);
    if (err != ALEPHIUM_OK) return err;
    length = 1 + bytes_read_inner1 + script_length + bytes_read_inner2 +
             params_length;
  } else if (script_type == 3) {
    length = 1;
  } else {
    return ALEPHIUM_ERROR_UNSUPPORTED_SCRIPT;
  }

  if (length > max_length) {
    return ALEPHIUM_ERROR_BUFFER_OVERFLOW;
  }

  memcpy(script, data, length);
  *bytes_read = length;
  return ALEPHIUM_OK;
}

AlephiumError generate_address_from_output(uint8_t lockup_script_type,
                                           const uint8_t* lockup_script_hash,
                                           char* address, size_t address_size) {
  if (lockup_script_type != SCRIPT_TYPE_P2PKH &&
      lockup_script_type != SCRIPT_TYPE_P2MPKH &&
      lockup_script_type != SCRIPT_TYPE_P2SH) {
    return ALEPHIUM_ERROR_UNSUPPORTED_SCRIPT;
  }

  uint8_t address_bytes[33];
  address_bytes[0] = lockup_script_type;
  memcpy(address_bytes + 1, lockup_script_hash, 32);

  size_t out_len = address_size;
  if (b58enc(address, &out_len, address_bytes, sizeof(address_bytes)) == 0) {
    return ALEPHIUM_ERROR_UNSUPPORTED_SCRIPT;
  }

  return ALEPHIUM_OK;
}

void format_alph_amount(long double amount, char* formatted,
                        size_t formatted_size) {
  snprintf(formatted, formatted_size, "%.18Lf", amount);

  char* end = formatted + strlen(formatted) - 1;
  while (*end == '0' && end > formatted && *(end - 1) != '.') {
    end--;
  }
  if (*end == '.') {
    end--;
  }
  *(end + 1) = '\0';
}

AlephiumError decode_alephium_tx(const uint8_t* data, size_t data_length,
                                 AlephiumDecodedTx* tx) {
  if (!data || !tx) {
    return ALEPHIUM_ERROR_INVALID_DATA;
  }

  size_t index = 0;
  size_t bytes_read;

  tx->version = data[index++];
  tx->network_id = data[index++];
  tx->script_opt = data[index++];

  AlephiumError err = decode_i32(data + index, &tx->gas_amount, &bytes_read);
  if (err != ALEPHIUM_OK) return err;
  index += bytes_read;

  char gas_price_str[65];
  err = decode_u256(data + index, gas_price_str, sizeof(gas_price_str),
                    &bytes_read);
  if (err != ALEPHIUM_OK) return err;
  index += bytes_read;
  tx->gas_price = strtoull(gas_price_str, NULL, 10);
  long double gas_price_alph =
      strtold(gas_price_str, NULL) / 1000000000000000000.0L;
  char formatted_gas_price[50];
  format_alph_amount(gas_price_alph, formatted_gas_price,
                     sizeof(formatted_gas_price));

  uint64_t inputs_count;
  err = decode_compact_int(data + index, &inputs_count, &bytes_read);
  if (err != ALEPHIUM_OK) return err;
  index += bytes_read;
  tx->inputs_count = (size_t)inputs_count;
  if (tx->inputs_count > MAX_INPUTS) {
    return ALEPHIUM_ERROR_TOO_MANY_INPUTS;
  }

  for (size_t i = 0; i < tx->inputs_count && i < MAX_INPUTS; i++) {
    memcpy(&tx->inputs[i].hint, data + index, 4);
    index += 4;
    memcpy(tx->inputs[i].key, data + index, 32);
    index += 32;
    err =
        decode_unlock_script(data + index, tx->inputs[i].unlock_script,
                             sizeof(tx->inputs[i].unlock_script), &bytes_read);
    if (err != ALEPHIUM_OK) return err;
    tx->inputs[i].unlock_script_length = bytes_read;
    index += bytes_read;
  }

  uint64_t outputs_count;
  err = decode_compact_int(data + index, &outputs_count, &bytes_read);
  if (err != ALEPHIUM_OK) return err;
  index += bytes_read;
  tx->outputs_count = (size_t)outputs_count;
  if (tx->outputs_count > MAX_OUTPUTS) {
    return ALEPHIUM_ERROR_TOO_MANY_OUTPUTS;
  }

  for (size_t i = 0; i < tx->outputs_count && i < MAX_OUTPUTS; i++) {
    if (tx->outputs[i].tokens_count > MAX_TOKENS) {
      return ALEPHIUM_ERROR_TOO_MANY_TOKENS;
    }
    if (index >= data_length) {
      return ALEPHIUM_ERROR_INVALID_DATA;
    }

    if (i > 0 && (data[index] == 0x00 || data[index] == 0x01)) {
      index++;
    }

    AlephiumError rr = decode_u256(data + index, tx->outputs[i].amount,
                                   sizeof(tx->outputs[i].amount), &bytes_read);
    if (rr == ALEPHIUM_OK) {
    } else {
      return rr;
    }
    index += bytes_read;

    long double alph_amount = 0.0L;
    long double multiplier = 1.0L;
    size_t amount_len = strlen(tx->outputs[i].amount);
    for (int j = amount_len - 1; j >= 0; j -= 8) {
      int start = (j - 7 > 0) ? (j - 7) : 0;
      int len = j - start + 1;
      char temp[9] = {0};
      strncpy(temp, tx->outputs[i].amount + start, len);
      uint64_t part = strtoull(temp, NULL, 10);
      alph_amount += part * multiplier;
      multiplier *= 100000000.0L;
    }
    alph_amount /= 1000000000000000000.0L;

    char formatted_amount[50];
    format_alph_amount(alph_amount, formatted_amount, sizeof(formatted_amount));

    tx->outputs[i].lockup_script_type = data[index++];
    memcpy(tx->outputs[i].lockup_script_hash, data + index, 32);
    index += 32;

    AlephiumError addr_err = generate_address_from_output(
        tx->outputs[i].lockup_script_type, tx->outputs[i].lockup_script_hash,
        tx->outputs[i].address, sizeof(tx->outputs[i].address));
    if (addr_err == ALEPHIUM_OK) {
    } else {
      tx->outputs[i].address[0] = '\0';
    }

    memcpy(&tx->outputs[i].lock_time, data + index, 4);
    index += 4;

    memcpy(&tx->outputs[i].message_length, data + index, 4);
    index += 4;
    memcpy(tx->outputs[i].message, data + index, tx->outputs[i].message_length);
    index += tx->outputs[i].message_length;

    uint64_t tokens_count;
    err = decode_compact_int(data + index, &tokens_count, &bytes_read);
    if (err != ALEPHIUM_OK) return err;
    index += bytes_read;
    tx->outputs[i].tokens_count = (size_t)tokens_count;

    for (size_t j = 0; j < tx->outputs[i].tokens_count && j < MAX_TOKENS; j++) {
      memcpy(tx->outputs[i].tokens[j].id, data + index, 32);
      index += 32;
      err = decode_u256(data + index, tx->outputs[i].tokens[j].amount,
                        sizeof(tx->outputs[i].tokens[j].amount), &bytes_read);
      if (err != ALEPHIUM_OK) return err;
      index += bytes_read;
    }
  }

  return ALEPHIUM_OK;
}
