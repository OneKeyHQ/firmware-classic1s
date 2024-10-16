#include "alephium.h"
#include "alephium/alph_layout.h"

#define MAX_ALEPHIUM_DATA_SIZE 20480
static uint8_t alephium_data_buffer[MAX_ALEPHIUM_DATA_SIZE]
    __attribute__((section(".secMessageSection")));
static size_t alephium_data_left = 0;
static size_t alephium_data_total_size = 0;
static AlephiumTxRequest msg_tx_request;
static uint32_t alephium_address_n[8] = {0};
static uint32_t alephium_address_n_count = 0;
static HDNode global_node;

bool alephium_get_address(const AlephiumGetAddress *msg,
                          AlephiumAddress *resp) {
  return alph_get_address(msg, resp);
}

void alephium_sign_tx(const HDNode *node, const AlephiumSignTx *msg) {
  char log_buffer[1024];
  memcpy(&global_node, node, sizeof(HDNode));
  alephium_data_total_size = msg->data_initial_chunk.size;
  memcpy(alephium_data_buffer, msg->data_initial_chunk.bytes,
         msg->data_initial_chunk.size);
  alephium_address_n_count = msg->address_n_count;
  if (alephium_address_n_count > 8) {
    alephium_address_n_count = 8;
  }
  memcpy(alephium_address_n, msg->address_n,
         alephium_address_n_count * sizeof(uint32_t));

  if (msg->has_data_length && msg->data_length > 0 &&
      msg->data_length > msg->data_initial_chunk.size) {
    alephium_data_total_size = msg->data_length;
    alephium_data_left =
        alephium_data_total_size - msg->data_initial_chunk.size;
    snprintf(log_buffer, sizeof(log_buffer),
             "Requesting more data chunks, total size: %zu, data left: %zu",
             (size_t)alephium_data_total_size, (size_t)alephium_data_left);
    alephium_send_request_chunk();
  } else {
    if (alephium_data_buffer[2] == 1) {
      alephium_send_request_bytecode();
      return;
    }
    AlephiumDecodedTx decoded_tx;
    AlephiumError err = decode_alephium_tx(
        alephium_data_buffer, alephium_data_total_size, &decoded_tx);
    if (err != ALEPHIUM_OK) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Failed to decode transaction");
      alephium_signing_abort();
      return;
    }
    AlephiumSignedTx resp = {0};
    alephium_process_decoded_tx(&decoded_tx, NULL, 0, &resp);

    if (resp.signature.size == 64) {
      msg_write(MessageType_MessageType_AlephiumSignedTx, &resp);
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to generate signature");
    }

    layoutHome();
  }
}

void alephium_send_request_chunk(void) {
  msg_tx_request.has_data_length = true;
  msg_tx_request.data_length =
      alephium_data_left <= 1024 ? alephium_data_left : 1024;
  msg_write(MessageType_MessageType_AlephiumTxRequest, &msg_tx_request);
}

void alephium_send_request_bytecode(void) {
  AlephiumBytecodeRequest msg_bytecode_request;
  memset(&msg_bytecode_request, 0, sizeof(msg_bytecode_request));

  msg_bytecode_request.has_data_length = true;
  msg_bytecode_request.data_length = 1024;

  msg_write(MessageType_MessageType_AlephiumBytecodeRequest,
            &msg_bytecode_request);
}

void alephium_signing_txack(const AlephiumTxAck *tx) {
  char debug_msg[256];

  if (alephium_data_left == 0) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Alephium signing mode");
    layoutHome();
    return;
  }

  if (tx->data_chunk.size > alephium_data_left) {
    fsm_sendFailure(FailureType_Failure_DataError, "Too much data");
    alephium_signing_abort();
    return;
  }

  if (alephium_data_left > 0 && tx->data_chunk.size == 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "Empty data chunk received");
    alephium_signing_abort();
    return;
  }

  memcpy(alephium_data_buffer + (alephium_data_total_size - alephium_data_left),
         tx->data_chunk.bytes, tx->data_chunk.size);
  alephium_data_left -= tx->data_chunk.size;

  snprintf(debug_msg, sizeof(debug_msg), "Received data chunk size: %zu",
           (size_t)tx->data_chunk.size);
  snprintf(debug_msg, sizeof(debug_msg), "Data left after receiving chunk: %zu",
           (size_t)alephium_data_left);

  if (alephium_data_left > 0) {
    alephium_send_request_chunk();
  } else {
    if (alephium_data_buffer[2] == 1) {
      alephium_send_request_bytecode();
      return;
    }

    AlephiumDecodedTx decoded_tx;
    AlephiumError err = decode_alephium_tx(
        alephium_data_buffer, alephium_data_total_size, &decoded_tx);
    if (err != ALEPHIUM_OK) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Failed to decode transaction");
      alephium_signing_abort();
      return;
    }

    AlephiumSignedTx resp = {0};
    alephium_process_decoded_tx(&decoded_tx, NULL, 0, &resp);
    if (resp.signature.size == 64) {
      msg_write(MessageType_MessageType_AlephiumSignedTx, &resp);
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to generate signature");
    }

    layoutHome();
  }
}

void alephium_handle_bytecode_ack(const AlephiumBytecodeAck *msg) {
  if (msg->bytecode_data.size > 0) {
    size_t remove_length = msg->bytecode_data.size;
    if (remove_length > alephium_data_total_size) {
      fsm_sendFailure(FailureType_Failure_DataError, "Invalid remove_length");
      layoutHome();
      return;
    }
    size_t remove_bytecode_data_size = alephium_data_total_size - remove_length;

    if (remove_bytecode_data_size == 0) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "No data left after removing bytecode");
      layoutHome();
      return;
    }
    if (memcmp(alephium_data_buffer + 3, msg->bytecode_data.bytes,
               remove_length) != 0) {
      fsm_sendFailure(FailureType_Failure_DataError, "Bytecode data mismatch");
      layoutHome();
      return;
    }

    if (remove_bytecode_data_size < 3) {
      fsm_sendFailure(FailureType_Failure_DataError, "Data size too small");
      layoutHome();
      return;
    }
    uint8_t remove_bytecode_data_buffer[remove_bytecode_data_size];
    memcpy(remove_bytecode_data_buffer, alephium_data_buffer, 3);
    memcpy(remove_bytecode_data_buffer + 3,
           alephium_data_buffer + 3 + remove_length,
           remove_bytecode_data_size - 3);

    AlephiumDecodedTx decoded_tx;
    AlephiumError err = decode_alephium_tx(
        remove_bytecode_data_buffer, remove_bytecode_data_size, &decoded_tx);
    if (err != ALEPHIUM_OK) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Failed to decode transaction");
      alephium_signing_abort();
      return;
    }
    AlephiumSignedTx resp = {0};
    alephium_process_decoded_tx(&decoded_tx, msg->bytecode_data.bytes,
                                msg->bytecode_data.size, &resp);
    if (resp.signature.size == 64) {
      msg_write(MessageType_MessageType_AlephiumSignedTx, &resp);
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to generate signature");
    }

    layoutHome();

  } else {
    fsm_sendFailure(FailureType_Failure_DataError,
                    "Empty bytecode data received");
    layoutHome();
  }
}

void hex_string_to_decimal_string(const char *hex, char *decimal,
                                  size_t decimal_size) {
  size_t hex_len = strlen(hex);
  char *temp = calloc(hex_len * 4 + 1, sizeof(char));
  if (!temp) {
    snprintf(decimal, decimal_size, "Memory allocation failed");
    return;
  }
  temp[0] = '0';

  for (size_t i = 0; i < hex_len; i++) {
    int digit;
    if (hex[i] >= '0' && hex[i] <= '9')
      digit = hex[i] - '0';
    else if (hex[i] >= 'a' && hex[i] <= 'f')
      digit = hex[i] - 'a' + 10;
    else if (hex[i] >= 'A' && hex[i] <= 'F')
      digit = hex[i] - 'A' + 10;
    else {
      snprintf(decimal, decimal_size, "Invalid hex character");
      free(temp);
      return;
    }

    int carry = 0;
    for (size_t j = 0; temp[j] || carry; j++) {
      int val = (temp[j] ? temp[j] - '0' : 0) * 16 + carry;
      temp[j] = (val % 10) + '0';
      carry = val / 10;
    }

    carry = digit;
    for (size_t j = 0; carry; j++) {
      int val = (temp[j] ? temp[j] - '0' : 0) + carry;
      temp[j] = (val % 10) + '0';
      carry = val / 10;
    }
  }

  size_t len = strlen(temp);
  for (size_t i = 0; i < len / 2; i++) {
    char t = temp[i];
    temp[i] = temp[len - 1 - i];
    temp[len - 1 - i] = t;
  }

  strncpy(decimal, temp, decimal_size - 1);
  decimal[decimal_size - 1] = '\0';

  free(temp);
}

void alephium_signing_abort(void) {
  memset(alephium_data_buffer, 0, sizeof(alephium_data_buffer));
  memset(&global_node, 0, sizeof(HDNode));
  alephium_data_left = 0;
  alephium_data_total_size = 0;
  layoutHome();
}

void format_alph_amount_from_string(const char *amount_str, char *formatted,
                                    size_t formatted_size) {
  size_t len = strlen(amount_str);
  const size_t decimal_places = 18;

  if (len <= decimal_places) {
    snprintf(formatted, formatted_size, "0.");
    size_t zeros = decimal_places - len;
    for (size_t i = 0; i < zeros; i++) {
      strncat(formatted, "0", formatted_size - strlen(formatted) - 1);
    }
    strncat(formatted, amount_str, formatted_size - strlen(formatted) - 1);
  } else {
    size_t integer_len = len - decimal_places;
    strncpy(formatted, amount_str, integer_len);
    formatted[integer_len] = '\0';

    strncat(formatted, ".", formatted_size - strlen(formatted) - 1);
    strncat(formatted, amount_str + integer_len,
            formatted_size - strlen(formatted) - 1);
  }

  char *decimal_point = strchr(formatted, '.');
  if (decimal_point) {
    char *end = formatted + strlen(formatted) - 1;
    while (end > decimal_point && *end == '0') {
      *end = '\0';
      end--;
    }

    if (end == decimal_point) {
      *end = '\0';
    }
  }

  if (formatted[0] == '\0') {
    strcpy(formatted, "0");
  }
}

void uint64_to_decimal_string(uint64_t value, char *str, size_t str_size) {
  char temp[21];
  size_t i = 0;

  do {
    temp[i++] = (value % 10) + '0';
    value /= 10;
  } while (value > 0 && i < 20);

  size_t j = 0;
  while (i > 0 && j < str_size - 1) {
    str[j++] = temp[--i];
  }
  str[j] = '\0';
}

void alephium_calculate_total_fee(uint32_t gas_amount, uint64_t gas_price,
                                  char *total_fee, size_t total_fee_size) {
  uint64_t total_fee_value = (uint64_t)gas_amount * gas_price;
  uint64_to_decimal_string(total_fee_value, total_fee, total_fee_size);
}

bool generate_alephium_address(const uint8_t *public_key, char *address,
                               size_t address_size) {
  uint8_t hash[32];
  if (blake2b(public_key, 33, hash, sizeof(hash)) != 0) {
    return false;
  }

  uint8_t address_bytes[33];
  address_bytes[0] = 0x00;
  memcpy(address_bytes + 1, hash, 32);

  size_t encoded_size = address_size;
  return b58enc(address, &encoded_size, address_bytes, sizeof(address_bytes)) !=
         0;
}

void alephium_process_decoded_tx(const AlephiumDecodedTx *decoded_tx,
                                 const uint8_t *bytecode, size_t bytecode_size,
                                 AlephiumSignedTx *resp) {
  char debug_msg[256];
  char chain_name[32] = "Alephium";
  char signer[65] = {0};
  char current_address[50] = {0};

  if (!generate_alephium_address(global_node.public_key, current_address,
                                 sizeof(current_address))) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to generate current address");
    layoutHome();
    return;
  }

  for (size_t i = 0; i < decoded_tx->outputs_count; i++) {
    const AlephiumTxOutput *output = &decoded_tx->outputs[i];

    if (strcmp(output->address, current_address) == 0) {
      continue;
    }
    char formatted_amount[65] = {0};
    format_alph_amount_from_string(output->amount, formatted_amount,
                                   sizeof(formatted_amount));

    if (decoded_tx->inputs_count > 0 && i == 0) {
      data2hex(decoded_tx->inputs[0].key, 32, signer);
    }
    if (!layoutOutput(chain_name, formatted_amount, output->address, NULL, NULL,
                      NULL, 0)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Transaction cancelled by user");
      layoutHome();
      return;
    }

    for (size_t j = 0; j < output->tokens_count; j++) {
      char token_id[65] = {0};
      char token_amount[120] = {0};

      data2hex(output->tokens[j].id, 32, token_id);
      hex_string_to_decimal_string(output->tokens[j].amount, token_amount,
                                   sizeof(token_amount));

      if (!layoutOutput(chain_name, NULL, output->address, token_id,
                        output->tokens[j].amount, NULL, 0)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Transaction cancelled by user");
        layoutHome();
        return;
      }
    }
  }

  if (bytecode && bytecode_size > 0) {
    size_t offset = 0;
    for (size_t i = 0; i < bytecode_size; i++) {
      offset += snprintf(debug_msg + offset, sizeof(debug_msg) - offset, "%02x",
                         bytecode[i]);
      if ((i + 1) % 16 == 0 || i == bytecode_size - 1) {
        offset = 0;
      }
    }

    if (!layoutOutput(chain_name, NULL, NULL, NULL, NULL, bytecode,
                      bytecode_size)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Transaction cancelled by user");
      layoutHome();
      return;
    }
  }

  char total_fee[41] = {0};
  alephium_calculate_total_fee(decoded_tx->gas_amount, decoded_tx->gas_price,
                               total_fee, sizeof(total_fee));

  char formatted_fee[65] = {0};
  format_alph_amount_from_string(total_fee, formatted_fee,
                                 sizeof(formatted_fee));

  if (!layoutFee(formatted_fee)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Transaction cancelled by user");
    layoutHome();
    return;
  }

  if (!layoutFinal()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Transaction cancelled by user");
    layoutHome();
    return;
  }

  uint8_t hash[32];
  blake2b(alephium_data_buffer, alephium_data_total_size, hash, sizeof(hash));
  uint8_t signature[64];
  uint8_t v;
  int ret = hdnode_sign_digest(&global_node, hash, signature, &v, NULL);
  if (ret != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    layoutHome();
    return;
  }

  resp->signature.size = 64;
  memcpy(resp->signature.bytes, signature, 64);
  return;
}

bool alephium_sign_message(const HDNode *node, const AlephiumSignMessage *msg,
                           AlephiumMessageSignature *resp) {
  if (!node || !msg || !resp) {
    return false;
  }

  const char *prefix = "Alephium Signed Message: ";
  uint8_t prefixed_message[1024 * 30 + 64];
  size_t prefix_len = strlen(prefix);
  memcpy(prefixed_message, prefix, prefix_len);
  memcpy(prefixed_message + prefix_len, msg->message.bytes, msg->message.size);
  size_t total_len = prefix_len + msg->message.size;

  uint8_t hash[32];
  blake2b(prefixed_message, total_len, hash, sizeof(hash));

  char address[100];
  if (!generate_alephium_address(node->public_key, address, sizeof(address))) {
    return false;
  }

  uint8_t signature[64];
  uint8_t pby;
  if (hdnode_sign_digest(node, hash, signature, &pby, NULL) != 0) {
    return false;
  }
  resp->has_address = true;
  strlcpy(resp->address, address, sizeof(resp->address));
  resp->has_signature = true;
  memcpy(resp->signature.bytes, signature, 64);
  resp->signature.size = 64;
  return true;
}