#include "alephium.h"
#include "alephium/alph_layout.h"
#include "signing_workspace.h"

#define MAX_ALEPHIUM_DATA_SIZE 20480
static uint8_t alephium_data_buffer[MAX_ALEPHIUM_DATA_SIZE]
    __attribute__((section(".secMessageSection")));
static size_t alephium_data_left;
static size_t alephium_data_total_size;
static AlephiumTxRequest msg_tx_request;
static HDNode global_node;
static uint32_t alephium_address_n[8];
static uint32_t alephium_address_n_count;
typedef enum {
  ALEPHIUM_SIGNING_IDLE,
  ALEPHIUM_SIGNING_WAIT_CHUNK,
  ALEPHIUM_SIGNING_WAIT_BYTECODE,
  ALEPHIUM_SIGNING_PROCESSING,
} AlephiumSigningState;
static AlephiumSigningState alephium_signing_state;
static bool alephium_cancel_requested;

static void alephium_clear_signing_state(void) {
  memset(alephium_data_buffer, 0, sizeof(alephium_data_buffer));
  memset(&global_node, 0, sizeof(global_node));
  memset(alephium_address_n, 0, sizeof(alephium_address_n));
  alephium_address_n_count = 0;
  memset(&msg_tx_request, 0, sizeof(msg_tx_request));
  alephium_data_left = 0;
  alephium_data_total_size = 0;
  alephium_cancel_requested = false;
  alephium_signing_state = ALEPHIUM_SIGNING_IDLE;
  signing_workspace_release(SigningWorkspaceOwner_ALEPHIUM);
}

static void alephium_fail(FailureType failure, const char *message) {
  fsm_sendFailure(failure, message);
  alephium_clear_signing_state();
  layoutHome();
}

static bool alephium_is_cancelled(void) { return alephium_cancel_requested; }

static void alephium_complete_transaction(size_t bytecode_skip,
                                          const uint8_t *bytecode,
                                          size_t bytecode_size);

bool alephium_get_address(const AlephiumGetAddress *msg,
                          AlephiumAddress *resp) {
  return alph_get_address(msg, resp);
}

void alephium_sign_tx(const HDNode *node, const AlephiumSignTx *msg) {
  if (!node || !msg || alephium_signing_state != ALEPHIUM_SIGNING_IDLE ||
      !signing_workspace_acquire(SigningWorkspaceOwner_ALEPHIUM)) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing is busy");
    return;
  }

  size_t initial_size = msg->data_initial_chunk.size;
  if (msg->address_n_count > sizeof(alephium_address_n) /
                                  sizeof(alephium_address_n[0]) ||
      msg->address_n_count > sizeof(msg->address_n) /
                                  sizeof(msg->address_n[0])) {
    alephium_fail(FailureType_Failure_DataError, "Invalid address path");
    return;
  }
  size_t total_size = msg->has_data_length && msg->data_length > 0
                          ? msg->data_length
                          : initial_size;
  if (total_size > MAX_ALEPHIUM_DATA_SIZE || initial_size > total_size ||
      initial_size > MAX_ALEPHIUM_DATA_SIZE ||
      initial_size > sizeof(msg->data_initial_chunk.bytes)) {
    alephium_fail(FailureType_Failure_DataError, "Invalid transaction length");
    return;
  }

  memcpy(&global_node, node, sizeof(HDNode));
  alephium_address_n_count = msg->address_n_count;
  memcpy(alephium_address_n, msg->address_n,
         alephium_address_n_count * sizeof(alephium_address_n[0]));
  alephium_data_total_size = total_size;
  memcpy(alephium_data_buffer, msg->data_initial_chunk.bytes, initial_size);
  alephium_data_left = total_size - initial_size;
  if (alephium_data_left > 0) {
    alephium_signing_state = ALEPHIUM_SIGNING_WAIT_CHUNK;
    alephium_send_request_chunk();
    return;
  }
  if (alephium_data_total_size < 3) {
    alephium_fail(FailureType_Failure_DataError, "Failed to decode transaction");
    return;
  }
  if (alephium_data_buffer[2] == 1) {
    alephium_signing_state = ALEPHIUM_SIGNING_WAIT_BYTECODE;
    alephium_send_request_bytecode();
    return;
  }
  alephium_complete_transaction(0, NULL, 0);
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
  if (!tx || alephium_signing_state != ALEPHIUM_SIGNING_WAIT_CHUNK ||
      alephium_data_left == 0) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Alephium signing mode");
    if (alephium_signing_state == ALEPHIUM_SIGNING_PROCESSING) {
      alephium_signing_abort();
    } else if (alephium_signing_state != ALEPHIUM_SIGNING_IDLE) {
      alephium_clear_signing_state();
      layoutHome();
    }
    return;
  }
  size_t received = alephium_data_total_size - alephium_data_left;
  if (tx->data_chunk.size > sizeof(tx->data_chunk.bytes) ||
      tx->data_chunk.size > alephium_data_left ||
      tx->data_chunk.size > MAX_ALEPHIUM_DATA_SIZE - received) {
    alephium_fail(FailureType_Failure_DataError, "Too much data");
    return;
  }
  if (tx->data_chunk.size == 0) {
    alephium_fail(FailureType_Failure_DataError, "Empty data chunk received");
    return;
  }
  memcpy(alephium_data_buffer + received, tx->data_chunk.bytes,
         tx->data_chunk.size);
  alephium_data_left -= tx->data_chunk.size;
  if (alephium_data_left > 0) {
    alephium_send_request_chunk();
    return;
  }
  if (alephium_data_total_size < 3) {
    alephium_fail(FailureType_Failure_DataError, "Failed to decode transaction");
    return;
  }
  if (alephium_data_buffer[2] == 1) {
    alephium_signing_state = ALEPHIUM_SIGNING_WAIT_BYTECODE;
    alephium_send_request_bytecode();
    return;
  }
  alephium_complete_transaction(0, NULL, 0);
}

void alephium_handle_bytecode_ack(const AlephiumBytecodeAck *msg) {
  if (!msg || alephium_signing_state != ALEPHIUM_SIGNING_WAIT_BYTECODE) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Alephium signing mode");
    if (alephium_signing_state == ALEPHIUM_SIGNING_PROCESSING) {
      alephium_signing_abort();
    } else if (alephium_signing_state != ALEPHIUM_SIGNING_IDLE) {
      alephium_clear_signing_state();
      layoutHome();
    }
    return;
  }
  size_t bytecode_size = msg->bytecode_data.size;
  if (bytecode_size == 0 || bytecode_size > sizeof(msg->bytecode_data.bytes) ||
      alephium_data_total_size < 3 ||
      bytecode_size > alephium_data_total_size - 3) {
    alephium_fail(FailureType_Failure_DataError, "Invalid bytecode data");
    return;
  }
  if (memcmp(alephium_data_buffer + 3, msg->bytecode_data.bytes,
             bytecode_size) != 0) {
    alephium_fail(FailureType_Failure_DataError, "Bytecode data mismatch");
    return;
  }
  alephium_complete_transaction(bytecode_size, alephium_data_buffer + 3,
                                bytecode_size);
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
  if (alephium_signing_state == ALEPHIUM_SIGNING_PROCESSING) {
    alephium_cancel_requested = true;
    return;
  }
  alephium_clear_signing_state();
  layoutHome();
}

void alephium_signing_clear_runtime_state(void) {
  if (alephium_signing_state == ALEPHIUM_SIGNING_PROCESSING) {
    alephium_cancel_requested = true;
    return;
  }
  alephium_clear_signing_state();
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

static bool alephium_process_decoded_tx(const AlephiumDecodedTx *decoded_tx,
                                        const uint8_t *bytecode,
                                        size_t bytecode_size,
                                        AlephiumSignedTx *resp) {
  char debug_msg[256];
  char chain_name[32] = "Alephium";
  char current_address[50] = {0};

  if (!generate_alephium_address(global_node.public_key, current_address,
                                 sizeof(current_address))) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to generate current address");
    return false;
  }

  for (size_t i = 0; i < decoded_tx->outputs_count; i++) {
    AlephiumTxOutput output;
    if (decode_alephium_output(decoded_tx, i, &output) != ALEPHIUM_OK) {
      fsm_sendFailure(FailureType_Failure_DataError, "Failed to decode transaction");
      return false;
    }
    if (alephium_is_cancelled()) return false;

    if (strcmp(output.address, current_address) == 0) {
      continue;
    }
    char formatted_amount[65] = {0};
    format_alph_amount_from_string(output.amount, formatted_amount,
                                   sizeof(formatted_amount));

    if (!layoutOutput(chain_name, formatted_amount, output.address, NULL, NULL,
                      NULL, 0)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Transaction cancelled by user");
      return false;
    }
    if (alephium_is_cancelled()) return false;

    for (size_t j = 0; j < output.tokens_count; j++) {
      char token_id[65] = {0};
      data2hex(output.tokens[j].id, 32, token_id);

      if (!layoutOutput(chain_name, NULL, output.address, token_id,
                        output.tokens[j].amount, NULL, 0)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Transaction cancelled by user");
        return false;
      }
      if (alephium_is_cancelled()) return false;
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
      return false;
    }
    if (alephium_is_cancelled()) return false;
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
    return false;
  }
  if (alephium_is_cancelled()) return false;

  if (!layoutFinal()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Transaction cancelled by user");
    return false;
  }
  if (alephium_is_cancelled()) return false;

  uint8_t hash[32];
  blake2b(alephium_data_buffer, alephium_data_total_size, hash, sizeof(hash));
  if (alephium_is_cancelled()) return false;
  uint8_t signature[64];
  uint8_t v;
  HDNode *signing_node = fsm_getDerivedNode(
      SECP256K1_NAME, alephium_address_n, alephium_address_n_count, NULL);
  if (!signing_node) return false;
  if (alephium_is_cancelled()) return false;
  if (hdnode_fill_public_key(signing_node) != 0 ||
      memcmp(signing_node->public_key, global_node.public_key,
             sizeof(global_node.public_key)) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to restore signing path");
    return false;
  }
  if (alephium_is_cancelled()) return false;
  int ret = hdnode_sign_digest(signing_node, hash, signature, &v, NULL);
  if (alephium_is_cancelled()) return false;
  if (ret != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return false;
  }

  resp->signature.size = 64;
  memcpy(resp->signature.bytes, signature, 64);
  return true;
}

static void alephium_complete_transaction(size_t bytecode_skip,
                                          const uint8_t *bytecode,
                                          size_t bytecode_size) {
  AlephiumDecodedTx decoded_tx;
  AlephiumError err = decode_alephium_tx(alephium_data_buffer,
                                         alephium_data_total_size,
                                         bytecode_skip, &decoded_tx);
  if (err != ALEPHIUM_OK) {
    char error_msg[128];
    if (err == ALEPHIUM_ERROR_TOO_MANY_INPUTS) {
      snprintf(error_msg, sizeof(error_msg), "Too many inputs (max %d supported)",
               ALEPHIUM_MAX_INPUTS);
    } else {
      snprintf(error_msg, sizeof(error_msg), "Failed to decode transaction");
    }
    alephium_fail(FailureType_Failure_DataError, error_msg);
    return;
  }

  alephium_signing_state = ALEPHIUM_SIGNING_PROCESSING;
  AlephiumSignedTx resp = {0};
  bool signed_tx = alephium_process_decoded_tx(&decoded_tx, bytecode,
                                                bytecode_size, &resp);
  bool cancelled = alephium_is_cancelled();
  if (signed_tx && !cancelled && resp.signature.size == 64) {
    msg_write(MessageType_MessageType_AlephiumSignedTx, &resp);
  } else if (!cancelled && signed_tx) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Failed to generate signature");
  }
  alephium_clear_signing_state();
  layoutHome();
}

bool alephium_sign_message(const HDNode *node, const AlephiumSignMessage *msg,
                           AlephiumMessageSignature *resp) {
  if (!node || !msg || !resp || msg->message.size > sizeof(msg->message.bytes)) {
    return false;
  }

  const char *prefix = "Alephium Signed Message: ";
  size_t prefix_len = strlen(prefix);
  uint8_t hash[32];
  BLAKE2B_CTX hash_ctx;
  blake2b_Init(&hash_ctx, sizeof(hash));
  blake2b_Update(&hash_ctx, (const uint8_t *)prefix, prefix_len);
  blake2b_Update(&hash_ctx, msg->message.bytes, msg->message.size);
  blake2b_Final(&hash_ctx, hash, sizeof(hash));

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
