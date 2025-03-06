#include "neo.h"
#include <stdio.h>
#include "base58.h"
#include "buttons.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "neo_tokens.h"
#include "protect.h"
#include "util.h"

#define ADDRESS_VERSION 0x35
#define COMPRESSED_PUBLIC_KEY_SIZE 33
#define MAX_ADDRESS_SIZE 34
#define UINT_160_SIZE 20
#define VERIFICATION_SCRIPT_SUFFIX "\x41\x56\xe7\xb3\x27"
#define VERIFICATION_SCRIPT_PREFIX "\x0C\x21"
#define MAX_TX_SIGNERS 2
#define MAX_TX_ATTRIBUTES 2
#define MAX_TX_SCRIPT_SIZE 1024
#define NETWORK_MAGIC_MAINNET 860833102
#define NETWORK_MAGIC_TESTNET 894710606

static bool build_check_sig_script_hash(const uint8_t *public_key,
                                        uint8_t *script_hash) {
  if (public_key[0] != 0x02 && public_key[0] != 0x03) {
    return false;
  }
  uint8_t verification_script[40];
  memcpy(verification_script, VERIFICATION_SCRIPT_PREFIX, 2);
  memcpy(verification_script + 2, public_key, COMPRESSED_PUBLIC_KEY_SIZE);
  memcpy(verification_script + 35, VERIFICATION_SCRIPT_SUFFIX, 5);
  uint8_t temp_hash[32];
  hasher_Raw(HASHER_SHA2_RIPEMD, verification_script,
             sizeof(verification_script), temp_hash);
  memcpy(script_hash, temp_hash, 20);
  return true;
}

static bool neo_address_from_script_hash(const uint8_t *script_hash,
                                         char *address) {
  uint8_t payload[21] = {ADDRESS_VERSION};
  memcpy(payload + 1, script_hash, 20);
  return base58_encode_check(payload, sizeof(payload), HASHER_SHA2D, address,
                             MAX_ADDRESS_SIZE + 1);
}

bool neo_address_from_pubkey(const uint8_t *public_key, char *address) {
  uint8_t script_hash[20];
  if (!build_check_sig_script_hash(public_key, script_hash)) {
    return false;
  }
  return neo_address_from_script_hash(script_hash, address);
}

typedef enum {
  OK = 0,
  INVALID_DATA = 1,
  INVALID_DATA_LENGTH = 2,
  INVALID_TRANSACTION_VERSION = 3,
  INVALID_NONCE = 4,
  INVALID_SYSTEM_FEE = 5,
  INVALID_NETWORK_FEE = 6,
  INVALID_VALID_UNTIL_BLOCK = 7,
  INVALID_SIGNER_LENGTH = 8,
  INVALID_SIGNER_ACCOUNT = 9,
  DUPLICATE_SIGNER_ACCOUNT = 10,
  INVALID_SCOPE_GLOBAL_FLAG_MUTEX = 11,
  INVALID_SIGNER_ALLOWED_CONTRACTS_LENGTH = 12,
  INVALID_SIGNER_ALLOWED_CONTRACTS_ACCOUNT = 13,
  INVALID_SIGNER_ALLOWED_GROUPS_LENGTH = 14,
  INVALID_ATTRIBUTES_LENGTH = 15,
  UNSUPPORTED_WITNESS_SCOPE_TYPE = 16,
  INVALID_ATTRIBUTES_TYPE = 17,
  INVALID_ATTRIBUTES_DUPLICATE = 18,
} ERROR_CODE;

typedef enum {
  NONE = 0,
  CALLED_BY_ENTRY = 0x1,
  CUSTOM_CONTRACTS = 0x10,
  CUSTOM_GROUPS = 0x20,
  WITNESS_RULES = 0x40,
  GLOBAL = 0x80
} WitnessScope;

#define MAX_SIGNER_ALLOWED_CONTRACTS 16
#define MAX_SIGNER_ALLOWED_GROUPS 16

typedef struct {
  uint8_t account[UINT_160_SIZE];
  WitnessScope scope;
  uint8_t allowed_contracts[MAX_SIGNER_ALLOWED_CONTRACTS][UINT_160_SIZE];
  uint8_t allowed_contracts_size;
  uint8_t allowed_groups[MAX_SIGNER_ALLOWED_GROUPS][COMPRESSED_PUBLIC_KEY_SIZE];
  uint8_t allowed_groups_size;
} Signer;

typedef enum { HIGH_PRIORITY = 0x1, ORACLE_RESPONSE = 0x11 } TxAttributeType;

typedef struct {
  TxAttributeType type;
} Attribute;

typedef struct {
  uint8_t version;
  uint32_t nonce;
  int64_t system_fee;
  int64_t network_fee;
  uint32_t valid_until_block;
  Signer signers[MAX_TX_SIGNERS];
  uint8_t signers_size;
  Attribute attributes[MAX_TX_ATTRIBUTES];
  uint8_t attributes_size;
  uint8_t script[MAX_TX_SCRIPT_SIZE];
  uint16_t script_size;
  bool is_asset_transfer;
  int64_t amount;
  char dst_address[MAX_ADDRESS_SIZE + 1];
  char src_address[MAX_ADDRESS_SIZE + 1];
  uint8_t contract_script_hash[UINT_160_SIZE];
  bool is_vote_script;
  bool is_remove_vote;
  char vote_to[MAX_ADDRESS_SIZE + 1];
} Transaction;

static void parse_transfer_script(Transaction *transaction) {
  uint8_t opcode;
  BufferReader reader = {0};
  init_buffer_reader(&reader, transaction->script, transaction->script_size);
  if (!read_bytes(&reader, &opcode, sizeof(opcode))) {
    return;
  }
  if (opcode != 0xb) {
    return;
  }
  if (!read_bytes(&reader, &opcode, sizeof(opcode))) {
    return;
  }
  if (opcode >= 0x10 && opcode <= 0x20) {
    transaction->amount = (int64_t)opcode - 0x10;
  } else if (opcode == 0x00) {
    int8_t value;
    if (!read_bytes(&reader, (uint8_t *)&value, sizeof(value))) {
      return;
    }
    transaction->amount = (int64_t)value;
  } else if (opcode == 0x01) {
    int16_t value;
    if (!read_bytes(&reader, (uint8_t *)&value, sizeof(value))) {
      return;
    }
    transaction->amount = (int64_t)value;
  } else if (opcode == 0x02) {
    int32_t value;
    if (!read_bytes(&reader, (uint8_t *)&value, sizeof(value))) {
      return;
    }
    transaction->amount = (int64_t)value;
  } else if (opcode == 0x03) {
    int64_t value;
    if (!read_bytes(&reader, (uint8_t *)&value, sizeof(value))) {
      return;
    }
    transaction->amount = value;
  } else {
    return;
  }
  if (transaction->amount < 0) {
    return;
  }
  // read destination address
  if (!read_bytes(&reader, &opcode, sizeof(opcode))) {
    return;
  }
  if (opcode != 0x0C) {
    return;
  }
  uint8_t dst_size;
  if (!read_bytes(&reader, &dst_size, sizeof(dst_size))) {
    return;
  }
  if (dst_size != UINT_160_SIZE) {
    return;
  }
  uint8_t dst_script_hash[UINT_160_SIZE];
  if (!read_bytes(&reader, dst_script_hash, UINT_160_SIZE)) {
    return;
  }
  neo_address_from_script_hash(dst_script_hash, transaction->dst_address);
  // read source address
  if (!read_bytes(&reader, &opcode, sizeof(opcode))) {
    return;
  }
  if (opcode != 0x0C) {
    return;
  }
  uint8_t src_size;
  if (!read_bytes(&reader, &src_size, sizeof(src_size))) {
    return;
  }
  if (src_size != UINT_160_SIZE) {
    return;
  }
  uint8_t src_script_hash[UINT_160_SIZE];
  if (!read_bytes(&reader, src_script_hash, UINT_160_SIZE)) {
    return;
  }
  neo_address_from_script_hash(src_script_hash, transaction->src_address);
  // clang-format off
    uint8_t expected_sequence[] = {
        0x14,  // OpCode.PUSH4
        0xC0,  // OpCode.PACK - we pack the 4 arguments to the transfer() method
        0x1F,  // OpCode.PUSH15 - CallFlags
        0x0C, 0x08,  // OpCode.PUSHDATA1, length 8 - contract method name
        0x74, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72,  // 'transfer'
        0x0C, 0x14,  // OpCode.PUSHDATA1, length 20 - contract script hash
    };
  // clang-format on
  uint8_t sequence[sizeof(expected_sequence)];
  if (!read_bytes(&reader, sequence, sizeof(sequence))) {
    return;
  }
  if (memcmp(sequence, expected_sequence, sizeof(expected_sequence))) return;
  uint8_t contract_script_hash[UINT_160_SIZE];
  if (!read_bytes(&reader, contract_script_hash, UINT_160_SIZE)) {
    return;
  }
  memcpy(transaction->contract_script_hash, contract_script_hash,
         UINT_160_SIZE);
  // clang-format off
  uint8_t expected_ending_sequence[] = {
        0x41,  // OpCode.SYSCALL
        0x62, 0x7d, 0x5b, 0x52  // id 'System.Contract.Call'
    };
  // clang-format on
  uint8_t ending_sequence[sizeof(expected_ending_sequence)];
  if (!read_bytes(&reader, ending_sequence, sizeof(ending_sequence))) {
    return;
  }
  if (memcmp(ending_sequence, expected_ending_sequence,
             sizeof(expected_ending_sequence)))
    return;
  if (reader.position != reader.length) return;
  transaction->is_asset_transfer = true;
}

static void parse_vote_script(Transaction *transaction) {
  uint8_t opcode;
  BufferReader reader = {0};
  init_buffer_reader(&reader, transaction->script, transaction->script_size);
  if (!read_bytes(&reader, &opcode, sizeof(opcode))) {
    return;
  }
  if (opcode != 0xB && opcode != 0x0C) {
    return;
  }
  if (opcode == 0xB) {
    transaction->is_remove_vote = true;
  } else {
    if (!read_bytes(&reader, &opcode, sizeof(opcode))) {
      return;
    }
    if (opcode != 0x21) {
      return;
    }
    uint8_t candidate_pub[COMPRESSED_PUBLIC_KEY_SIZE];
    if (!read_bytes(&reader, candidate_pub, sizeof(candidate_pub))) {
      return;
    }
    if (candidate_pub[0] != 0x02 && candidate_pub[0] != 0x03) return;
    neo_address_from_pubkey(candidate_pub, transaction->vote_to);
    transaction->is_remove_vote = false;
  }
  if (!read_bytes(&reader, &opcode, sizeof(opcode))) {
    return;
  }
  if (opcode != 0x0C) {
    return;
  }
  uint8_t src_size;
  if (!read_bytes(&reader, &src_size, sizeof(src_size))) {
    return;
  }
  if (src_size != UINT_160_SIZE) {
    return;
  }
  uint8_t src_script_hash[UINT_160_SIZE];
  if (!read_bytes(&reader, src_script_hash, UINT_160_SIZE)) {
    return;
  }
  neo_address_from_script_hash(src_script_hash, transaction->src_address);
  // clang-format off
  uint8_t expected_sequence[] = {
        0x12,  // OpCode.PUSH2
        0xC0,  // OpCode.PACK - we pack the 2 arguments to the vote() method
        0x1F,  // OpCode.PUSH15 - CallFlags
        0x0C, 0x04,  // OpCode.PUSHDATA1, length 4 - contract method name
        0x76, 0x6f, 0x74, 0x65,  // 'vote'
        0x0C, 0x14,  // OpCode.PUSHDATA1, length 20 - contract script hash
  };
  // clang-format on
  uint8_t sequence[sizeof(expected_sequence)];
  if (!read_bytes(&reader, sequence, sizeof(sequence))) {
    return;
  }
  if (memcmp(sequence, expected_sequence, sizeof(expected_sequence))) return;
  uint8_t contract_script_hash[UINT_160_SIZE];
  if (!read_bytes(&reader, contract_script_hash, UINT_160_SIZE)) {
    return;
  }
  const NeoToken *token =
      neo_token_by_contract_script_hash(contract_script_hash);
  if (strcmp(token->symbol, "NEO") != 0) return;
  // clang-format off
  uint8_t expected_ending_sequence[] = {
        0x41,  // OpCode.SYSCALL
        0x62, 0x7d, 0x5b, 0x52  // id 'System.Contract.Call'
    };
  // clang-format on
  uint8_t ending_sequence[sizeof(expected_ending_sequence)];
  if (!read_bytes(&reader, ending_sequence, sizeof(ending_sequence))) {
    return;
  }
  if (memcmp(ending_sequence, expected_ending_sequence,
             sizeof(expected_ending_sequence)))
    return;
  if (reader.position != reader.length) return;
  transaction->is_vote_script = true;
}

static ERROR_CODE transaction_deserialize(const uint8_t *data, size_t size,
                                          Transaction *transaction) {
  BufferReader reader = {0};
  init_buffer_reader(&reader, data, size);
  if (!read_bytes(&reader, &transaction->version,
                  sizeof(transaction->version))) {
    return INVALID_DATA;
  }
  if (transaction->version > 0) {
    return INVALID_TRANSACTION_VERSION;
  }
  if (!read_bytes(&reader, (uint8_t *)&transaction->nonce,
                  sizeof(transaction->nonce))) {
    return INVALID_DATA;
  }
  if (!read_bytes(&reader, (uint8_t *)&transaction->system_fee,
                  sizeof(transaction->system_fee))) {
    return INVALID_DATA;
  }
  if (transaction->system_fee < 0) {
    return INVALID_SYSTEM_FEE;
  }
  if (!read_bytes(&reader, (uint8_t *)&transaction->network_fee,
                  sizeof(transaction->network_fee))) {
    return INVALID_DATA;
  }
  if (transaction->network_fee < 0) {
    return INVALID_NETWORK_FEE;
  }
  if (!read_bytes(&reader, (uint8_t *)&transaction->valid_until_block,
                  sizeof(transaction->valid_until_block))) {
    return INVALID_DATA;
  }
  uint8_t signers_size = (uint8_t)deser_compact_size(&reader);
  if (signers_size < 1 || signers_size > MAX_TX_SIGNERS) {
    return INVALID_SIGNER_LENGTH;
  }
  transaction->signers_size = signers_size;
  for (int i = 0; i < signers_size; i++) {
    if (!read_bytes(&reader, transaction->signers[i].account, UINT_160_SIZE)) {
      return INVALID_SIGNER_ACCOUNT;
    }
    for (int j = 0; j < i; j++) {
      if (!memcmp(transaction->signers[j].account,
                  transaction->signers[i].account, UINT_160_SIZE)) {
        return DUPLICATE_SIGNER_ACCOUNT;
      }
    }
    uint8_t scope;
    if (!read_bytes(&reader, &scope, sizeof(scope))) {
      return INVALID_DATA;
    }
    transaction->signers[i].scope = (WitnessScope)scope;
    if ((((WitnessScope)scope & GLOBAL)) && ((WitnessScope)scope != GLOBAL)) {
      return INVALID_SCOPE_GLOBAL_FLAG_MUTEX;
    }
    if ((((WitnessScope)scope & CUSTOM_CONTRACTS))) {
      uint8_t alcs = (uint8_t)deser_compact_size(&reader);
      if (alcs <= 0 || alcs > MAX_SIGNER_ALLOWED_CONTRACTS) {
        return INVALID_SIGNER_ALLOWED_CONTRACTS_LENGTH;
      }
      transaction->signers[i].allowed_contracts_size = alcs;
      for (int j = 0; j < alcs; j++) {
        if (!read_bytes(&reader, transaction->signers[i].allowed_contracts[j],
                        UINT_160_SIZE)) {
          return INVALID_SIGNER_ALLOWED_CONTRACTS_ACCOUNT;
        }
      }
    }
    if ((((WitnessScope)scope & CUSTOM_GROUPS))) {
      uint8_t algs = (uint8_t)deser_compact_size(&reader);
      if (algs <= 0 || algs > MAX_SIGNER_ALLOWED_GROUPS) {
        return INVALID_SIGNER_ALLOWED_GROUPS_LENGTH;
      }
      transaction->signers[i].allowed_groups_size = algs;
      for (int j = 0; j < algs; j++) {
        if (!read_bytes(&reader, transaction->signers[i].allowed_groups[j],
                        COMPRESSED_PUBLIC_KEY_SIZE)) {
          return INVALID_DATA;
        }
      }
    }
    if (((WitnessScope)scope & WITNESS_RULES)) {
      return UNSUPPORTED_WITNESS_SCOPE_TYPE;
    }
    uint8_t attributes_size = (uint8_t)deser_compact_size(&reader);
    if (attributes_size > MAX_TX_ATTRIBUTES) {
      return INVALID_ATTRIBUTES_LENGTH;
    }
    transaction->attributes_size = attributes_size;
    for (int j = 0; j < attributes_size; j++) {
      uint8_t attribute_type;
      if (!read_bytes(&reader, &attribute_type, sizeof(attribute_type))) {
        return INVALID_DATA;
      }
      if (attribute_type != HIGH_PRIORITY) {
        return INVALID_ATTRIBUTES_TYPE;
      }
      for (int k = 0; k < j; k++) {
        if (transaction->attributes[k].type == attribute_type) {
          return INVALID_ATTRIBUTES_DUPLICATE;
        }
      }
      transaction->attributes[j].type = attribute_type;
    }
  }
  // parse script
  size_t script_size = (size_t)deser_compact_size(&reader);
  size_t remaining_size = reader.length - reader.position;
  if (script_size > MAX_TX_SCRIPT_SIZE || script_size == 0 ||
      script_size != remaining_size) {
    return INVALID_DATA_LENGTH;
  }
  if (!read_bytes(&reader, transaction->script, script_size)) {
    return INVALID_DATA_LENGTH;
  }
  transaction->script_size = (uint16_t)script_size;
  parse_transfer_script(transaction);
  if (!transaction->is_asset_transfer) {
    parse_vote_script(transaction);
  }
  return OK;
}

static void make_digest(uint32_t network_magic, const uint8_t *tx,
                        size_t tx_size, uint8_t *digest) {
  uint8_t payload[36];
  memcpy(payload, (uint8_t *)&network_magic, sizeof(network_magic));
  hasher_Raw(HASHER_SHA2, tx, tx_size, payload + 4);
  hasher_Raw(HASHER_SHA2, payload, sizeof(payload), digest);
}

static void neo_format_amount(int64_t amount, const char *symbol,
                              uint8_t decimals, char *buf, int buflen) {
  bn_format_uint64((uint64_t)amount, NULL, symbol, decimals, 0, false, ',', buf,
                   buflen);
}

inline static bool is_mainnet(uint32_t network_magic) {
  return network_magic == NETWORK_MAGIC_MAINNET;
}
inline static bool is_testnet(uint32_t network_magic) {
  return network_magic == NETWORK_MAGIC_TESTNET;
}
inline static bool is_unknown_network(uint32_t network_magic) {
  return !(is_mainnet(network_magic)) && !(is_testnet(network_magic));
}

static bool layout_token_transfer(const Transaction *transaction,
                                  uint32_t network_magic) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t max_index = 4;
  char amount_str[40] = {0};
  char fee_str[20] = {0};
  const NeoToken *token =
      neo_token_by_contract_script_hash(transaction->contract_script_hash);
  neo_format_amount(transaction->amount, token->symbol, token->decimals,
                    amount_str, sizeof(amount_str));
  neo_format_amount((transaction->network_fee + transaction->system_fee), "GAS",
                    8, fee_str, sizeof(fee_str));
  const char **tx_msg = format_tx_message("Neo");

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_ProtectCall;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);
  if (is_unknown_network(network_magic)) {
    max_index = 5;
  }
  if (is_unknown_token(token)) {
    char contract_str[43] = {'0', 'x'};
    uint8_t contract_script_hash[20];
    memcpy(contract_script_hash, transaction->contract_script_hash,
           sizeof(contract_script_hash));
    reverse_bytes(contract_script_hash, sizeof(contract_script_hash));
    data2hex(contract_script_hash, sizeof(contract_script_hash),
             contract_str + 2);
    layoutSwipe();
    layoutHeader(_(GLOBAL_UNKNOWN_TOKEN));
    oledDrawStringAdapter(0, 13, _(I__TOKEN_CONTRACT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 23, contract_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
    oledRefresh();
    if (protectWaitKeyValue(
            ButtonRequestType_ButtonRequest_UnknownDerivationPath, true, 0,
            1) != KEY_CONFIRM) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    }
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;
  uint8_t bubble_key = KEY_NULL;
  if (index == 0) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__AMOUNT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, amount_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__SEND_TO_COLON), FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, transaction->dst_address, FONT_STANDARD,
        &bmp_bottom_left_arrow, &bmp_bottom_right_arrow);
  } else if (index == 2) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__FROM_COLON), FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, transaction->src_address, FONT_STANDARD,
        &bmp_bottom_left_arrow, &bmp_bottom_right_arrow);
  } else if (index == 3) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__FEE_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, fee_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);

  } else if (max_index == index) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else if (index == 4) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(GLOBAL_TARGET_NETWORK), FONT_STANDARD);
    char network_magic_str[11] = {0};
    snprintf(network_magic_str, sizeof(network_magic_str), "%lu",
             network_magic);
    oledDrawStringAdapter(0, y + 10, network_magic_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}

static bool layout_vote(const Transaction *transaction,
                        uint32_t network_magic) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t max_index = 1;
  char network_name[20] = "Neo ";
  if (transaction->is_remove_vote) {
    strcat(network_name, _(TITLE_REMOVE_VOTE));
  } else {
    char *vote = _(I__VOTE_COLON);
    strncat(network_name, vote, strlen(vote) - 1);
    max_index++;
  }
  if (is_unknown_network(network_magic)) {
    max_index++;
  }
  const char **tx_msg = format_tx_message(network_name);

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_ProtectCall;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;
  uint8_t bubble_key = KEY_NULL;
  if (index == 0) {
    layoutHeader(tx_msg[0]);
    if (!transaction->is_remove_vote) {
      oledDrawStringAdapter(0, y, _(GLOBAL_CANDIDATE), FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, transaction->vote_to, FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y, _(I__VOTER_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, transaction->src_address, FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index == index) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, 13, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    if (!transaction->is_remove_vote) {
      oledDrawStringAdapter(0, y, _(I__VOTER_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, transaction->src_address, FONT_STANDARD);
    } else if (is_unknown_network(network_magic)) {
      oledDrawStringAdapter(0, y, _(GLOBAL_TARGET_NETWORK), FONT_STANDARD);
      char network_magic_str[11] = {0};
      snprintf(network_magic_str, sizeof(network_magic_str), "%lu",
               network_magic);
      oledDrawStringAdapter(0, y + 10, network_magic_str, FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 2) {
    layoutHeader(tx_msg[0]);
    if (is_unknown_network(network_magic)) {
      oledDrawStringAdapter(0, y, _(GLOBAL_TARGET_NETWORK), FONT_STANDARD);
      char network_magic_str[11] = {0};
      snprintf(network_magic_str, sizeof(network_magic_str), "%lu",
               network_magic);
      oledDrawStringAdapter(0, y + 10, network_magic_str, FONT_STANDARD);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    }
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}

bool neo_sign_tx(const NeoSignTx *msg, HDNode *node, NeoSignedTx *resp) {
  Transaction transaction = {0};
  ERROR_CODE code = transaction_deserialize(msg->raw_tx.bytes, msg->raw_tx.size,
                                            &transaction);
  if (code != OK) {
    char error_msg[32];
    snprintf(error_msg, sizeof(error_msg), "Invalid transaction: %d", code);
    fsm_sendFailure(FailureType_Failure_ProcessError, error_msg);
    return false;
  }
  if (transaction.is_asset_transfer) {
    if (!layout_token_transfer(&transaction, msg->network_magic)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      return false;
    }
  } else if (transaction.is_vote_script) {
    if (!layout_vote(&transaction, msg->network_magic)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      return false;
    }
  } else {
    char address[35] = {0};
    neo_address_from_pubkey(node->public_key, address);
    if (!layoutBlindSign("Neo", false, NULL, address, msg->raw_tx.bytes,
                         msg->raw_tx.size, NULL, NULL, NULL, NULL, NULL,
                         NULL)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      return false;
    }
  }

  uint8_t digest[32];
  make_digest(msg->network_magic, msg->raw_tx.bytes, msg->raw_tx.size, digest);
  if (hdnode_sign_digest(node, digest, resp->signature.bytes, NULL, NULL) !=
      0) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return false;
  }
  return true;
}
