/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2021 OneKey Team <core@onekey.so>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ADA_H__
#define __ADA_H__

#include <stdbool.h>
#include "bip32.h"
#include "messages-cardano.pb.h"

#define MAINNET_PROTOCOL_MAGIC 764824073
#define LOVELACE_MAX_SUPPLY 45000000000000000
#define INPUT_PREV_HASH_SIZE 32
#define ADDRESS_KEY_HASH_SIZE 28
#define SCRIPT_HASH_SIZE 28
#define OUTPUT_DATUM_HASH_SIZE 32
#define SCRIPT_DATA_HASH_SIZE 32
#define NETWORK_ID_MAINNET 1
#define NETWORK_ID_TESTNET 0
#define MAX_CHUNK_SIZE 1024

#define HRP_SEPARATOR "1"
// CIP-0005 prefixes -
// https://github.com/cardano-foundation/CIPs/blob/master/CIP-0005/CIP-0005.md
#define HRP_ADDRESS "addr"
#define HRP_TESTNET_ADDRESS "addr_test"
#define HRP_REWARD_ADDRESS "stake"
#define HRP_TESTNET_REWARD_ADDRESS "stake_test"
#define HRP_GOVERNANCE_PUBLIC_KEY "gov_vk"
#define HRP_SCRIPT_HASH "script"
#define HRP_KEY_HASH "addr_vkh"
#define HRP_SHARED_KEY_HASH "addr_shared_vkh"
#define HRP_STAKE_KEY_HASH "stake_vkh"
#define HRP_REQUIRED_SIGNER_KEY_HASH "req_signer_vkh"
#define HRP_OUTPUT_DATUM_HASH "datum"
#define HRP_SCRIPT_DATA_HASH "script_data"

enum {
  TX_BODY_KEY_INPUTS = 0,
  TX_BODY_KEY_OUTPUTS = 1,
  TX_BODY_KEY_FEE = 2,
  TX_BODY_KEY_TTL = 3,
  TX_BODY_KEY_CERTIFICATES = 4,
  TX_BODY_KEY_WITHDRAWALS = 5,
  // TX_BODY_KEY_UPDATE = 6, // not used
  TX_BODY_KEY_AUX_DATA = 7,
  TX_BODY_KEY_VALIDITY_INTERVAL_START = 8,
  TX_BODY_KEY_MINT = 9,
  TX_BODY_KEY_SCRIPT_HASH_DATA = 11,
  TX_BODY_KEY_COLLATERAL_INPUTS = 13,
  TX_BODY_KEY_REQUIRED_SIGNERS = 14,
  TX_BODY_KEY_NETWORK_ID = 15,
  TX_BODY_KEY_COLLATERAL_OUTPUT = 16,
  TX_BODY_KEY_TOTAL_COLLATERAL = 17,
  TX_BODY_KEY_REFERENCE_INPUTS = 18,
};
enum {
  BABBAGE_OUTPUT_KEY_ADDRESS,
  BABBAGE_OUTPUT_KEY_AMOUNT,
  BABBAGE_OUTPUT_KEY_DATUM_OPTION,
  BABBAGE_OUTPUT_KEY_REFERENCE_SCRIPT,
};
enum {
  BABBAGE_OUTPUT_KEY_DATUM_HASH = 0,
  BABBAGE_OUTPUT_KEY_INLINE_DATUM = 1,
};

/* The state machine of the tx hash builder is driven by user calls.
 * E.g., when the user calls txHashBuilder_addInput(), the input is only
 * added and the state is not advanced to outputs even if all inputs have been
 * added
 * --- only after calling txHashBuilder_enterOutputs()
 * is the state advanced to TX_HASH_BUILDER_IN_OUTPUTS.
 */
typedef enum {
  TX_HASH_BUILDER_INIT = 100,
  TX_HASH_BUILDER_IN_INPUTS = 200,
  TX_HASH_BUILDER_IN_OUTPUTS = 300,
  TX_HASH_BUILDER_IN_FEE = 400,
  TX_HASH_BUILDER_IN_TTL = 500,
  TX_HASH_BUILDER_IN_CERTIFICATES = 600,
  TX_HASH_BUILDER_IN_WITHDRAWALS = 700,
  TX_HASH_BUILDER_IN_AUX_DATA = 800,
  TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START = 900,
  TX_HASH_BUILDER_IN_MINT = 1000,
  TX_HASH_BUILDER_IN_SCRIPT_DATA_HASH = 1100,
  TX_HASH_BUILDER_IN_COLLATERAL_INPUTS = 1200,
  TX_HASH_BUILDER_IN_REQUIRED_SIGNERS = 1300,
  TX_HASH_BUILDER_IN_NETWORK_ID = 1400,
  TX_HASH_BUILDER_IN_COLLATERAL_RETURN = 1500,
  TX_HASH_BUILDER_IN_TOTAL_COLLATERAL = 1600,
  TX_HASH_BUILDER_IN_REFERENCE_INPUTS = 1700,
  TX_HASH_BUILDER_FINISHED = 1800,
  TX_SIGN_FINISHED = 6000,
} tx_hash_builder_state_t;

typedef enum {
  STATE_OUTPUT_TOP_LEVEL_DATA,
  STATE_OUTPUT_ASSET_GROUP,
  STATE_OUTPUT_TOKEN,
  STATE_OUTPUT_DATUM,
  STATE_OUTPUT_DATUM_INLINE_CHUNKS,
  STATE_OUTPUT_REFERENCE_SCRIPT,
  STATE_OUTPUT_REFERENCE_SCRIPT_CHUNKS,
  STATE_OUTPUT_CONFIRM,
  STATE_OUTPUT_FINISHED,
} tx_hash_builder_output_state_t;

typedef enum {
  STATE_MINT_TOP_LEVEL_DATA = 9,
  STATE_MINT_ASSET_GROUP = 10,
  STATE_MINT_TOKEN = 11,
  STATE_MINT_FINISHED = 12,
} tx_hash_builder_mint_state_t;

struct AdaSigner {
  const CardanoSignTxInit *signertx;
  BLAKE2B_CTX ctx;
  uint8_t digest[32];
  int tx_dict_items_count;
  uint16_t remainingInputs;
  uint16_t remainingOutputs;
  uint16_t remainingWithdrawals;
  uint16_t remainingCertificates;
  uint16_t remainingCollateralInputs;
  uint16_t remainingRequiredSigners;
  uint16_t remainingReferenceInputs;
  uint16_t remainingMintingAssetGroupsCount;
  uint16_t remainingMintingAssetTokensCount;
  uint16_t remainingOutputAssetTokensCount;
  uint16_t remainingOutputAssetGroupsCount;
  uint16_t remainingWitnessRequestsCount;
  uint16_t remainingInlineDatumChunksCount;
  uint16_t remainingReferenceScriptChunksCount;
  tx_hash_builder_output_state_t outputState;
  tx_hash_builder_mint_state_t mintState;
  tx_hash_builder_state_t state;

  bool is_feeed;
  bool is_finished;
  bool is_change;
  uint8_t policy_id[28];
  uint16_t policy_id_size;
  uint8_t datum_hash[32];
  uint16_t datum_hash_size;
  uint32_t inline_datum_size;
  uint32_t reference_script_size;
};
#if EMULATOR
bool fsm_getCardanoIcaruNode(HDNode *node, const uint32_t *address_n,
                             size_t address_n_count, uint32_t *fingerprint);
#endif
bool deriveCardanoIcaruNode(HDNode *node, const uint32_t *address_n,
                            size_t address_n_count, uint32_t *fingerprint);

bool ada_get_address(const CardanoGetAddress *msg, char *address);
bool validate_network_info(int network_id, int protocol_magic);

bool _processs_tx_init(const CardanoSignTxInit *msg);
void state_transmute(void);

bool txHashBuilder_addInput(const CardanoTxInput *input);
bool txHashBuilder_addOutput(const CardanoTxOutput *output);
bool txHashBuilder_addAssetGroup(const CardanoAssetGroup *msg);
bool txHashBuilder_addToken(const CardanoToken *msg);
bool txHashBuilder_addCertificate(const CardanoTxCertificate *cert);
bool txHashBuilder_addWithdrawal(const CardanoTxWithdrawal *wdr);
bool txHashBuilder_addAuxiliaryData(const CardanoTxAuxiliaryData *wdr);
bool txHashBuilder_addMintingAssetGroups(const CardanoTxAuxiliaryData *wdr);
bool txHashBuilder_addMint(const CardanoTxMint *mint);
bool txHashBuilder_addRequiredSigner(const CardanoTxRequiredSigner *req);
bool txHashBuilder_addInlineDatumChunk(const CardanoTxInlineDatumChunk *chunk);
bool txHashBuilder_addReferenceScriptChunk(
    const CardanoTxReferenceScriptChunk *chunk);
bool cardano_txack(void);
bool cardano_txwitness(const CardanoTxWitnessRequest *msg,
                       CardanoTxWitnessResponse *resp);
bool ada_sign_messages(const CardanoSignMessage *msg,
                       CardanoMessageSignature *resp);

#endif  // __ADA_H__
