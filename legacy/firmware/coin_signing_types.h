#ifndef __COIN_SIGNING_TYPES_H__
#define __COIN_SIGNING_TYPES_H__

/*
 * Bitcoin signing state that is shared with the global signing-state pool.
 * Keep this definition in a header so the pool uses the real object layout,
 * rather than an aligned byte reservation.
 */

#include "transaction.h"

typedef enum _MatchState {
  MatchState_UNDEFINED = 0,
  MatchState_MATCH = 1,
  MatchState_MISMATCH = 2,
} MatchState;

typedef struct {
  uint32_t inputs_count;
  uint32_t outputs_count;
  uint32_t segwit_count;
  uint32_t next_legacy_input;
  uint32_t min_sequence;
  bool multisig_fp_set;
  bool multisig_fp_mismatch;
  uint8_t multisig_fp[32];
  uint32_t in_address_n[8];
  size_t in_address_n_count;
  InputScriptType in_script_type;
  MatchState in_script_type_state;
  uint32_t version;
  uint32_t lock_time;
  uint32_t expiry;
  uint32_t version_group_id;
  uint32_t timestamp;
#if !BITCOIN_ONLY
  uint32_t branch_id;
  uint8_t hash_header[32];
#endif
  Hasher hasher_check;
  Hasher hasher_prevouts;
  Hasher hasher_amounts;
  Hasher hasher_scriptpubkeys;
  Hasher hasher_sequences;
  Hasher hasher_outputs;
  uint8_t hash_inputs_check[32];
  uint8_t hash_prevouts[32];
  uint8_t hash_amounts[32];
  uint8_t hash_scriptpubkeys[32];
  uint8_t hash_sequences[32];
  uint8_t hash_outputs[32];
  uint8_t hash_prevouts143[32];
  uint8_t hash_outputs143[32];
  uint8_t hash_sequence143[32];
} TxInfo;

#endif /* __COIN_SIGNING_TYPES_H__ */
