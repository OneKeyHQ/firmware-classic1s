#ifndef __COIN_STATE_H__
#define __COIN_STATE_H__

#include <stdbool.h>
#include <stdint.h>

typedef enum {
  COIN_STATE_OWNER_NONE = 0,
  COIN_STATE_OWNER_BITCOIN,
  COIN_STATE_OWNER_ETHEREUM,
  COIN_STATE_OWNER_ETHEREUM_ONEKEY,
  COIN_STATE_OWNER_CARDANO,
  COIN_STATE_OWNER_SCDO,
  COIN_STATE_OWNER_CONFLUX,
  COIN_STATE_OWNER_NERVOS,
  COIN_STATE_OWNER_COSMOS_PARSER,
  COIN_STATE_OWNER_ALGORAND_PARSER,
  COIN_STATE_OWNER_FILECOIN_PARSER,
  COIN_STATE_OWNER_FIDO,
} coin_state_owner_t;

/* Pre-decode check and frame entry for automatically dispatched messages. */
bool coin_state_can_dispatch(uint16_t message_type);
bool coin_state_message_is_managed(uint16_t message_type);
bool coin_state_dispatch_enter(uint16_t message_type);
void coin_state_dispatch_leave(void);

/* A successful streaming flow retains its provisional acquisition. */
void coin_state_retain(coin_state_owner_t owner);
void coin_state_abort(coin_state_owner_t owner);
void coin_state_clear_all(void);
bool coin_state_is_owner(coin_state_owner_t owner);

/* FIDO GetAssertion has a single request frame, rather than protobuf flow. */
bool coin_state_fido_can_begin(void);
bool coin_state_fido_begin(void);
void coin_state_fido_end(void);
bool coin_state_fido_is_active(void);

#endif /* __COIN_STATE_H__ */
