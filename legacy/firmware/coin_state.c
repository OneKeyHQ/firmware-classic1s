#include "coin_state.h"

#include "coin_signing_state.h"
#include "coin_parser_state.h"
#include "memzero.h"
#include "messages.pb.h"

typedef enum {
  COIN_STATE_MESSAGE_OTHER = 0,
  COIN_STATE_MESSAGE_START,
  COIN_STATE_MESSAGE_CONTINUE,
} coin_state_message_kind_t;

typedef struct {
  coin_state_owner_t owner;
  coin_state_message_kind_t kind;
} coin_state_message_t;

/* Metadata intentionally lives outside the reusable storage union. */
static coin_state_owner_t current_owner;
static bool retained;
static bool active_frame;
static bool cancelled;

static coin_state_message_t coin_state_classify(uint16_t message_type) {
  switch (message_type) {
    case MessageType_MessageType_SignTx:
      return (coin_state_message_t){COIN_STATE_OWNER_BITCOIN,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_TxAck:
      return (coin_state_message_t){COIN_STATE_OWNER_BITCOIN,
                                    COIN_STATE_MESSAGE_CONTINUE};
#if !BITCOIN_ONLY
    case MessageType_MessageType_EthereumSignTx:
    case MessageType_MessageType_EthereumSignTxEIP1559:
      return (coin_state_message_t){COIN_STATE_OWNER_ETHEREUM,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_EthereumTxAck:
      return (coin_state_message_t){COIN_STATE_OWNER_ETHEREUM,
                                    COIN_STATE_MESSAGE_CONTINUE};
    case MessageType_MessageType_EthereumSignTxOneKey:
    case MessageType_MessageType_EthereumSignTxEIP1559OneKey:
    case MessageType_MessageType_EthereumSignTxEIP7702OneKey:
      return (coin_state_message_t){COIN_STATE_OWNER_ETHEREUM_ONEKEY,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_EthereumTxAckOneKey:
      return (coin_state_message_t){COIN_STATE_OWNER_ETHEREUM_ONEKEY,
                                    COIN_STATE_MESSAGE_CONTINUE};
    case MessageType_MessageType_CardanoSignTxInit:
      return (coin_state_message_t){COIN_STATE_OWNER_CARDANO,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_CardanoTxWitnessRequest:
    case MessageType_MessageType_CardanoTxHostAck:
    case MessageType_MessageType_CardanoTxInput:
    case MessageType_MessageType_CardanoTxOutput:
    case MessageType_MessageType_CardanoAssetGroup:
    case MessageType_MessageType_CardanoToken:
    case MessageType_MessageType_CardanoTxCertificate:
    case MessageType_MessageType_CardanoTxWithdrawal:
    case MessageType_MessageType_CardanoTxAuxiliaryData:
    case MessageType_MessageType_CardanoPoolOwner:
    case MessageType_MessageType_CardanoPoolRelayParameters:
    case MessageType_MessageType_CardanoTxMint:
    case MessageType_MessageType_CardanoTxCollateralInput:
    case MessageType_MessageType_CardanoTxRequiredSigner:
    case MessageType_MessageType_CardanoTxInlineDatumChunk:
    case MessageType_MessageType_CardanoTxReferenceScriptChunk:
    case MessageType_MessageType_CardanoTxReferenceInput:
      return (coin_state_message_t){COIN_STATE_OWNER_CARDANO,
                                    COIN_STATE_MESSAGE_CONTINUE};
    case MessageType_MessageType_ScdoSignTx:
      return (coin_state_message_t){COIN_STATE_OWNER_SCDO,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_ScdoTxAck:
      return (coin_state_message_t){COIN_STATE_OWNER_SCDO,
                                    COIN_STATE_MESSAGE_CONTINUE};
    case MessageType_MessageType_ConfluxSignTx:
      return (coin_state_message_t){COIN_STATE_OWNER_CONFLUX,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_ConfluxTxAck:
      return (coin_state_message_t){COIN_STATE_OWNER_CONFLUX,
                                    COIN_STATE_MESSAGE_CONTINUE};
    case MessageType_MessageType_NervosSignTx:
      return (coin_state_message_t){COIN_STATE_OWNER_NERVOS,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_NervosTxAck:
      return (coin_state_message_t){COIN_STATE_OWNER_NERVOS,
                                    COIN_STATE_MESSAGE_CONTINUE};
    case MessageType_MessageType_CosmosSignTx:
      return (coin_state_message_t){COIN_STATE_OWNER_COSMOS_PARSER,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_AlgorandSignTx:
      return (coin_state_message_t){COIN_STATE_OWNER_ALGORAND_PARSER,
                                    COIN_STATE_MESSAGE_START};
    case MessageType_MessageType_FilecoinSignTx:
      return (coin_state_message_t){COIN_STATE_OWNER_FILECOIN_PARSER,
                                    COIN_STATE_MESSAGE_START};
#endif
    default:
      return (coin_state_message_t){COIN_STATE_OWNER_NONE,
                                    COIN_STATE_MESSAGE_OTHER};
  }
}

static void coin_state_wipe(void) {
  memzero(&coin_signing_state, sizeof(coin_signing_state));
  coin_parser_state_clear();
}

bool coin_state_message_is_managed(uint16_t message_type) {
  return coin_state_classify(message_type).kind != COIN_STATE_MESSAGE_OTHER;
}

bool coin_state_can_dispatch(uint16_t message_type) {
  coin_state_message_t message = coin_state_classify(message_type);
  if (message.kind == COIN_STATE_MESSAGE_OTHER) return true;
  if (message.kind == COIN_STATE_MESSAGE_START) {
    return current_owner == COIN_STATE_OWNER_NONE && !active_frame;
  }
  return current_owner == message.owner && retained && !active_frame &&
         !cancelled;
}

bool coin_state_dispatch_enter(uint16_t message_type) {
  coin_state_message_t message = coin_state_classify(message_type);
  if (!coin_state_can_dispatch(message_type)) return false;
  if (message.kind == COIN_STATE_MESSAGE_OTHER) return true;

  if (message.kind == COIN_STATE_MESSAGE_START) {
    coin_state_wipe();
    current_owner = message.owner;
    retained = false;
    cancelled = false;
  }

  active_frame = true;
  return true;
}

void coin_state_dispatch_leave(void) {
  if (!active_frame) return;
  active_frame = false;
  if (cancelled || !retained) {
    coin_state_wipe();
    current_owner = COIN_STATE_OWNER_NONE;
    retained = false;
    cancelled = false;
  }
}

void coin_state_retain(coin_state_owner_t owner) {
  if (current_owner == owner && active_frame && !cancelled) retained = true;
}

void coin_state_abort(coin_state_owner_t owner) {
  if (current_owner != owner) return;
  retained = false;
  if (active_frame) {
    cancelled = true;
    return;
  }
  coin_state_wipe();
  current_owner = COIN_STATE_OWNER_NONE;
  cancelled = false;
}

void coin_state_clear_all(void) {
  if (active_frame) {
    cancelled = true;
    retained = false;
    return;
  }
  coin_state_wipe();
  current_owner = COIN_STATE_OWNER_NONE;
  retained = false;
  cancelled = false;
}

bool coin_state_is_owner(coin_state_owner_t owner) {
  return current_owner == owner && retained && !cancelled;
}

bool coin_state_fido_can_begin(void) {
  return current_owner == COIN_STATE_OWNER_NONE && !active_frame;
}

bool coin_state_fido_begin(void) {
  if (!coin_state_fido_can_begin()) return false;
  coin_state_wipe();
  current_owner = COIN_STATE_OWNER_FIDO;
  retained = false;
  active_frame = true;
  cancelled = false;
  return true;
}

void coin_state_fido_end(void) {
  if (current_owner != COIN_STATE_OWNER_FIDO || !active_frame) return;
  coin_state_abort(COIN_STATE_OWNER_FIDO);
  coin_state_dispatch_leave();
}

bool coin_state_fido_is_active(void) {
  return current_owner == COIN_STATE_OWNER_FIDO && active_frame && !cancelled;
}
