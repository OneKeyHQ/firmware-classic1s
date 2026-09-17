#ifndef SIGNING_WORKSPACE_H
#define SIGNING_WORKSPACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "psbt/psbt.h"

#if !defined(BITCOIN_ONLY) || !BITCOIN_ONLY
#include "ethereum_typed_data_types.h"
#include "messages-aptos.pb.h"
#include "ton_cell.h"
#endif

/* All signing flows below are mutually exclusive while a request is active. */
#define SIGNING_WORKSPACE_BYTES (30U * 1024U)

typedef enum {
  SigningWorkspaceOwner_NONE = 0,
  SigningWorkspaceOwner_TYPED_DATA,
  SigningWorkspaceOwner_PSBT,
  SigningWorkspaceOwner_APTOS,
  /* Reserved owner for the subsequent Alephium RAM work. */
  SigningWorkspaceOwner_ALEPHIUM,
  SigningWorkspaceOwner_TON,
} SigningWorkspaceOwner;

typedef struct {
  PSBT psbt;
  BitcoinSigHasher sig_hasher;
  TxOutputType tx_output;
} PsbtSigningWorkspace;

typedef union {
  uint8_t reserved[SIGNING_WORKSPACE_BYTES];
  PsbtSigningWorkspace psbt;
#if !defined(BITCOIN_ONLY) || !BITCOIN_ONLY
  TypedDataEnvelope typed_data;
  uint8_t aptos_raw_tx[sizeof(AptosSignTx_raw_tx_t) + 32U];
  TonBocWorkspace ton_boc;
#endif
} SigningWorkspaceStorage;

/* Host unit tests may use wider pointer and size_t fields than the MCU. */
#if UINTPTR_MAX <= UINT32_MAX
_Static_assert(sizeof(PsbtSigningWorkspace) <= SIGNING_WORKSPACE_BYTES,
               "PSBT signing workspace exceeds the RAM budget");
#if !defined(BITCOIN_ONLY) || !BITCOIN_ONLY
_Static_assert(sizeof(TypedDataEnvelope) <= SIGNING_WORKSPACE_BYTES,
               "Typed data workspace exceeds the RAM budget");
#endif
#endif
#if !defined(BITCOIN_ONLY) || !BITCOIN_ONLY
_Static_assert(sizeof(AptosSignTx_raw_tx_t) + 32U <= SIGNING_WORKSPACE_BYTES,
               "Aptos signing workspace exceeds the RAM budget");
_Static_assert(sizeof(TonBocWorkspace) <= SIGNING_WORKSPACE_BYTES,
               "TON BOC workspace exceeds the RAM budget");
#endif

bool signing_workspace_acquire(SigningWorkspaceOwner owner);
void signing_workspace_release(SigningWorkspaceOwner owner);
SigningWorkspaceOwner signing_workspace_owner(void);

PSBT *signing_workspace_psbt(void);
BitcoinSigHasher *signing_workspace_psbt_hasher(void);
TxOutputType *signing_workspace_psbt_output(void);
#if !defined(BITCOIN_ONLY) || !BITCOIN_ONLY
TypedDataEnvelope *signing_workspace_typed_data(void);
uint8_t *signing_workspace_aptos_raw_tx(void);
TonBocWorkspace *signing_workspace_ton_boc(void);
#endif

#endif  // SIGNING_WORKSPACE_H
