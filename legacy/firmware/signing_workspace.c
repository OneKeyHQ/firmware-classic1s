#include "signing_workspace.h"

#include "memzero.h"

static SigningWorkspaceStorage signing_workspace;
static SigningWorkspaceOwner signing_workspace_active_owner;

bool signing_workspace_acquire(SigningWorkspaceOwner owner) {
  if (owner == SigningWorkspaceOwner_NONE ||
      signing_workspace_active_owner != SigningWorkspaceOwner_NONE) {
    return false;
  }

  memzero(&signing_workspace, sizeof(signing_workspace));
  signing_workspace_active_owner = owner;
  return true;
}

void signing_workspace_release(SigningWorkspaceOwner owner) {
  if (owner != SigningWorkspaceOwner_NONE &&
      signing_workspace_active_owner == owner) {
    memzero(&signing_workspace, sizeof(signing_workspace));
    signing_workspace_active_owner = SigningWorkspaceOwner_NONE;
  }
}

SigningWorkspaceOwner signing_workspace_owner(void) {
  return signing_workspace_active_owner;
}

PSBT *signing_workspace_psbt(void) {
  if (signing_workspace_active_owner != SigningWorkspaceOwner_PSBT) {
    return NULL;
  }
  return &signing_workspace.psbt.psbt;
}

BitcoinSigHasher *signing_workspace_psbt_hasher(void) {
  if (signing_workspace_active_owner != SigningWorkspaceOwner_PSBT) {
    return NULL;
  }
  return &signing_workspace.psbt.sig_hasher;
}

TxOutputType *signing_workspace_psbt_output(void) {
  if (signing_workspace_active_owner != SigningWorkspaceOwner_PSBT) {
    return NULL;
  }
  return &signing_workspace.psbt.tx_output;
}

#if !defined(BITCOIN_ONLY) || !BITCOIN_ONLY
TypedDataEnvelope *signing_workspace_typed_data(void) {
  if (signing_workspace_active_owner != SigningWorkspaceOwner_TYPED_DATA) {
    return NULL;
  }
  return &signing_workspace.typed_data;
}

uint8_t *signing_workspace_aptos_raw_tx(void) {
  if (signing_workspace_active_owner != SigningWorkspaceOwner_APTOS) {
    return NULL;
  }
  return signing_workspace.aptos_raw_tx;
}

TonBocWorkspace *signing_workspace_ton_boc(void) {
  if (signing_workspace_active_owner != SigningWorkspaceOwner_TON) {
    return NULL;
  }
  return &signing_workspace.ton_boc;
}
#endif
