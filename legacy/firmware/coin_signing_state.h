#ifndef __COIN_SIGNING_STATE_H__
#define __COIN_SIGNING_STATE_H__

#include <stdbool.h>
#include <stdint.h>

#include "ada.h"
#include "coin_signing_types.h"
#include "fido2/ctap.h"
#include "messages-ethereum-onekey.pb.h"
#include "messages-ethereum.pb.h"
#include "sha3.h"

typedef struct {
  TxInputType input;
  TxOutputType output;
  TxRequest resp;
  TxInfo info;
  TxInfo orig_info;
  TxOutputBinType bin_output;
  TxStruct to;
  TxStruct tp;
  TxStruct ti;
  Hasher global_hasher_check;
  Hasher coinjoin_request_hasher;
} coin_signing_bitcoin_state_t;

typedef struct {
  EthereumAccessList signing_access_list[16];
  struct SHA3_CTX keccak_ctx;
} coin_signing_ethereum_state_t;

typedef struct {
  EthereumTxRequestOneKey msg_tx_request;
  EthereumAccessListOneKey signing_access_list[16];
  EthereumAuthorizationOneKey signing_authorization_list[16];
  struct SHA3_CTX keccak_ctx;
} coin_signing_ethereum_onekey_state_t;

typedef struct {
  struct AdaSigner signer;
} coin_signing_cardano_state_t;

typedef struct {
  struct SHA3_CTX keccak_ctx;
} coin_signing_sha3_state_t;

typedef struct {
  uint8_t witness[1024];
} coin_signing_nervos_state_t;

typedef struct {
  struct _getAssertionState assertion;
} coin_signing_fido_state_t;

typedef union {
  coin_signing_bitcoin_state_t bitcoin;
  coin_signing_fido_state_t fido;
#if !BITCOIN_ONLY
  coin_signing_ethereum_state_t ethereum;
  coin_signing_ethereum_onekey_state_t ethereum_onekey;
  coin_signing_cardano_state_t cardano;
  coin_signing_sha3_state_t scdo;
  coin_signing_sha3_state_t conflux;
  coin_signing_nervos_state_t nervos;
#endif
} coin_signing_state_t;

extern coin_signing_state_t coin_signing_state;

_Static_assert(_Alignof(coin_signing_state_t) >= _Alignof(TxInfo),
               "signing pool must preserve TxInfo alignment");
_Static_assert(sizeof(coin_signing_state_t) >=
                   sizeof(struct _getAssertionState),
               "signing pool must fit FIDO assertion state");
_Static_assert(sizeof(coin_signing_bitcoin_state_t) >=
                   sizeof(struct _getAssertionState),
               "FIDO assertion state must not grow the signing pool");
_Static_assert(_Alignof(coin_signing_state_t) >=
                   _Alignof(struct _getAssertionState),
               "signing pool must preserve FIDO assertion alignment");
_Static_assert(sizeof(coin_signing_nervos_state_t) == 1024,
               "Nervos witness pool size changed");

#endif /* __COIN_SIGNING_STATE_H__ */
