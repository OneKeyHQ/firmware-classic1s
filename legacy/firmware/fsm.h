/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#ifndef __FSM_H__
#define __FSM_H__

#include "coins.h"
#include "messages-alephium.pb.h"
#include "messages-algorand.pb.h"
#include "messages-aptos.pb.h"
#include "messages-benfen.pb.h"
#include "messages-bitcoin.pb.h"
#include "messages-cardano.pb.h"
#include "messages-conflux.pb.h"
#include "messages-cosmos.pb.h"
#include "messages-crypto.pb.h"
#include "messages-debug.pb.h"
#include "messages-ethereum-onekey.pb.h"
#include "messages-ethereum.pb.h"
#include "messages-filecoin.pb.h"
#include "messages-kaspa.pb.h"
#include "messages-lnurl.pb.h"
#include "messages-management.pb.h"
#include "messages-near.pb.h"
#include "messages-nem.pb.h"
#include "messages-neo.pb.h"
#include "messages-nervos.pb.h"
#include "messages-nexa.pb.h"
#include "messages-nostr.pb.h"
#include "messages-polkadot.pb.h"
#include "messages-ripple.pb.h"
#include "messages-scdo.pb.h"
#include "messages-solana.pb.h"
#include "messages-starcoin.pb.h"
#include "messages-stellar.pb.h"
#include "messages-sui.pb.h"
#include "messages-ton.pb.h"
#include "messages-tron.pb.h"
#include "messages-webauthn.pb.h"

// CoinJoin fee rate multiplier.
#define FEE_RATE_DECIMALS (1000000)

// message functions

void fsm_sendSuccess(const char *text);

#if DEBUG_LINK
void fsm_sendFailureDebug(FailureType code, const char *text,
                          const char *source);

#define fsm_sendFailure(code, text) \
  fsm_sendFailureDebug((code), (text), __FILE__ ":" VERSTR(__LINE__) ":")
#else
void fsm_sendFailure(FailureType code, const char *text);
#endif

// void fsm_msgPinMatrixAck(const PinMatrixAck *msg);   // tiny
// void fsm_msgButtonAck(const ButtonAck *msg);         // tiny
// void fsm_msgPassphraseAck(const PassphraseAck *msg); // tiny

// common
void fsm_msgInitialize(const Initialize *msg);
void fsm_msgGetFeatures(const GetFeatures *msg);
void fsm_msgPing(const Ping *msg);
void fsm_msgChangePin(const ChangePin *msg);
void fsm_msgChangeWipeCode(const ChangeWipeCode *msg);
void fsm_msgWipeDevice(const WipeDevice *msg);
void fsm_msgGetEntropy(const GetEntropy *msg);
#if DEBUG_LINK
void fsm_msgLoadDevice(const LoadDevice *msg);
#endif
void fsm_msgResetDevice(const ResetDevice *msg);
void fsm_msgEntropyAck(const EntropyAck *msg);
void fsm_msgBackupDevice(const BackupDevice *msg);
void fsm_msgCancel(const Cancel *msg);
void fsm_msgLockDevice(const LockDevice *msg);
void fsm_msgEndSession(const EndSession *msg);
void fsm_msgApplySettings(const ApplySettings *msg);
void fsm_msgApplyFlags(const ApplyFlags *msg);
void fsm_msgRecoveryDevice(const RecoveryDevice *msg);
void fsm_msgWordAck(const WordAck *msg);
void fsm_msgSetU2FCounter(const SetU2FCounter *msg);
void fsm_msgGetNextU2FCounter(void);
void fsm_msgGetFirmwareHash(const GetFirmwareHash *msg);
void fsm_msgSetBusy(const SetBusy *msg);

// coin
void fsm_msgGetPublicKey(const GetPublicKey *msg);
void fsm_msgSignTx(const SignTx *msg);
void fsm_msgTxAck(
    TxAck *msg);  // not const because we mutate input/output scripts
void fsm_msgGetAddress(const GetAddress *msg);
void fsm_msgSignMessage(const SignMessage *msg);
void fsm_msgVerifyMessage(const VerifyMessage *msg);
void fsm_msgGetOwnershipId(const GetOwnershipId *msg);
void fsm_msgGetOwnershipProof(const GetOwnershipProof *msg);
void fsm_msgAuthorizeCoinJoin(const AuthorizeCoinJoin *msg);
void fsm_msgCancelAuthorization(const CancelAuthorization *msg);
void fsm_msgDoPreauthorized(const DoPreauthorized *msg);
void fsm_msgUnlockPath(const UnlockPath *msg);
void fsm_msgSignPsbt(const SignPsbt *msg);

// crypto
void fsm_msgCipherKeyValue(const CipherKeyValue *msg);
void fsm_msgSignIdentity(const SignIdentity *msg);
void fsm_msgGetECDHSessionKey(const GetECDHSessionKey *msg);
void fsm_msgCosiCommit(const CosiCommit *msg);
void fsm_msgCosiSign(const CosiSign *msg);
void fsm_msgBatchGetPublickeys(const BatchGetPublickeys *msg);
void fsm_clearCosiNonce(void);

// debug
#if DEBUG_LINK
// void fsm_msgDebugLinkDecision(const DebugLinkDecision *msg); // tiny
void fsm_msgDebugLinkGetState(const DebugLinkGetState *msg);
void fsm_msgDebugLinkStop(const DebugLinkStop *msg);
void fsm_msgDebugLinkMemoryWrite(const DebugLinkMemoryWrite *msg);
void fsm_msgDebugLinkMemoryRead(const DebugLinkMemoryRead *msg);
void fsm_msgDebugLinkFlashErase(const DebugLinkFlashErase *msg);
void fsm_msgDebugLinkReseedRandom(const DebugLinkReseedRandom *msg);
#endif

// ethereum
void fsm_msgEthereumGetAddress(const EthereumGetAddress *msg);
void fsm_msgEthereumGetPublicKey(const EthereumGetPublicKey *msg);
void fsm_msgEthereumSignTx(const EthereumSignTx *msg);
void fsm_msgEthereumSignTxEIP1559(const EthereumSignTxEIP1559 *msg);
void fsm_msgEthereumTxAck(const EthereumTxAck *msg);
void fsm_msgEthereumSignMessage(const EthereumSignMessage *msg);
void fsm_msgEthereumVerifyMessage(const EthereumVerifyMessage *msg);
void fsm_msgEthereumSignTypedHash(const EthereumSignTypedHash *msg);

// ethereum onekey
void fsm_msgEthereumGetAddressOneKey(const EthereumGetAddressOneKey *msg);
void fsm_msgEthereumGetPublicKeyOneKey(const EthereumGetPublicKeyOneKey *msg);
void fsm_msgEthereumSignTxOneKey(const EthereumSignTxOneKey *msg);
void fsm_msgEthereumSignTxEIP1559OneKey(const EthereumSignTxEIP1559OneKey *msg);
void fsm_msgEthereumTxAckOneKey(const EthereumTxAckOneKey *msg);
void fsm_msgEthereumSignMessageOneKey(const EthereumSignMessageOneKey *msg);
void fsm_msgEthereumVerifyMessageOneKey(const EthereumVerifyMessageOneKey *msg);
void fsm_msgEthereumSignTypedHashOneKey(const EthereumSignTypedHashOneKey *msg);

// nem
void fsm_msgNEMGetAddress(
    NEMGetAddress *msg);  // not const because we mutate msg->network
void fsm_msgNEMSignTx(
    NEMSignTx *msg);  // not const because we mutate msg->network
void fsm_msgNEMDecryptMessage(
    NEMDecryptMessage *msg);  // not const because we mutate msg->payload

// solana
void fsm_msgSolanaGetAddress(const SolanaGetAddress *msg);
void fsm_msgSolanaSignTx(const SolanaSignTx *msg);
void fsm_msgSolanaSignOffChainMessage(const SolanaSignOffChainMessage *msg);
void fsm_msgSolanaSignUnsafeMessage(const SolanaSignUnsafeMessage *msg);
// starcoin
void fsm_msgStarcoinGetAddress(const StarcoinGetAddress *msg);
void fsm_msgStarcoinGetPublicKey(const StarcoinGetPublicKey *msg);
void fsm_msgStarcoinSignTx(const StarcoinSignTx *msg);
void fsm_msgStarcoinSignMessage(const StarcoinSignMessage *msg);
void fsm_msgStarcoinVerifyMessage(const StarcoinVerifyMessage *msg);

// stellar
void fsm_msgStellarGetAddress(const StellarGetAddress *msg);
void fsm_msgStellarSignTx(const StellarSignTx *msg);
void fsm_msgStellarPaymentOp(const StellarPaymentOp *msg);
void fsm_msgStellarCreateAccountOp(const StellarCreateAccountOp *msg);
void fsm_msgStellarPathPaymentStrictReceiveOp(
    const StellarPathPaymentStrictReceiveOp *msg);
void fsm_msgStellarPathPaymentStrictSendOp(
    const StellarPathPaymentStrictSendOp *msg);
void fsm_msgStellarManageBuyOfferOp(const StellarManageBuyOfferOp *msg);
void fsm_msgStellarManageSellOfferOp(const StellarManageSellOfferOp *msg);
void fsm_msgStellarCreatePassiveSellOfferOp(
    const StellarCreatePassiveSellOfferOp *msg);
void fsm_msgStellarSetOptionsOp(const StellarSetOptionsOp *msg);
void fsm_msgStellarChangeTrustOp(const StellarChangeTrustOp *msg);
void fsm_msgStellarAllowTrustOp(const StellarAllowTrustOp *msg);
void fsm_msgStellarAccountMergeOp(const StellarAccountMergeOp *msg);
void fsm_msgStellarManageDataOp(const StellarManageDataOp *msg);
void fsm_msgStellarBumpSequenceOp(const StellarBumpSequenceOp *msg);

void fsm_msgRebootToBootloader(void);

bool fsm_layoutSignMessage(const char *chain_name, const char *signer,
                           const uint8_t *msg, uint32_t len);
bool fsm_layoutVerifyMessage(const char *chain_name, const char *signer,
                             const uint8_t *msg, uint32_t len);
bool fsm_layoutSignHash(const char *chain_name, const char *signer,
                        const char *domain_hash, const char *message_hash,
                        const char *warning);
bool fsm_layoutVerifyHash(const char *chain_name, const char *signer,
                          const char *domain_hash, const char *message_hash,
                          const char *warning);

void fsm_msgBixinReboot(const BixinReboot *msg);
void fsm_msgBixinMessageSE(const BixinMessageSE *msg);
void fsm_msgBixinVerifyDeviceRequest(const BixinVerifyDeviceRequest *msg);

void fsm_msgGetPublicKeyMultiple(const GetPublicKeyMultiple *msg);

bool fsm_layoutPathWarning(uint32_t address_n_count, const uint32_t *address_n);
bool fsm_checkCoinPath(const CoinInfo *coin, InputScriptType script_type,
                       uint32_t address_n_count, const uint32_t *address_n,
                       bool has_multisig, MessageType message_type,
                       bool show_warning);

bool fsm_getOwnershipId(uint8_t *script_pubkey, size_t script_pubkey_size,
                        uint8_t ownership_id[32]);

void fsm_abortWorkflows(void);
void fsm_postMsgCleanup(MessageType message_type);

// tron
void fsm_msgTronSignMessage(TronSignMessage *msg);
void fsm_msgTronGetAddress(TronGetAddress *msg);
void fsm_msgTronSignTx(TronSignTx *msg);

// aptos
void fsm_msgAptosGetAddress(const AptosGetAddress *msg);
void fsm_msgAptosSignTx(const AptosSignTx *msg);
void fsm_msgAptosSignMessage(const AptosSignMessage *msg);

// near
void fsm_msgNearGetAddress(NearGetAddress *msg);
void fsm_msgNearSignTx(const NearSignTx *msg);

// conflux
void fsm_msgConfluxGetAddress(const ConfluxGetAddress *msg);
void fsm_msgConfluxSignTx(ConfluxSignTx *msg);  // not const because we mutate
                                                // transaction during validation
void fsm_msgConfluxTxAck(const ConfluxTxAck *msg);
void fsm_msgConfluxSignMessage(const ConfluxSignMessage *msg);
void fsm_msgConfluxSignMessageCIP23(const ConfluxSignMessageCIP23 *msg);

// algorand
void fsm_msgAlgorandGetAddress(AlgorandGetAddress *msg);
void fsm_msgAlgorandSignTx(const AlgorandSignTx *msg);

// ripple
void fsm_msgRippleGetAddress(RippleGetAddress *msg);
void fsm_msgRippleSignTx(RippleSignTx *msg);

// sui
void fsm_msgSuiGetAddress(const SuiGetAddress *msg);
void fsm_msgSuiSignTx(const SuiSignTx *msg);
void fsm_msgSuiSignMessage(SuiSignMessage *msg);
void fsm_msgSuiTxAck(SuiTxAck *msg);

// filecoin
void fsm_msgFilecoinGetAddress(const FilecoinGetAddress *msg);
void fsm_msgFilecoinSignTx(const FilecoinSignTx *msg);

// cosmos
void fsm_msgCosmosGetAddress(CosmosGetAddress *msg);
void fsm_msgCosmosSignTx(const CosmosSignTx *msg);

// polkadot
void fsm_msgPolkadotGetAddress(PolkadotGetAddress *msg);
void fsm_msgPolkadotSignTx(const PolkadotSignTx *msg);

// cardano
void fsm_msgCardanoGetPublicKey(CardanoGetPublicKey *msg);
void fsm_msgCardanoGetAddress(CardanoGetAddress *msg);
void fsm_msgCardanoTxWitnessRequest(CardanoTxWitnessRequest *msg);
void fsm_msgCardanoTxHostAck(void);
void fsm_msgCardanoSignTxInit(CardanoSignTxInit *msg);
void fsm_msgCardanoTxInput(CardanoTxInput *msg);
void fsm_msgCardanoTxOutput(CardanoTxOutput *msg);
void fsm_msgCardanoAssetGroup(CardanoAssetGroup *msg);
void fsm_msgCardanoToken(CardanoToken *msg);
void fsm_msgCardanoTxCertificate(CardanoTxCertificate *msg);
void fsm_msgCardanoTxWithdrawal(CardanoTxWithdrawal *msg);
void fsm_msgCardanoTxAuxiliaryData(CardanoTxAuxiliaryData *msg);
void fsm_msgCardanoPoolOwner(CardanoPoolOwner *msg);
void fsm_msgCardanoPoolRelayParameters(CardanoPoolRelayParameters *msg);
void fsm_msgCardanoGetNativeScriptHash(void);
void fsm_msgCardanoTxMint(CardanoTxMint *msg);
void fsm_msgCardanoTxCollateralInput(CardanoTxCollateralInput *msg);
void fsm_msgCardanoTxRequiredSigner(CardanoTxRequiredSigner *msg);
void fsm_msgCardanoTxInlineDatumChunk(CardanoTxInlineDatumChunk *msg);
void fsm_msgCardanoTxReferenceScriptChunk(CardanoTxReferenceScriptChunk *msg);
void fsm_msgCardanoTxReferenceInput(CardanoTxReferenceInput *msg);
void fsm_msgCardanoSignMessage(CardanoSignMessage *msg);

// Kaspa
void fsm_msgKaspaGetAddress(const KaspaGetAddress *msg);
void fsm_msgKaspaSignTx(const KaspaSignTx *msg);
void fsm_msgKaspaTxInputAck(const KaspaTxInputAck *msg);

// Nexa
void fsm_msgNexaGetAddress(const NexaGetAddress *msg);
void fsm_msgNexaSignTx(const NexaSignTx *msg);
void fsm_msgNexaTxInputAck(const NexaTxInputAck *msg);

// nervos
void fsm_msgNervosGetAddress(const NervosGetAddress *msg);
void fsm_msgNervosSignTx(const NervosSignTx *msg);
void fsm_msgNervosTxAck(const NervosTxAck *msg);

// alephium
void fsm_msgAlephiumGetAddress(const AlephiumGetAddress *msg);
void fsm_msgAlephiumSignTx(const AlephiumSignTx *msg);
void fsm_msgAlephiumTxAck(const AlephiumTxAck *msg);
void fsm_msgAlephiumBytecodeAck(const AlephiumBytecodeAck *msg);
void fsm_msgAlephiumSignMessage(const AlephiumSignMessage *msg);

// Nostr
void fsm_msgNostrGetPublicKey(const NostrGetPublicKey *msg);
void fsm_msgNostrSignEvent(const NostrSignEvent *msg);
void fsm_msgNostrEncryptMessage(NostrEncryptMessage *msg);
void fsm_msgNostrDecryptMessage(NostrDecryptMessage *msg);
void fsm_msgNostrSignSchnorr(const NostrSignSchnorr *msg);

// scdo
void fsm_msgScdoGetAddress(const ScdoGetAddress *msg);
void fsm_msgScdoSignTx(ScdoSignTx *msg);
void fsm_msgScdoTxAck(const ScdoTxAck *msg);
void fsm_msgScdoSignMessage(const ScdoSignMessage *msg);

// lnurl
void fsm_msgLnurlAuth(const LnurlAuth *msg);

// ton
void fsm_msgTonGetAddress(const TonGetAddress *msg);
void fsm_msgTonSignMessage(const TonSignMessage *msg);
void fsm_msgTonSignProof(const TonSignProof *msg);

// webauthn
void fsm_msgWebAuthnListResidentCredentials(
    const WebAuthnListResidentCredentials *msg);
void fsm_msgWebAuthnAddResidentCredential(
    const WebAuthnAddResidentCredential *msg);
void fsm_msgWebAuthnRemoveResidentCredential(
    const WebAuthnRemoveResidentCredential *msg);

// benfen
void fsm_msgBenfenGetAddress(const BenfenGetAddress *msg);
void fsm_msgBenfenSignTx(const BenfenSignTx *msg);
void fsm_msgBenfenSignMessage(BenfenSignMessage *msg);
void fsm_msgBenfenTxAck(BenfenTxAck *msg);
// neo
void fsm_msgNeoGetAddress(const NeoGetAddress *msg);
void fsm_msgNeoSignTx(const NeoSignTx *msg);
#endif
