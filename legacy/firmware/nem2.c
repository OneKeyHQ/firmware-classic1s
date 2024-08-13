/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
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

#include "nem2.h"

#include "aes/aes.h"
#include "crypto.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "protect.h"
#include "rng.h"
#include "secp256k1.h"

const char *nem_validate_common(NEMTransactionCommon *common, bool inner) {
  if (!common->has_network) {
    common->has_network = true;
    common->network = NEM_NETWORK_MAINNET;
  }

  if (common->network > 0xFF || nem_network_name(common->network) == NULL) {
    return inner ? "Invalid NEM network in inner transaction"
                 : "Invalid NEM network";
  }

  if (inner != common->has_signer) {
    return inner ? "No signer provided in inner transaction"
                 : "Signer not allowed in outer transaction";
  }

  if (common->has_signer && common->signer.size != sizeof(ed25519_public_key)) {
    return "Invalid signer public key in inner transaction";
  }

  return NULL;
}

const char *nem_validate_transfer(const NEMTransfer *transfer,
                                  uint8_t network) {
  if (transfer->has_public_key &&
      transfer->public_key.size != sizeof(ed25519_public_key)) {
    return "Invalid recipient public key";
  }

  if (!nem_validate_address(transfer->recipient, network))
    return "Invalid recipient address";

  return NULL;
}

const char *nem_validate_provision_namespace(
    const NEMProvisionNamespace *provision_namespace, uint8_t network) {
  if (!nem_validate_address(provision_namespace->sink, network))
    return "Invalid rental sink address";

  return NULL;
}

const char *nem_validate_mosaic_creation(
    const NEMMosaicCreation *mosaic_creation, uint8_t network) {
  if (!nem_validate_address(mosaic_creation->sink, network))
    return "Invalid creation sink address";

  if (mosaic_creation->definition.has_name)
    return "Name not allowed in mosaic creation transactions";
  if (mosaic_creation->definition.has_ticker)
    return "Ticker not allowed in mosaic creation transactions";
  if (mosaic_creation->definition.networks_count)
    return "Networks not allowed in mosaic creation transactions";

  if (mosaic_creation->definition.has_levy) {
    if (!mosaic_creation->definition.has_fee) return "No levy address provided";
    if (!mosaic_creation->definition.has_levy_address)
      return "No levy address provided";
    if (!mosaic_creation->definition.has_levy_namespace)
      return "No levy namespace provided";
    if (!mosaic_creation->definition.has_levy_mosaic)
      return "No levy mosaic name provided";

    if (!mosaic_creation->definition.has_divisibility)
      return "No divisibility provided";
    if (!mosaic_creation->definition.has_supply) return "No supply provided";
    if (!mosaic_creation->definition.has_mutable_supply)
      return "No supply mutability provided";
    if (!mosaic_creation->definition.has_transferable)
      return "No mosaic transferability provided";

    if (mosaic_creation->definition.divisibility > NEM_MAX_DIVISIBILITY)
      return "Invalid divisibility provided";
    if (mosaic_creation->definition.supply > NEM_MAX_SUPPLY)
      return "Invalid supply provided";

    if (!nem_validate_address(mosaic_creation->definition.levy_address,
                              network))
      return "Invalid levy address";
  }

  return NULL;
}

const char *nem_validate_supply_change(
    const NEMMosaicSupplyChange *supply_change) {
  (void)supply_change;
  return NULL;
}

const char *nem_validate_aggregate_modification(
    const NEMAggregateModification *aggregate_modification, bool creation) {
  if (creation && aggregate_modification->modifications_count == 0) {
    return "No modifications provided";
  }

  for (size_t i = 0; i < aggregate_modification->modifications_count; i++) {
    const NEMCosignatoryModification *modification =
        &aggregate_modification->modifications[i];

    if (modification->public_key.size != 32)
      return "Invalid cosignatory public key provided";

    if (creation && modification->type ==
                        NEMModificationType_CosignatoryModification_Delete) {
      return "Cannot remove cosignatory when converting account";
    }
  }

  return NULL;
}

const char *nem_validate_importance_transfer(
    const NEMImportanceTransfer *importance_transfer) {
  if (importance_transfer->public_key.size != 32)
    return "Invalid remote account provided";

  return NULL;
}

bool nem_askTransfer(const NEMTransactionCommon *common,
                     const NEMTransfer *transfer, const char *desc) {
  if (transfer->mosaics_count) {
    const NEMMosaic *xem = NULL;
    bool unknownMosaic = false;

    const NEMMosaicDefinition *definitions[transfer->mosaics_count];
    memset(definitions, 0, sizeof(definitions));

    for (size_t i = 0; i < transfer->mosaics_count; i++) {
      const NEMMosaic *mosaic = &transfer->mosaics[i];

      definitions[i] =
          nem_mosaicByName(mosaic->namespace, mosaic->mosaic, common->network);

      if (definitions[i] == NEM_MOSAIC_DEFINITION_XEM) {
        xem = mosaic;
      } else if (definitions[i] == NULL) {
        unknownMosaic = true;
      }
    }

    bignum256 multiplier = {0};
    bn_read_uint64(transfer->amount, &multiplier);

    if (unknownMosaic) {
      layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("I take the risk"),
                        __("Unknown Mosaics"), __("Divisibility and levy"),
                        __("cannot be shown for"), __("unknown mosaics!"), NULL,
                        NULL, NULL);
      if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         false)) {
        return false;
      }
    }

    layoutNEMTransferXEM(desc, xem ? xem->quantity : 0, &multiplier,
                         common->fee);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }

    for (size_t i = 0; i < transfer->mosaics_count; i++) {
      const NEMMosaic *mosaic = &transfer->mosaics[i];

      if (mosaic == xem) {
        continue;
      }

      if (definitions[i]) {
        layoutNEMTransferMosaic(definitions[i], mosaic->quantity, &multiplier,
                                common->network);
      } else {
        layoutNEMTransferUnknownMosaic(mosaic->namespace, mosaic->mosaic,
                                       mosaic->quantity, &multiplier);
      }

      if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         false)) {
        return false;
      }
    }
  } else {
    layoutNEMTransferXEM(desc, transfer->amount, NULL, common->fee);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }
  }

  if (transfer->has_payload) {
    layoutNEMTransferPayload(transfer->payload.bytes, transfer->payload.size,
                             transfer->has_public_key);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }
  }

  layoutNEMDialog(&bmp_icon_question, __("Cancel"), __("Confirm"), desc,
                  __("Confirm transfer to"), transfer->recipient);
  if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, false)) {
    return false;
  }

  return true;
}

bool nem_fsmTransfer(nem_transaction_ctx *context, const HDNode *node,
                     const NEMTransactionCommon *common,
                     const NEMTransfer *transfer) {
  static uint8_t
      encrypted[NEM_ENCRYPTED_PAYLOAD_SIZE(sizeof(transfer->payload.bytes))];

  const uint8_t *payload = transfer->payload.bytes;
  size_t size = transfer->payload.size;

  if (transfer->has_public_key) {
    if (node == NULL) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Private key unavailable for encrypted message");
      return false;
    }

    random_buffer(encrypted, NEM_SALT_SIZE + AES_BLOCK_SIZE);

    const uint8_t *salt = encrypted;
    const uint8_t *iv = &encrypted[NEM_SALT_SIZE];
    uint8_t *buffer = &encrypted[NEM_SALT_SIZE + AES_BLOCK_SIZE];

    bool ret = hdnode_nem_encrypt(node, transfer->public_key.bytes, iv, salt,
                                  payload, size, buffer);

    if (!ret) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to encrypt payload");
      return false;
    }

    payload = encrypted;
    size = NEM_ENCRYPTED_PAYLOAD_SIZE(size);
  }

  bool ret = nem_transaction_create_transfer(
      context, common->network, common->timestamp, NULL, common->fee,
      common->deadline, transfer->recipient, transfer->amount, payload, size,
      transfer->has_public_key, transfer->mosaics_count);

  if (!ret) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to create transfer transaction");
    return false;
  }

  for (size_t i = 0; i < transfer->mosaics_count; i++) {
    const NEMMosaic *mosaic = &transfer->mosaics[i];

    ret = nem_transaction_write_mosaic(context, mosaic->namespace,
                                       mosaic->mosaic, mosaic->quantity);

    if (!ret) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      "Failed to attach mosaics");
      return false;
    }
  }

  return true;
}

bool nem_askProvisionNamespace(const NEMTransactionCommon *common,
                               const NEMProvisionNamespace *provision_namespace,
                               const char *desc) {
  layoutDialogSwipe(
      &bmp_icon_question, __("Cancel"), __("Next"), desc,
      __("Create namespace"), provision_namespace->namespace,
      provision_namespace->has_parent ? __("under namespace") : NULL,
      provision_namespace->has_parent ? provision_namespace->parent : NULL,
      NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  layoutNEMNetworkFee(desc, true, __("Confirm rental fee of"),
                      provision_namespace->fee, __("and network fee of"),
                      common->fee);
  if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, false)) {
    return false;
  }

  return true;
}

bool nem_fsmProvisionNamespace(
    nem_transaction_ctx *context, const NEMTransactionCommon *common,
    const NEMProvisionNamespace *provision_namespace) {
  return nem_transaction_create_provision_namespace(
      context, common->network, common->timestamp, NULL, common->fee,
      common->deadline, provision_namespace->namespace,
      provision_namespace->has_parent ? provision_namespace->parent : NULL,
      provision_namespace->sink, provision_namespace->fee);
}

bool nem_askMosaicCreation(const NEMTransactionCommon *common,
                           const NEMMosaicCreation *mosaic_creation,
                           const char *desc, const char *address) {
  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Next"), desc,
                    __("Create mosaic"), mosaic_creation->definition.mosaic,
                    __("under namespace"),
                    mosaic_creation->definition.namespace, NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  layoutNEMMosaicDescription(mosaic_creation->definition.description);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  char str_out[32] = {0};

  bn_format_uint64(mosaic_creation->definition.supply, NULL, NULL,
                   mosaic_creation->definition.divisibility,
                   mosaic_creation->definition.divisibility, true, ',', str_out,
                   sizeof(str_out));

  layoutDialogSwipe(
      &bmp_icon_question, __("Cancel"), __("Next"), __("Properties"),
      mosaic_creation->definition.mutable_supply ? __("Mutable supply:")
                                                 : __("Immutable supply:"),
      str_out, __("Mosaic will be"),
      mosaic_creation->definition.transferable ? __("transferable")
                                               : __("non-transferable"),
      NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  if (mosaic_creation->definition.has_levy) {
    layoutNEMLevy(&mosaic_creation->definition, common->network);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }

    if (strcmp(address, mosaic_creation->definition.levy_address) == 0) {
      layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Next"),
                        __("Levy Recipient"), __("Levy will be paid to"),
                        __("yourself"), NULL, NULL, NULL, NULL);
    } else {
      layoutNEMDialog(&bmp_icon_question, __("Cancel"), __("Next"),
                      __("Levy Recipient"), __("Levy will be paid to"),
                      mosaic_creation->definition.levy_address);
    }

    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }
  }

  layoutNEMNetworkFee(desc, true, __("Confirm creation fee"),
                      mosaic_creation->fee, __("and network fee of"),
                      common->fee);
  if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, false)) {
    return false;
  }

  return true;
}

bool nem_fsmMosaicCreation(nem_transaction_ctx *context,
                           const NEMTransactionCommon *common,
                           const NEMMosaicCreation *mosaic_creation) {
  return nem_transaction_create_mosaic_creation(
      context, common->network, common->timestamp, NULL, common->fee,
      common->deadline, mosaic_creation->definition.namespace,
      mosaic_creation->definition.mosaic,
      mosaic_creation->definition.description,
      mosaic_creation->definition.divisibility,
      mosaic_creation->definition.supply,
      mosaic_creation->definition.mutable_supply,
      mosaic_creation->definition.transferable,
      mosaic_creation->definition.has_levy ? mosaic_creation->definition.levy
                                           : 0,
      mosaic_creation->definition.fee, mosaic_creation->definition.levy_address,
      mosaic_creation->definition.levy_namespace,
      mosaic_creation->definition.levy_mosaic, mosaic_creation->sink,
      mosaic_creation->fee);
}

bool nem_askSupplyChange(const NEMTransactionCommon *common,
                         const NEMMosaicSupplyChange *supply_change,
                         const char *desc) {
  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Next"), desc,
                    __("Modify supply for"), supply_change->mosaic,
                    __("under namespace"), supply_change->namespace, NULL,
                    NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  char str_out[32] = {0};
  bn_format_uint64(supply_change->delta, NULL, NULL, 0, 0, false, ',', str_out,
                   sizeof(str_out));

  layoutDialogSwipe(
      &bmp_icon_question, __("Cancel"), __("Next"), desc,
      supply_change->type == NEMSupplyChangeType_SupplyChange_Increase
          ? __("Increase supply by")
          : __("Decrease supply by"),
      str_out, __("whole units"), NULL, NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  layoutNEMNetworkFee(desc, true, __("Confirm network fee"), common->fee, NULL,
                      0);
  if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, false)) {
    return false;
  }

  return true;
}

bool nem_fsmSupplyChange(nem_transaction_ctx *context,
                         const NEMTransactionCommon *common,
                         const NEMMosaicSupplyChange *supply_change) {
  return nem_transaction_create_mosaic_supply_change(
      context, common->network, common->timestamp, NULL, common->fee,
      common->deadline, supply_change->namespace, supply_change->mosaic,
      supply_change->type, supply_change->delta);
}

bool nem_askAggregateModification(
    const NEMTransactionCommon *common,
    const NEMAggregateModification *aggregate_modification, const char *desc,
    bool creation) {
  if (creation) {
    layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Next"), desc,
                      __("Convert account to"), __("multisig account?"), NULL,
                      NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }
  }

  char address[NEM_ADDRESS_SIZE + 1] = {0};

  for (size_t i = 0; i < aggregate_modification->modifications_count; i++) {
    const NEMCosignatoryModification *modification =
        &aggregate_modification->modifications[i];
    nem_get_address(modification->public_key.bytes, common->network, address);

    layoutNEMDialog(
        &bmp_icon_question, __("Cancel"), __("Next"), desc,
        modification->type == NEMModificationType_CosignatoryModification_Add
            ? __("Add cosignatory")
            : __("Remove cosignatory"),
        address);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }
  }

  int32_t relative_change = aggregate_modification->relative_change;
  if (relative_change) {
    char str_out[32] = {0};
    bn_format_uint64(relative_change < 0 ? -relative_change : relative_change,
                     NULL, NULL, 0, 0, false, ',', str_out, sizeof(str_out));

    layoutDialogSwipe(
        &bmp_icon_question, __("Cancel"), __("Next"), desc,
        creation ? __("Set minimum")
                 : (relative_change < 0 ? __("Decrease minimum")
                                        : __("Increase minimum")),
        creation ? __("cosignatories to") : __("cosignatories by"), str_out,
        NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return false;
    }
  }

  layoutNEMNetworkFee(desc, true, __("Confirm network fee"), common->fee, NULL,
                      0);
  if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, false)) {
    return false;
  }

  return true;
}

bool nem_fsmAggregateModification(
    nem_transaction_ctx *context, const NEMTransactionCommon *common,
    const NEMAggregateModification *aggregate_modification) {
  bool ret = nem_transaction_create_aggregate_modification(
      context, common->network, common->timestamp, NULL, common->fee,
      common->deadline, aggregate_modification->modifications_count,
      aggregate_modification->relative_change != 0);
  if (!ret) return false;

  for (size_t i = 0; i < aggregate_modification->modifications_count; i++) {
    const NEMCosignatoryModification *modification =
        &aggregate_modification->modifications[i];

    ret = nem_transaction_write_cosignatory_modification(
        context, modification->type, modification->public_key.bytes);
    if (!ret) return false;
  }

  if (aggregate_modification->relative_change) {
    ret = nem_transaction_write_minimum_cosignatories(
        context, aggregate_modification->relative_change);
    if (!ret) return false;
  }

  return true;
}

bool nem_askImportanceTransfer(const NEMTransactionCommon *common,
                               const NEMImportanceTransfer *importance_transfer,
                               const char *desc) {
  layoutDialogSwipe(
      &bmp_icon_question, __("Cancel"), __("Next"), desc,
      importance_transfer->mode ==
              NEMImportanceTransferMode_ImportanceTransfer_Activate
          ? __("Activate remote")
          : __("Deactivate remote"),
      __("harvesting?"), NULL, NULL, NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  layoutNEMNetworkFee(desc, true, __("Confirm network fee"), common->fee, NULL,
                      0);
  if (!protectButton(ButtonRequestType_ButtonRequest_SignTx, false)) {
    return false;
  }

  return true;
}

bool nem_fsmImportanceTransfer(
    nem_transaction_ctx *context, const NEMTransactionCommon *common,
    const NEMImportanceTransfer *importance_transfer) {
  return nem_transaction_create_importance_transfer(
      context, common->network, common->timestamp, NULL, common->fee,
      common->deadline, importance_transfer->mode,
      importance_transfer->public_key.bytes);
}

bool nem_askMultisig(const char *address, const char *desc, bool cosigning,
                     uint64_t fee) {
  layoutNEMDialog(
      &bmp_icon_question, __("Cancel"), __("Next"), desc,
      cosigning ? __("Cosign transaction for") : __("Initiate transaction for"),
      address);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  layoutNEMNetworkFee(desc, false, __("Confirm multisig fee"), fee, NULL, 0);
  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
    return false;
  }

  return true;
}

bool nem_fsmMultisig(nem_transaction_ctx *context,
                     const NEMTransactionCommon *common,
                     const nem_transaction_ctx *inner, bool cosigning) {
  bool ret;
  if (cosigning) {
    ret = nem_transaction_create_multisig_signature(
        context, common->network, common->timestamp, NULL, common->fee,
        common->deadline, inner);
  } else {
    ret = nem_transaction_create_multisig(context, common->network,
                                          common->timestamp, NULL, common->fee,
                                          common->deadline, inner);
  }

  if (!ret) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to create multisig transaction");
    return false;
  }

  return true;
}

const NEMMosaicDefinition *nem_mosaicByName(const char *namespace,
                                            const char *mosaic,
                                            uint8_t network) {
  for (size_t i = 0; i < NEM_MOSAIC_DEFINITIONS_COUNT; i++) {
    const NEMMosaicDefinition *definition = &NEM_MOSAIC_DEFINITIONS[i];

    if (nem_mosaicMatches(definition, namespace, mosaic, network)) {
      return definition;
    }
  }

  return NULL;
}

static inline size_t format_amount(const NEMMosaicDefinition *definition,
                                   const bignum256 *amnt,
                                   const bignum256 *multiplier, int divisor,
                                   char *str_out, size_t size) {
  bignum256 val = {0};
  memcpy(&val, amnt, sizeof(bignum256));

  if (multiplier) {
    bn_multiply(multiplier, &val, &secp256k1.prime);
    divisor += NEM_MOSAIC_DEFINITION_XEM->divisibility;
  }

  return bn_format(
      &val, NULL,
      definition && definition->has_ticker ? definition->ticker : NULL,
      definition && definition->has_divisibility ? definition->divisibility : 0,
      -divisor, false, ',', str_out, size);
}

void nem_canonicalizeMosaics(NEMTransfer *transfer) {
  size_t old_count = transfer->mosaics_count;

  if (old_count <= 1) {
    return;
  }

  NEMMosaic *const mosaics = transfer->mosaics;

  bool skip[old_count];
  memzero(skip, sizeof(skip));

  size_t new_count = 0;

  // Merge duplicates
  for (size_t i = 0; i < old_count; i++) {
    if (skip[i]) continue;

    NEMMosaic *mosaic = &mosaics[new_count];

    if (new_count++ != i) {
      memcpy(mosaic, &mosaics[i], sizeof(NEMMosaic));
    }

    for (size_t j = i + 1; j < old_count; j++) {
      if (skip[j]) continue;

      const NEMMosaic *new_mosaic = &mosaics[j];

      if (nem_mosaicCompare(mosaic, new_mosaic) == 0) {
        skip[j] = true;
        mosaic->quantity += new_mosaic->quantity;
      }
    }
  }

  transfer->mosaics_count = new_count;

  // Sort mosaics
  for (size_t i = 0; i < new_count - 1; i++) {
    NEMMosaic *a = &mosaics[i];

    for (size_t j = i + 1; j < new_count; j++) {
      NEMMosaic *b = &mosaics[j];

      if (nem_mosaicCompare(a, b) > 0) {
        NEMMosaic temp = {0};
        memcpy(&temp, a, sizeof(NEMMosaic));
        memcpy(a, b, sizeof(NEMMosaic));
        memcpy(b, &temp, sizeof(NEMMosaic));
      }
    }
  }
}

void nem_mosaicFormatAmount(const NEMMosaicDefinition *definition,
                            uint64_t quantity, const bignum256 *multiplier,
                            char *str_out, size_t size) {
  bignum256 amnt = {0};
  bn_read_uint64(quantity, &amnt);

  format_amount(definition, &amnt, multiplier, 0, str_out, size);
}

bool nem_mosaicFormatLevy(const NEMMosaicDefinition *definition,
                          uint64_t quantity, const bignum256 *multiplier,
                          uint8_t network, char *str_out, size_t size) {
  if (!definition->has_levy || !definition->has_fee) {
    return false;
  }

  bignum256 amnt = {0}, fee = {0};
  bn_read_uint64(quantity, &amnt);
  bn_read_uint64(definition->fee, &fee);

  const NEMMosaicDefinition *mosaic = nem_mosaicByName(
      definition->levy_namespace, definition->levy_mosaic, network);

  switch (definition->levy) {
    case NEMMosaicLevy_MosaicLevy_Absolute:
      return format_amount(mosaic, &fee, NULL, 0, str_out, size);

    case NEMMosaicLevy_MosaicLevy_Percentile:
      bn_multiply(&fee, &amnt, &secp256k1.prime);
      return format_amount(mosaic, &amnt, multiplier,
                           NEM_LEVY_PERCENTILE_DIVISOR, str_out, size);

    default:
      return false;
  }
}

bool nem_path_check(uint32_t address_n_count, const uint32_t *address_n,
                    uint8_t network, bool check_coin_type) {
  bool valid = (address_n_count >= 3);
  valid = valid && (address_n[0] == (PATH_HARDENED | 44));
  valid = valid && (address_n[1] == (PATH_HARDENED | 43) ||
                    address_n[1] == (PATH_HARDENED | 1));
  valid = valid && (address_n[2] & PATH_HARDENED);
  valid = valid && ((address_n[2] & PATH_UNHARDEN_MASK) <= PATH_MAX_ACCOUNT);

  if (address_n_count == 3) {
    // SEP-0005 for non-UTXO-based currencies, defined by Stellar:
    // https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
    // m/44'/coin_type'/account'
    // No further checks required.
  } else if (address_n_count == 5) {
    // NanoWallet compatibility path
    // "m/44'/coin_type'/account'/0'/0'"
    valid = valid && (address_n[3] == (PATH_HARDENED | 0));
    valid = valid && (address_n[4] == (PATH_HARDENED | 0));
  } else {
    return false;
  }

  if (check_coin_type) {
    // Check that the appropriate coin_type is set for the given network.
    switch (network) {
      case NEM_NETWORK_MAINNET:
      case NEM_NETWORK_MIJIN:
        valid = valid && (address_n[1] == (PATH_HARDENED | 43));
        break;
      case NEM_NETWORK_TESTNET:
        valid = valid && (address_n[1] == (PATH_HARDENED | 1));
        break;
      default:
        return false;
    }
  }

  return valid;
}
