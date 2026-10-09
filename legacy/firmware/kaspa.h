#pragma once

#ifndef __KASPA_H__
#define __KASPA_H__
#include "bip32.h"
#include "messages-kaspa.pb.h"

void kaspa_get_address(const uint8_t *pubkey, const uint8_t pubkey_len,
                       const char *prefix, char *addr, bool use_tweak);
bool kaspa_sign_sighash(HDNode *node, const uint8_t *raw_message,
                        uint32_t raw_message_len, uint8_t *signature,
                        pb_size_t *signature_len);
bool kaspa_valid_prefix(const char *addr_prefix);
bool kaspa_valid_scheme(const char *scheme);

typedef enum {
  KASPA_SIGNING_MODE_NONE = 0,
  KASPA_SIGNING_MODE_LEGACY = 1,
  KASPA_SIGNING_MODE_STREAMING = 2,
} KaspaSigningMode;

typedef enum {
  KASPA_PHASE_NONE = 0,
  KASPA_PHASE_COLLECT_INPUTS = 1,
  KASPA_PHASE_COLLECT_OUTPUTS = 2,
  KASPA_PHASE_CONFIRM_TOTAL = 3,
  KASPA_PHASE_COLLECT_PAYLOAD = 4,
  KASPA_PHASE_REPLAY_INPUT = 5,
  KASPA_PHASE_VERIFY_PREV_META = 6,
  KASPA_PHASE_VERIFY_PREV_INPUTS = 7,
  KASPA_PHASE_VERIFY_PREV_OUTPUTS = 8,
  KASPA_PHASE_VERIFY_PREV_PAYLOAD = 9,
  KASPA_PHASE_SIGN_INPUTS = 10,
  KASPA_PHASE_FINISHED = 11,
} KaspaSigningPhase;

#define KASPA_MAX_SCRIPT_PUBLIC_KEY_LEN 35

void kaspa_signing_init(const KaspaSignTx *msg);
void kaspa_signing_abort(void);
void kaspa_signing_clear_runtime_state(void);
bool kaspa_is_legacy_signing(const KaspaSignTx *msg);
bool kaspa_is_streaming_signing(const KaspaSignTx *msg);
KaspaSigningMode kaspa_signing_mode(void);

bool kaspa_streaming_signing_init(const KaspaSignTx *msg);
bool kaspa_process_input(const KaspaTxAckInput *input);
bool kaspa_prepare_prev_tx_verification(const KaspaTxAckInput *input,
                                        HDNode *node);
bool kaspa_process_output(const KaspaTxAckOutput *output, HDNode *node);
bool kaspa_process_prev_meta(const KaspaTxAckPrevMeta *meta);
bool kaspa_process_prev_input(const KaspaTxAckPrevInput *input);
bool kaspa_process_prev_output(const KaspaTxAckPrevOutput *output);
bool kaspa_send_request(KaspaTxRequest *resp);
bool kaspa_receive_payload(const KaspaTxAckPayloadChunk *payload);
bool kaspa_confirm_total(void);
bool kaspa_sign_input(const KaspaTxAckInput *input, HDNode *node,
                      uint8_t *signature, pb_size_t *signature_len);
KaspaSigningPhase kaspa_signing_phase(void);

extern uint32_t input_count;
extern uint32_t input_index;
#endif  // __KASPA_H__
