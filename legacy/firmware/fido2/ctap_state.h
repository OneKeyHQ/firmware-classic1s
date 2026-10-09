#ifndef CTAP_STATE_H
#define CTAP_STATE_H

#include "../coin_signing_state.h"
#include "../coin_state.h"

/* The assertion state aliases the signing pool while a FIDO request is active. */
#define getAssertionState (coin_signing_state.fido.assertion)

#endif /* CTAP_STATE_H */
