#include "coin_parser_state.h"

#include "memzero.h"

/* These parser packages intentionally use the same generic type names. */
#define parser_tx_t cosmos_parser_tx_t
#define parser_error_t cosmos_parser_error_t
#define parser_context_t cosmos_parser_context_t
#define zxerr_t cosmos_zxerr_t
#include "cosmos/tx_parser.h"
#undef zxerr_t
#undef parser_context_t
#undef parser_error_t
#undef parser_tx_t

#define parser_tx_t algorand_parser_tx_t
#define parser_error_t algorand_parser_error_t
#define parser_context_t algorand_parser_context_t
#define zxerr_t algorand_zxerr_t
#include "algo/parser_txdef.h"
#undef zxerr_t
#undef parser_context_t
#undef parser_error_t
#undef parser_tx_t

#define parser_tx_t filecoin_parser_tx_t
#include "filecoin/parser_txdef.h"
#undef parser_tx_t

typedef union {
  cosmos_parser_tx_t cosmos;
  algorand_parser_tx_t algorand;
  filecoin_parser_tx_t filecoin;
} coin_parser_state_t;

static coin_parser_state_t coin_parser_state;

_Static_assert(_Alignof(coin_parser_state_t) >= _Alignof(cosmos_parser_tx_t),
               "Cosmos parser alignment changed");
_Static_assert(_Alignof(coin_parser_state_t) >= _Alignof(algorand_parser_tx_t),
               "Algorand parser alignment changed");
_Static_assert(_Alignof(coin_parser_state_t) >= _Alignof(filecoin_parser_tx_t),
               "Filecoin parser alignment changed");

void *coin_parser_state_cosmos(void) { return &coin_parser_state.cosmos; }
void *coin_parser_state_algorand(void) { return &coin_parser_state.algorand; }
void *coin_parser_state_filecoin(void) { return &coin_parser_state.filecoin; }
void coin_parser_state_clear(void) {
  memzero(&coin_parser_state, sizeof(coin_parser_state));
}
