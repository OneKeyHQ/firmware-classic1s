#include "ton_bits.h"

typedef struct CellRef_t {
  uint16_t max_depth;
  uint8_t hash[HASH_LEN];
} CellRef_t;

typedef struct {
  BitString_t bits;
  uint32_t ref_indices[4];  // max ref = 4
  uint8_t refs_count;
  CellRef_t cell_ref;
} CellData_t;

typedef struct {
  CellRef_t root;
  BitString_t root_bits;
  CellRef_t root_refs[4];
  uint8_t root_refs_count;
} TonParsedBoc_t;

typedef enum {
  TON_BOC_OK = 0,
  TON_BOC_ERROR_INVALID_ARGUMENT,
  TON_BOC_ERROR_INVALID_FORMAT,
  TON_BOC_ERROR_UNSUPPORTED_FORMAT,
  TON_BOC_ERROR_INVALID_CRC,
  TON_BOC_ERROR_INVALID_CELL_COUNT,
  TON_BOC_ERROR_INVALID_ROOT_COUNT,
  TON_BOC_ERROR_UNSUPPORTED_ABSENT_CELLS,
  TON_BOC_ERROR_INVALID_ROOT,
  TON_BOC_ERROR_INVALID_INDEX,
  TON_BOC_ERROR_INVALID_SIZE,
  TON_BOC_ERROR_OUT_OF_MEMORY,
  TON_BOC_ERROR_UNSUPPORTED_CELL_DESCRIPTOR,
  TON_BOC_ERROR_INVALID_CELL,
  TON_BOC_ERROR_INVALID_TOP_UPPED_ARRAY,
  TON_BOC_ERROR_INVALID_REFERENCE,
  TON_BOC_ERROR_UNREACHABLE_CELL,
  TON_BOC_ERROR_HASH_FAILED,
} TonBocError;

bool ton_create_transfer_body(const char* memo, CellRef_t* payload);

bool ton_create_jetton_transfer_body(uint8_t dest_workchain, uint8_t* dest_hash,
                                     const uint8_t* jetton_value,
                                     uint8_t jetton_value_len,
                                     uint64_t forward_amount,
                                     const char* forward_payload,
                                     uint8_t resp_workchain, uint8_t* resp_hash,
                                     CellRef_t* payload);
bool ton_hash_cell(BitString_t* bits, const CellRef_t* refs, uint8_t refs_count,
                   CellRef_t* out);

// out_boc_error identifies a nested external-payload parse failure.
bool ton_create_message_digest(
    uint32_t expire_at, uint32_t seqno, bool is_bounceable,
    uint8_t dest_workchain, uint8_t* dest_hash, uint64_t value, uint8_t mode,
    CellRef_t* payload, bool is_jetton, const char* payload_str,
    const BitString_t* payload_bits, const CellRef_t* payload_refs,
    uint8_t payload_refs_count, const char** ext_dest,
    const uint64_t* ext_ton_amount, const char** ext_payload,
    uint8_t ext_dest_count, TonBocError* out_boc_error, uint8_t* digest);

TonBocError ton_parse_boc_full(const uint8_t* input_boc, size_t input_boc_len,
                               TonParsedBoc_t* parsed_boc);

TonBocError ton_parse_boc(const uint8_t* input_boc, size_t input_boc_len,
                          CellRef_t* payload, BitString_t* payload_bits,
                          CellRef_t* payload_ref);
