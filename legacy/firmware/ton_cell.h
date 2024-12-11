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

bool ton_create_transfer_body(const char* memo, CellRef_t* payload);

bool ton_create_jetton_transfer_body(uint8_t dest_workchain, uint8_t* dest_hash,
                                     const uint8_t* jetton_value,
                                     uint8_t jetton_value_len,
                                     uint64_t forward_amount,
                                     const char* forward_payload,
                                     uint8_t resp_workchain, uint8_t* resp_hash,
                                     CellRef_t* payload);

bool ton_create_message_digest(
    uint32_t expire_at, uint32_t seqno, bool is_bounceable,
    uint8_t dest_workchain, uint8_t* dest_hash, uint64_t value, uint8_t mode,
    CellRef_t* payload, bool is_jetton, const char* payload_str,
    BitString_t* payload_bits, CellRef_t* payload_ref, const char** ext_dest,
    const uint64_t* ext_ton_amount, const char** ext_payload,
    uint8_t ext_dest_count, uint8_t* digest);

bool ton_parse_boc(const uint8_t* input_boc, size_t input_boc_len,
                   CellRef_t* payload, BitString_t* payload_bits,
                   CellRef_t* payload_ref);