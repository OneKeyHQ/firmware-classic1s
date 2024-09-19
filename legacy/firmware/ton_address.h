#ifndef __TON_ADDRESS_H__
#define __TON_ADDRESS_H__

#include <stdbool.h>
#include <stdint.h>
#include "messages-ton.pb.h"
#include "messages.pb.h"

#define USER_FRIENDLY_LEN 36
#define USER_FRIENDLY_B64_LEN 48

typedef struct {
  uint32_t workchain;
  uint8_t hash[32];
  bool is_bounceable;
  bool is_testnet_only;
} TON_PARSED_ADDRESS;

void ton_decode_addr(TonWorkChain workchain, const char *hash,
                     bool is_bounceable, bool is_testnet_only, char *output);

void ton_parse_addr(const char *dest, TON_PARSED_ADDRESS *parsed_addr);

#endif  // __TON_ADDRESS_H__
