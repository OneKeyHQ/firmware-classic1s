#ifndef ETHEREUM_APPROVERS_H
#define ETHEREUM_APPROVERS_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef enum { APPROVER_TYPE_UNIFIED, APPROVER_TYPE_MIXED } ApproverType;

typedef struct {
  const char* name;
  const uint8_t address[20];
  const ApproverType type;
  const union {
    struct {
      const uint64_t* chain_ids;
      size_t chain_count;
    } unified;
    uint64_t chain_id;
  } data;
} EthereumApprover;

static const uint64_t oneinch_chains[] = {1,   10,   56,    137,
                                          250, 8453, 42161, 43114};
static const uint64_t zerox_chains[] = {1, 10, 56, 137, 8453, 42161, 43114};
static const uint64_t cow_chains[] = {1, 8453, 42161};
static const uint64_t socket_chains[] = {
    1,    10,    56,    100,   137,   250,   1101,      5000,
    8453, 34443, 42161, 43114, 59144, 81457, 1313161554};

static const uint64_t okx_unified_chains_1[] = {
    1088, 1101,  5000,
    8453, 59144, 534352};  // 0x57df6092665eb6058de53939612413ff4b09114e
static const uint64_t okx_unified_chains_2[] = {
    66, 250, 42161};  // 0x70cbb871e8f30fc8ce23609e9e0ea87b6b222f58
static const uint64_t okx_unified_chains_3[] = {
    1, 43114};  // 0x40aa958dd87fc8305b97f2ba922cddca374bcd7f

static const EthereumApprover ethereum_approvers[] = {
    {.name = "1inch",
     .address = "\x11\x11\x11\x12\x54\x21\xca\x6d\xc4\x52\xd2\x89\x31\x42\x80"
                "\xa0\xf8\x84\x2a\x65",
     .type = APPROVER_TYPE_UNIFIED,
     .data.unified = {.chain_ids = oneinch_chains,
                      .chain_count =
                          sizeof(oneinch_chains) / sizeof(oneinch_chains[0])}},
    {.name = "0x",
     .address = "\x00\x00\x00\x00\x00\x00\x1f\xf3\x68\x4f\x28\xc6\x75\x38\xd4"
                "\xd0\x72\xc2\x27\x34",
     .type = APPROVER_TYPE_UNIFIED,
     .data.unified = {.chain_ids = zerox_chains,
                      .chain_count =
                          sizeof(zerox_chains) / sizeof(zerox_chains[0])}},
    {.name = "CoW",
     .address = "\xc9\x2e\x8b\xdf\x79\xf0\x50\x7f\x65\xa3\x92\xb0\xab\x46\x67"
                "\x71\x6b\xfe\x01\x10",
     .type = APPROVER_TYPE_UNIFIED,
     .data.unified = {.chain_ids = cow_chains,
                      .chain_count =
                          sizeof(cow_chains) / sizeof(cow_chains[0])}},
    {.name = "Socket",
     .address = "\x3a\x23\xf9\x43\x18\x14\x08\xea\xc4\x24\x11\x6a\xf7\xb7\x79"
                "\x0c\x94\xcb\x97\xa5",
     .type = APPROVER_TYPE_UNIFIED,
     .data.unified = {.chain_ids = socket_chains,
                      .chain_count =
                          sizeof(socket_chains) / sizeof(socket_chains[0])}},

    {.name = "OKX",
     .type = APPROVER_TYPE_UNIFIED,
     .address = "\x57\xdf\x60\x92\x66\x5e\xb6\x05\x8d\xe5\x39\x39\x61\x24\x13"
                "\xff\x4b\x09\x11\x4e",
     .data.unified = {.chain_ids = okx_unified_chains_1,
                      .chain_count = sizeof(okx_unified_chains_1) /
                                     sizeof(okx_unified_chains_1[0])}},
    {.name = "OKX",
     .type = APPROVER_TYPE_UNIFIED,
     .address = "\x70\xcb\xb8\x71\xe8\xf3\x0f\xc8\xce\x23\x60\x9e\x9e\x0e\xa8"
                "\x7b\x6b\x22\x2f\x58",
     .data.unified = {.chain_ids = okx_unified_chains_2,
                      .chain_count = sizeof(okx_unified_chains_2) /
                                     sizeof(okx_unified_chains_2[0])}},
    {.name = "OKX",
     .type = APPROVER_TYPE_UNIFIED,
     .address = "\x40\xaa\x95\x8d\xd8\x7f\xc8\x30\x5b\x97\xf2\xba\x92\x2c\xdd"
                "\xca\x37\x4b\xcd\x7f",
     .data.unified = {.chain_ids = okx_unified_chains_3,
                      .chain_count = sizeof(okx_unified_chains_3) /
                                     sizeof(okx_unified_chains_3[0])}},

    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\x68\xd6\xb7\x39\xd2\x02\x00\x67\xd1\xe2\xf7\x13\xb9\x99\xda"
                "\x97\xe4\xd5\x48\x12",
     .data.chain_id = 10},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\x2c\x34\xa2\xfb\x1d\x0b\x4f\x55\xde\x51\xe1\xd0\xbd\xef\xad"
                "\xdc\xe6\xb7\xcd\xd6",
     .data.chain_id = 56},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\x2e\x28\x28\x1c\xf3\xd5\x8f\x47\x5c\xeb\xe2\x7b\xec\x4b\x8a"
                "\x23\xdf\xc7\x78\x2c",
     .data.chain_id = 130},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\x3b\x86\x91\x73\x69\xb8\x3a\x68\x92\xf5\x53\x60\x9f\x3c\x2f"
                "\x43\x9c\x18\x4e\x31",
     .data.chain_id = 137},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\xd3\x21\xab\x55\x89\xd3\xe8\xfa\x5d\xf9\x85\xcc\xfe\xf6\x25"
                "\x02\x2e\x2d\xd9\x10",
     .data.chain_id = 146},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\xc6\x78\x79\xf4\x06\x5d\x3b\x9f\xe1\xc0\x9e\xe9\x90\xb8\x91"
                "\xaa\x8e\x3a\x4c\x2f",
     .data.chain_id = 324},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\x80\x1d\x8e\xd8\x49\x03\x90\x07\xa7\x17\x08\x30\x62\x31\x80"
                "\x39\x64\x92\xc7\xed",
     .data.chain_id = 1329},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\x03\xb5\xac\xda\x01\x20\x78\x24\xcc\x7b\xc2\x17\x83\xee\x5a"
                "\xa2\xb8\xd1\xd2\xfe",
     .data.chain_id = 7000},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\xbd\x0e\xbe\x49\x77\x9e\x15\x4e\x50\x42\xb3\x4d\x5b\xcf\xbc"
                "\x49\x8e\x4b\x32\x49",
     .data.chain_id = 34443},
    {.name = "OKX",
     .type = APPROVER_TYPE_MIXED,
     .address = "\x5f\xd2\xdc\x91\xff\x1d\xe7\xff\x4a\xeb\x1c\xac\xef\x8e\x99"
                "\x11\xba\xae\xca\x68",
     .data.chain_id = 81457}};

#define ETHEREUM_APPROVERS_COUNT \
  (sizeof(ethereum_approvers) / sizeof(ethereum_approvers[0]))
#define UNIFIED_APPROVERS_COUNT 7
#define MIXED_APPROVERS_COUNT 10

const EthereumApprover* ethereum_approver_by_chain_address(
    uint64_t chain_id, const uint8_t* address) {
  for (size_t i = 0; i < ETHEREUM_APPROVERS_COUNT; i++) {
    const EthereumApprover* approver = &ethereum_approvers[i];

    if (memcmp(approver->address, address, 20) == 0) {
      if (approver->type == APPROVER_TYPE_UNIFIED) {
        for (size_t j = 0; j < approver->data.unified.chain_count; j++) {
          if (approver->data.unified.chain_ids[j] == chain_id) {
            return approver;
          }
        }
      } else if (approver->type == APPROVER_TYPE_MIXED) {
        if (approver->data.chain_id == chain_id) {
          return approver;
        }
      }
    }
  }

  return NULL;
}

#endif  // ETHEREUM_APPROVERS_H
