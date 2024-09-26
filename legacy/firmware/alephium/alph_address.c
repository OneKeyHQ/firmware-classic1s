#include "alph_address.h"

#define TOTAL_NUMBER_OF_GROUPS 4
#define MAX_CHILD_INDEX 0x7FFFFFFF

extern HDNode *fsm_getDerivedNode(const char *curve, const uint32_t *address_n,
                                  size_t address_n_count,
                                  uint32_t *fingerprint);

static uint32_t djb_hash(const uint8_t *data, size_t len) {
  uint32_t h = 5381;
  for (size_t i = 0; i < len; i++) {
    h = ((h << 5) + h) + data[i];
  }
  return h & 0xFFFFFFFF;
}

static uint8_t xor_bytes(uint32_t value) {
  return ((value >> 24) ^ ((value >> 16) & 0xFF) ^ ((value >> 8) & 0xFF) ^
          (value & 0xFF));
}

static int get_pub_key_group(const uint8_t *pub_key, int group_num) {
  uint8_t hash[32];
  blake2b(pub_key, 33, hash, sizeof(hash));
  uint32_t script_hint = djb_hash(hash, sizeof(hash)) | 1;
  uint8_t group_index = xor_bytes(script_hint);
  return group_index % group_num;
}

HDNode *alph_get_derived_node(const uint32_t *address_n,
                              size_t address_n_count) {
  HDNode *node =
      fsm_getDerivedNode(SECP256K1_NAME, address_n, address_n_count, NULL);
  if (!node) {
    return NULL;
  }
  hdnode_fill_public_key(node);
  return node;
}

static bool derive_pub_key_for_group(uint32_t *address_n,
                                     uint32_t *address_n_count,
                                     int target_group) {
  HDNode *node = NULL;
  while (1) {
    node = alph_get_derived_node(address_n, *address_n_count);
    if (!node) {
      return false;
    }
    int current_group =
        get_pub_key_group(node->public_key, TOTAL_NUMBER_OF_GROUPS);
    if (current_group == target_group) {
      return true;
    }
    address_n[*address_n_count - 1]++;
    if (address_n[*address_n_count - 1] > MAX_CHILD_INDEX) {
      return false;
    }
  }
}

bool alph_get_address(const AlephiumGetAddress *msg, AlephiumAddress *resp) {
  if (msg->address_n_count > 10) {
    return false;
  }
  uint32_t derived_path[10];
  memcpy(derived_path, msg->address_n, msg->address_n_count * sizeof(uint32_t));
  uint32_t derived_path_count = msg->address_n_count;
  if (msg->has_target_group) {
    if (msg->target_group >= TOTAL_NUMBER_OF_GROUPS) {
      return false;
    }
    if (!derive_pub_key_for_group(derived_path, &derived_path_count,
                                  msg->target_group)) {
      return false;
    }
  }
  HDNode *derived_node =
      alph_get_derived_node(derived_path, derived_path_count);
  if (!derived_node) {
    return false;
  }
  uint8_t hash[32];
  if (blake2b(derived_node->public_key, 33, hash, sizeof(hash)) != 0) {
    return false;
  }
  uint8_t address_bytes[33];
  address_bytes[0] = 0x00;
  memcpy(address_bytes + 1, hash, 32);
  char address[100];
  size_t address_size = sizeof(address);
  b58enc(address, &address_size, address_bytes, sizeof(address_bytes));
  strlcpy(resp->address, address, sizeof(resp->address));
  if (msg->include_public_key) {
    resp->has_public_key = true;
    resp->public_key.size = 33;
    memcpy(resp->public_key.bytes, derived_node->public_key, 33);
  }
  resp->derived_path_count = derived_path_count;
  memcpy(resp->derived_path, derived_path,
         derived_path_count * sizeof(uint32_t));
  return true;
}