#ifndef __ETHEREUM_UINT256_H__
#define __ETHEREUM_UINT256_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bignum.h"

#define ETHEREUM_UINT256_SIZE 32U
#define ETHEREUM_UINT256_DECIMAL_BUFFER_SIZE 80U

static bool ethereum_uint256_to_decimal(const uint8_t *data, uint32_t data_len,
                                        char *output, size_t output_len) {
  if (output == NULL || output_len < ETHEREUM_UINT256_DECIMAL_BUFFER_SIZE ||
      data_len > ETHEREUM_UINT256_SIZE ||
      (data_len != 0 && data == NULL)) {
    return false;
  }

  uint8_t padded[ETHEREUM_UINT256_SIZE] = {0};
  if (data_len != 0) {
    memcpy(padded + ETHEREUM_UINT256_SIZE - data_len, data, data_len);
  }

  bignum256 value = {0};
  bn_read_be(padded, &value);
  output[0] = '\0';
  if (bn_format(&value, NULL, NULL, 0, 0, false, 0, output, output_len) ==
      0) {
    output[0] = '\0';
    return false;
  }
  output[output_len - 1] = '\0';
  return true;
}

#endif
