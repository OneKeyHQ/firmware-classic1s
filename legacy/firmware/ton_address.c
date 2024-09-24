#include "ton_address.h"
#include <string.h>
#include "fsm.h"

static inline unsigned char to_uchar(char ch) { return ch; }

void ton_base64_encode(const char *restrict in, size_t inlen,
                       char *restrict out, size_t outlen) {
  static const char b64str[64] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  while (inlen && outlen) {
    *out++ = b64str[(to_uchar(in[0]) >> 2) & 0x3f];
    if (!--outlen) break;
    *out++ =
        b64str[((to_uchar(in[0]) << 4) + (--inlen ? to_uchar(in[1]) >> 4 : 0)) &
               0x3f];
    if (!--outlen) break;
    *out++ = (inlen ? b64str[((to_uchar(in[1]) << 2) +
                              (--inlen ? to_uchar(in[2]) >> 6 : 0)) &
                             0x3f]
                    : '=');
    if (!--outlen) break;
    *out++ = inlen ? b64str[to_uchar(in[2]) & 0x3f] : '=';
    if (!--outlen) break;
    if (inlen) inlen--;
    if (inlen) in += 3;
  }

  if (outlen) *out = '\0';
}

bool ton_base64_decode(const char *in, size_t in_len, uint8_t *out,
                       size_t max_out_len) {
  bool success = true;

  for (size_t i = 0; i < in_len; i++) {
    char c = in[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' ||
          c == '_' || (c == '=' && i >= in_len - 2))) {
      success = false;
      break;
    }
  }

  const uint32_t base64_index[256] = {
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  62U, 63U,
      62U, 62U, 63U, 52U, 53U, 54U, 55U, 56U, 57U, 58U, 59U, 60U, 61U, 0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  1U,  2U,  3U,  4U,  5U,  6U,  7U,  8U,  9U,
      10U, 11U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U,
      25U, 0U,  0U,  0U,  0U,  63U, 0U,  26U, 27U, 28U, 29U, 30U, 31U, 32U, 33U,
      34U, 35U, 36U, 37U, 38U, 39U, 40U, 41U, 42U, 43U, 44U, 45U, 46U, 47U, 48U,
      49U, 50U, 51U, 0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,  0U,
      0U};
  const uint8_t *in_data_uchar = (const uint8_t *)in;
  bool pad_bool =
      (in_len > 0U) &&
      (((in_len % 4U) != 0U) || (in_data_uchar[in_len - 1U] == (uint8_t)'='));
  uint32_t pad_uint = pad_bool ? 1U : 0U;
  const size_t len = (((in_len + 3U) / 4U) - pad_uint) * 4U;
  const size_t out_len = ((len / 4U) * 3U) + pad_uint;

  if (out_len > max_out_len) {
    success = false;
  }

  if (len == 0U) {
    success = false;
  }

  if (success) {
    size_t j = 0U;
    for (size_t i = 0U; i < len; i += 4U) {
      uint32_t n = (base64_index[in_data_uchar[i]] << 18U) |
                   (base64_index[in_data_uchar[i + 1U]] << 12U) |
                   (base64_index[in_data_uchar[i + 2U]] << 6U) |
                   (base64_index[in_data_uchar[i + 3U]]);
      out[j] = (uint8_t)(n >> 16U);
      ++j;
      out[j] = (uint8_t)((n >> 8U) & 0xFFU);
      ++j;
      out[j] = (uint8_t)(n & 0xFFU);
      ++j;
    }
    if (pad_bool) {
      uint32_t n = (base64_index[in_data_uchar[len]] << 18U) |
                   (base64_index[in_data_uchar[len + 1U]] << 12U);
      out[out_len - 1U] = (uint8_t)(n >> 16U);

      if ((in_len > (len + 2U)) && (in_data_uchar[len + 2U] != (uint8_t)'=')) {
        if ((out_len + 1U) > max_out_len) {
          success = false;
        } else {
          n |= base64_index[in_data_uchar[len + 2U]] << 6U;
          out[out_len] = (uint8_t)((n >> 8U) & 0xFFU);
        }
      }
    }
  }

  return success;
}

uint16_t crc16(uint8_t *ptr, size_t count) {
  uint16_t crc = 0;
  int counter = count;
  int i = 0;
  while (--counter >= 0) {
    crc = crc ^ (uint16_t)*ptr++ << 8;
    i = 8;
    do {
      if (crc & 0x8000) {
        crc = crc << 1 ^ 0x1021;
      } else {
        crc = crc << 1;
      }
    } while (--i);
  }
  return (crc);
}

void ton_decode_addr(TonWorkChain workchain, const char *hash,
                     bool is_bounceable, bool is_testnet_only, char *output) {
  char address[36] = {0};
  // Address Tag
  if (is_bounceable) {
    address[0] = 0x11;  // Bounceable
  } else {
    address[0] = 0x51;  // Non-Bounceable
  }
  if (is_testnet_only) {
    address[0] = address[0] | 0x80;
  }

  // Workchain
  address[1] = (workchain == TonWorkChain_BASECHAIN) ? 0x00 : 0xff;

  // Hash
  memmove(address + 2, hash, 32);

  // crc16
  uint16_t crc = crc16((uint8_t *)address, 34);
  address[34] = (crc >> 8) & 0xff;
  address[35] = crc & 0xff;

  // Base64
  ton_base64_encode(address, sizeof(address), output, USER_FRIENDLY_B64_LEN);
}

void ton_parse_addr(const char *dest, TON_PARSED_ADDRESS *parsed_addr) {
  // Base64
  uint8_t decode_res[36];
  if (!ton_base64_decode(dest, USER_FRIENDLY_B64_LEN, decode_res,
                         USER_FRIENDLY_LEN)) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Address decode failed");
  }

  // Flag
  uint8_t flag = decode_res[0];
  parsed_addr->is_bounceable = false;
  parsed_addr->is_testnet_only = false;
  if (flag & 0x80) {
    parsed_addr->is_testnet_only = true;
    flag ^= 0x80;
  }
  if (flag == 0x11) {
    parsed_addr->is_bounceable = true;
  } else if (flag != 0x51) {
    fsm_sendFailure(FailureType_Failure_ProcessError, "Invalid address");
  }

  // Workchain
  parsed_addr->workchain = decode_res[1];
  // Hash
  memmove(parsed_addr->hash, decode_res + 2, 32);
}
