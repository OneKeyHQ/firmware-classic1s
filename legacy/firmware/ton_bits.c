#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // explicit_bzero

#include "ton_bits.h"

void bitstring_init(BitString_t* self) {
  self->data_cursor = 0;
#if !EMULATOR
  explicit_bzero(self->data, sizeof(self->data));
#else
  memset(self->data, 0x00, sizeof(self->data));
#endif
}

void bitstring_write_bit(BitString_t* self, int8_t v) {
  if (v > 0) {
    // this.#buffer[(n / 8) | 0] |= 1 << (7 - (n % 8));
    self->data[(self->data_cursor / 8) | 0] |=
        (1 << (7 - (self->data_cursor % 8)));
  } else {
    // this.#buffer[(n / 8) | 0] &= ~(1 << (7 - (n % 8)));
    self->data[(self->data_cursor / 8) | 0] &=
        ~(1 << (7 - (self->data_cursor % 8)));
  }
  self->data_cursor++;
}

void bitstring_write_uint(BitString_t* self, uint64_t v, uint8_t bits) {
  for (int i = 0; i < bits; i++) {
    int8_t b = (v >> (bits - i - 1)) & 0x01;
    bitstring_write_bit(self, b);
  }
}

void bitstring_write_coins(BitString_t* self, uint64_t v) {
  // Measure length
  uint8_t len = 0;
  uint64_t r = v;
  for (int i = 0; i < 8; i++) {
    if (r > 0) {
      len++;
      r = r >> 8;
    } else {
      break;
    }
  }
  // Write length
  bitstring_write_uint(self, len, 4);

  // Write remaining
  for (int i = 0; i < len; i++) {
    bitstring_write_uint(self, v >> ((len - i - 1) * 8), 8);
  }
}

void bitstring_write_coins_bytes(BitString_t* self, const uint8_t* v,
                                 uint8_t length) {
  uint8_t effective_length = length;
  while (effective_length > 0 && v[length - effective_length] == 0) {
    effective_length--;
  }

  bitstring_write_uint(self, effective_length, 4);

  for (int i = 0; i < effective_length; i++) {
    bitstring_write_uint(self, v[length - effective_length + i], 8);
  }
}

void bitstring_write_buffer(BitString_t* self, uint8_t* v, uint8_t length) {
  for (int i = 0; i < length; i++) {
    bitstring_write_uint(self, v[i], 8);
  }
}

void bitstring_write_address(BitString_t* self, uint8_t chain, uint8_t* hash) {
  bitstring_write_uint(self, 2, 2);
  bitstring_write_uint(self, 0, 1);
  bitstring_write_uint(self, chain, CHAIN_LEN * 8);
  bitstring_write_buffer(self, hash, HASH_LEN);
}

void bitstring_write_null_address(BitString_t* self) {
  bitstring_write_uint(self, 0, 2);
}

void bitstring_final(BitString_t* self) {
  uint8_t padBytes = self->data_cursor % 8;
  if (padBytes > 0) {
    padBytes = 8 - padBytes;
    padBytes = padBytes - 1;
    bitstring_write_bit(self, 1);
    while (padBytes > 0) {
      padBytes = padBytes - 1;
      bitstring_write_bit(self, 0);
    }
  }
}
