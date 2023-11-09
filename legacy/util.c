/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "util.h"

inline void delay(uint32_t wait) {
  while (--wait > 0) __asm__("nop");
}

static const char *hexdigits = "0123456789ABCDEF";
static const char *hexaddrdigits = "0123456789abcdef";

void uint32hex(uint32_t num, char *str) {
  for (uint32_t i = 0; i < 8; i++) {
    str[i] = hexdigits[(num >> (28 - i * 4)) & 0xF];
  }
}

// converts data to hexa
void data2hex(const uint8_t *data, uint32_t len, char *str) {
  for (uint32_t i = 0; i < len; i++) {
    str[i * 2] = hexdigits[(data[i] >> 4) & 0xF];
    str[i * 2 + 1] = hexdigits[data[i] & 0xF];
  }
  str[len * 2] = 0;
}

// converts data to hexa
void data2hexaddr(const uint8_t *data, uint32_t len, char *str) {
  for (uint32_t i = 0; i < len; i++) {
    str[i * 2] = hexaddrdigits[(data[i] >> 4) & 0xF];
    str[i * 2 + 1] = hexaddrdigits[data[i] & 0xF];
  }
  str[len * 2] = 0;
}

// converts data to hexa
void uint2str(uint32_t num, char *str) {
  uint8_t i = 0, j;
  char temp;

  do {
    str[i++] = hexdigits[num % 10];
    num /= 10;
  } while (num);
  str[i] = 0;

  for (j = 0; j <= (i - 1) / 2; j++) {
    temp = str[j];
    str[j] = str[i - 1 - j];
    str[i - 1 - j] = temp;
  }
}

uint32_t version_string_to_int(const char *version_str) {
  uint32_t version = 0;
  int part = 0;
  int shift = 24;

  for (uint8_t i = 0; i < strlen(version_str); i++) {
    if (version_str[i] == '.') {
      version |= (part << shift);
      part = 0;
      shift -= 8;
    } else if (version_str[i] >= '0' && version_str[i] <= '9') {
      part = part * 10 + (version_str[i] - '0');
    } else {
      return 0;
    }
  }

  version |= (part << shift);
  return version;
}

extern int utf8_get_size(const uint8_t ch);
bool bracket_replace(char *orig, const char *with) {
  int steps = 0;
  int with_len = strlen(with), orig_len = strlen(orig), len = 0;
  char *p = orig;
  char tmp[256] = {0};

  while (*p) {
    if ((uint8_t)*p < 0x80) {
      if ((*p == '{') && (p[1] == '}')) {
        len = strlen(p + 2) + 1;
        memcpy(tmp, p + 2, len);
        memcpy(p, with, with_len);
        memcpy(p + with_len, tmp, len);
        orig[orig_len - 2 + with_len] = '\0';
        break;
      }
      p++;
    } else {
      steps = utf8_get_size(*p);
      p += steps;
    }
  }
  return true;
}
