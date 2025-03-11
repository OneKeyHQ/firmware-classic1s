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
void uint2str(uint64_t num, char *str) {
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

void int2str(int64_t num, char *str) {
  if (num < 0) {
    str[0] = '-';
    num = -num;
  }
  uint2str(num, str + (num < 0));
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

int hex2data(const char *hexStr, unsigned char *output,
             unsigned int *outputLen) {
  size_t len = strlen(hexStr);
  if (len % 2 != 0) {
    return -1;
  }
  size_t finalLen = len / 2;
  *outputLen = finalLen;
  for (size_t inIdx = 0, outIdx = 0; outIdx < finalLen; inIdx += 2, outIdx++) {
    if ((hexStr[inIdx] - 48) <= 9 && (hexStr[inIdx + 1] - 48) <= 9) {
      goto convert;
    } else {
      if (((hexStr[inIdx] - 65) <= 5 && (hexStr[inIdx + 1] - 65) <= 5) ||
          ((hexStr[inIdx] - 97) <= 5 && (hexStr[inIdx + 1] - 97) <= 5)) {
        goto convert;
      } else {
        *outputLen = 0;
        return -1;
      }
    }
  convert:
    output[outIdx] =
        (hexStr[inIdx] % 32 + 9) % 25 * 16 + (hexStr[inIdx + 1] % 32 + 9) % 25;
  }
  output[finalLen] = '\0';
  return 0;
}

int compare_str_version(const char *version1, const char *version2) {
  int vnum1 = 0, vnum2 = 0;

  // Loop until both strings are processed
  while (*version1 != '\0' || *version2 != '\0') {
    // Store numeric part of version1 in vnum1
    while (*version1 != '\0' && *version1 != '.') {
      vnum1 = vnum1 * 10 + (*version1 - '0');
      version1++;
    }

    // Store numeric part of version2 in vnum2
    while (*version2 != '\0' && *version2 != '.') {
      vnum2 = vnum2 * 10 + (*version2 - '0');
      version2++;
    }

    // If version1 is greater than version2
    if (vnum1 > vnum2) {
      return 1;
    }
    if (vnum1 < vnum2) {
      return -1;
    }

    // If equal, reset variables and go for next numeric part
    vnum1 = vnum2 = 0;
    if (*version1 != '\0') {
      version1++;
    }
    if (*version2 != '\0') {
      version2++;
    }
  }
  return 0;
}

bool is_valid_ascii(const uint8_t *data, uint32_t length) {
  for (uint32_t i = 0; i < length; i++) {
    if (data[i] < ' ' || data[i] > '~') {
      return false;
    }
  }
  return true;
}

/**
 * Checks if data is in UTF-8 format.
 * Adapted from: https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
 */
bool is_valid_utf8(const uint8_t *data, size_t length) {
  if (!data) {
    return false;
  }
  size_t i = 0;
  while (i < length) {
    if (data[i] < 0x80) {
      /* 0xxxxxxx */
      ++i;
    } else if ((data[i] & 0xe0) == 0xc0) {
      /* 110XXXXx 10xxxxxx */
      if (i + 1 >= length || (data[i + 1] & 0xc0) != 0x80 ||
          (data[i] & 0xfe) == 0xc0) /* overlong? */ {
        return false;
      } else {
        i += 2;
      }
    } else if ((data[i] & 0xf0) == 0xe0) {
      /* 1110XXXX 10Xxxxxx 10xxxxxx */
      if (i + 2 >= length || (data[i + 1] & 0xc0) != 0x80 ||
          (data[i + 2] & 0xc0) != 0x80 ||
          (data[i] == 0xe0 && (data[i + 1] & 0xe0) == 0x80) || /* overlong? */
          (data[i] == 0xed && (data[i + 1] & 0xe0) == 0xa0) || /* surrogate? */
          (data[i] == 0xef && data[i + 1] == 0xbf &&
           (data[i + 2] & 0xfe) == 0xbe)) /* U+FFFE or U+FFFF? */ {
        return false;
      } else {
        i += 3;
      }
    } else if ((data[i] & 0xf8) == 0xf0) {
      /* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
      if (i + 3 >= length || (data[i + 1] & 0xc0) != 0x80 ||
          (data[i + 2] & 0xc0) != 0x80 || (data[i + 3] & 0xc0) != 0x80 ||
          (data[i] == 0xf0 && (data[i + 1] & 0xf0) == 0x80) || /* overlong? */
          (data[i] == 0xf4 && data[i + 1] > 0x8f) ||
          data[i] > 0xf4) /* > U+10FFFF? */ {
        return false;
      } else {
        i += 4;
      }
    } else {
      return false;
    }
  }
  return true;
}

bool is_printable(const uint8_t *data, uint32_t length) {
  return is_valid_ascii(data, length) || is_valid_utf8(data, length);
}

void init_buffer_reader(BufferReader *reader, const uint8_t *buffer,
                        size_t length) {
  reader->buffer = buffer;
  reader->length = length;
  reader->position = 0;
}
void init_buffer_writer(BufferWriter *writer, uint8_t *buffer, size_t length) {
  writer->buffer = buffer;
  writer->length = length;
  writer->position = 0;
}
int read_bytes(BufferReader *reader, uint8_t *dest, size_t count) {
  if (reader->position + count > reader->length) {
    return 0;
  }
  memcpy(dest, reader->buffer + reader->position, count);
  reader->position += count;
  return 1;
}
int write_bytes(const uint8_t *src, size_t count, BufferWriter *writer) {
  if (writer->buffer == NULL && writer->length == 0) {
    writer->position += count;
    return 1;
  }
  if (writer->position + count > writer->length) {
    return 0;
  }
  memcpy(writer->buffer + writer->position, src, count);
  writer->position += count;
  return 1;
}

uint64_t deser_compact_size(BufferReader *s) {
  uint8_t first;
  if (!read_bytes(s, &first, 1)) {
    return 0;
  }

  if (first < 253) {
    return first;
  }

  uint64_t value = 0;
  size_t bytes_to_read = 1 << (first - 252);

  if (!read_bytes(s, (uint8_t *)&value, bytes_to_read)) {
    return 0;
  }

  return value;
}
