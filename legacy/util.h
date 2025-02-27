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

#ifndef __UTIL_H_
#define __UTIL_H_

#include <setup.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !EMULATOR
#include <libopencm3/cm3/scb.h>
#include <libopencm3/cm3/vector.h>
#include "timer.h"
#endif

typedef struct {
  const uint8_t *buffer;
  size_t length;
  size_t position;
} BufferReader;

typedef struct {
  uint8_t *buffer;
  size_t length;
  size_t position;
} BufferWriter;

// Statement expressions make these macros side-effect safe
#define MIN_8bits(a, b)                  \
  ({                                     \
    typeof(a) _a = (a);                  \
    typeof(b) _b = (b);                  \
    _a < _b ? (_a & 0xFF) : (_b & 0xFF); \
  })
#define MIN(a, b)       \
  ({                    \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a < _b ? _a : _b;  \
  })
#define MAX(a, b)       \
  ({                    \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a > _b ? _a : _b;  \
  })

void delay(uint32_t wait);

// converts uint32 to hexa (8 digits)
void uint32hex(uint32_t num, char *str);

// converts data to hexa
void data2hex(const uint8_t *data, uint32_t len, char *str);
void data2hexaddr(const uint8_t *data, uint32_t len, char *str);
int hex2data(const char *hexStr, unsigned char *output,
             unsigned int *outputLen);

void uint2str(uint64_t num, char *str);
void int2str(int64_t num, char *str);
uint32_t version_string_to_int(const char *version_str);

bool bracket_replace(char *orig, const char *with);
int compare_str_version(const char *version1, const char *version2);
bool is_valid_ascii(const uint8_t *data, uint32_t length);
bool is_valid_utf8(const uint8_t *data, size_t length);
bool is_printable(const uint8_t *data, uint32_t length);
void init_buffer_reader(BufferReader *reader, const uint8_t *buffer,
                        size_t length);
void init_buffer_writer(BufferWriter *writer, uint8_t *buffer, size_t length);
int read_bytes(BufferReader *reader, uint8_t *dest, size_t count);
int write_bytes(const uint8_t *src, size_t count, BufferWriter *writer);

// defined in startup.s (or setup.c for emulator)
extern void __attribute__((noreturn)) shutdown(void);

#if !EMULATOR
// defined in memory.ld
extern uint8_t _ram_start[], _ram_end[];

// defined in startup.s
extern void memset_reg(void *start, void *stop, uint32_t val);

#define FW_SIGNED 0x5A3CA5C3
#define FW_UNTRUSTED 0x00000000

static inline void __attribute__((noreturn))
jump_to_firmware(const vector_table_t *ivt, int trust) {
  if (FW_SIGNED == trust) {    // trusted signed firmware
    SCB_VTOR = (uint32_t)ivt;  // * relocate vector table
    // Set stack pointer
    __asm__ volatile("msr msp, %0" ::"r"(ivt->initial_sp_value));
  } else {  // untrusted firmware
    timer_init();
    mpu_config_firmware();  // * configure MPU for the firmware

    // Setup stack in unprivileged mode (MSR works only for privileged)
    // This syntax will use _stack as immediate value to put into SP
    // instead of dereferencing it
    __asm__ volatile("mov sp, %[input]" ::[input] "r"(&_stack));
  }

  // Jump to address
  ivt->reset();

  // Prevent compiler from generating stack protector code (which causes CPU
  // fault because the stack is moved)
  for (;;)
    ;
}

static inline void set_mode_privileged(void) {
  // http://infocenter.arm.com/help/topic/com.arm.doc.dui0552a/CHDBIBGJ.html
  __asm__ volatile("msr control, %0" ::"r"(0x0));
}

static inline void set_mode_unprivileged(void) {
  // http://infocenter.arm.com/help/topic/com.arm.doc.dui0552a/CHDBIBGJ.html
  __asm__ volatile("msr control, %0" ::"r"(0x1));
}

static inline bool is_mode_unprivileged(void) {
  uint32_t r0;
  __asm__ volatile("mrs %0, control" : "=r"(r0));
  return r0 & 1;
}

#else /* EMULATOR */

static inline bool is_mode_unprivileged(void) { return true; }
#endif

#endif
