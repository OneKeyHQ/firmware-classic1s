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

#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/rcc.h>
#include "flash.h"
#include "memory.h"
#include "util.h"
#include "oled.h"

static inline void __attribute__((noreturn))
jump_to_boot1(const vector_table_t *ivt) {
  SCB_VTOR = (uint32_t)ivt;  // * relocate vector table
  // Set stack pointer
  __asm__ volatile("msr msp, %0" ::"r"(ivt->initial_sp_value));
  // Jump to address
  ivt->reset();

  // Prevent compiler from generating stack protector code (which causes CPU
  // fault because the stack is moved)
  for (;;)
    ;
}

int main(void) {
  // zero out SRAM
  memset_reg(_ram_start, _ram_end, 0);
  jump_to_boot1((const vector_table_t *)FLASH_PTR(FLASH_BOOT_START));
  return 0;
}
