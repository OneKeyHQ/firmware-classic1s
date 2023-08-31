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

#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/rcc.h>
#include "flash.h"
#include "memory.h"
#include "oled.h"
#include "sys.h"
#include "util.h"

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
  register uint32_t r11 __asm__("r11");
  volatile uint32_t stay_in_bootloader_flag = r11;
  if ((stay_in_bootloader_flag == STAY_IN_BOOTLOADER_FLAG) ||
      (memcmp((uint8_t *)(ST_RAM_END - 4), "boot", 4) == 0)) {
    *STAY_IN_BOOTLOADER_FLAG_ADDR = STAY_IN_BOOTLOADER_FLAG;
  }

  jump_to_boot1((const vector_table_t *)FLASH_PTR(FLASH_BOOT_START));
  return 0;
}
