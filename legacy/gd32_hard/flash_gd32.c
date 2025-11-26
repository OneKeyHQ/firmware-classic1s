/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "flash.h"
#include "gd32f4xx.h"
#include "memory.h"
#include "supervise.h"

static uint8_t gd32_sector_map[FLASH_SECTOR_COUNT];

static const uint32_t FLASH_SECTOR_TABLE[FLASH_SECTOR_COUNT + 1] = {
    // BANK0 size 1MB
    [0] = 0x08000000,   // - 0x08003FFF |  16 KiB
    [1] = 0x08004000,   // - 0x08007FFF |  16 KiB
    [2] = 0x08008000,   // - 0x0800BFFF |  16 KiB
    [3] = 0x0800C000,   // - 0x0800FFFF |  16 KiB
    [4] = 0x08010000,   // - 0x0801FFFF |  64 KiB
    [5] = 0x08020000,   // - 0x0803FFFF | 128 KiB
    [6] = 0x08040000,   // - 0x0805FFFF | 128 KiB
    [7] = 0x08060000,   // - 0x0807FFFF | 128 KiB
    [8] = 0x08080000,   // - 0x0809FFFF | 128 KiB
    [9] = 0x080A0000,   // - 0x080BFFFF | 128 KiB
    [10] = 0x080C0000,  // - 0x080DFFFF | 128 KiB
    [11] = 0x080E0000,  // - 0x080FFFFF | 128 KiB
    // BANK1 size 2MB sector12~sector27
    [12] = 0x08100000,  // - 0x08003FFF |  16 KiB
    [13] = 0x08104000,  // - 0x08007FFF |  16 KiB
    [14] = 0x08108000,  // - 0x0800BFFF |  16 KiB
    [15] = 0x0810C000,  // - 0x0800FFFF |  16 KiB
    [16] = 0x08110000,  // - 0x0801FFFF |  64 KiB
    [17] = 0x08120000,  // - 0x0803FFFF | 128 KiB
    [18] = 0x08140000,  // - 0x0805FFFF | 128 KiB
    [19] = 0x08160000,  // - 0x0805FFFF | 128 KiB
    [20] = 0x08180000,  // - 0x0805FFFF | 128 KiB
    [21] = 0x081A0000,  // - 0x0805FFFF | 128 KiB
    [22] = 0x081C0000,  // - 0x0805FFFF | 128 KiB
    [23] = 0x081E0000,  // - 0x0805FFFF | 128 KiB
    [24] = 0x08200000,  // - 0x0805FFFF | 256 KiB
    [25] = 0x08240000,  // - 0x0805FFFF | 256 KiB
    [26] = 0x08280000,  // - 0x0805FFFF | 256 KiB
    [27] = 0x082C0000,  // - 0x0805FFFF | 256 KiB
    [28] = 0x08300000,  // last element - not a valid sector
};

secbool flash_check_success(uint32_t status) {
  (void)status;
  return sectrue;
}

void gd32_flash_init(void) {
  gd32_sector_map[0] = CTL_SECTOR_NUMBER_0;
  gd32_sector_map[1] = CTL_SECTOR_NUMBER_1;
  gd32_sector_map[2] = CTL_SECTOR_NUMBER_2;
  gd32_sector_map[3] = CTL_SECTOR_NUMBER_3;
  gd32_sector_map[4] = CTL_SECTOR_NUMBER_4;
  gd32_sector_map[5] = CTL_SECTOR_NUMBER_5;
  gd32_sector_map[6] = CTL_SECTOR_NUMBER_6;
  gd32_sector_map[7] = CTL_SECTOR_NUMBER_7;
  gd32_sector_map[8] = CTL_SECTOR_NUMBER_8;
  gd32_sector_map[9] = CTL_SECTOR_NUMBER_9;
  gd32_sector_map[10] = CTL_SECTOR_NUMBER_10;
  gd32_sector_map[11] = CTL_SECTOR_NUMBER_11;
  gd32_sector_map[12] = CTL_SECTOR_NUMBER_12;
  gd32_sector_map[13] = CTL_SECTOR_NUMBER_13;
  gd32_sector_map[14] = CTL_SECTOR_NUMBER_14;
  gd32_sector_map[15] = CTL_SECTOR_NUMBER_15;
  gd32_sector_map[16] = CTL_SECTOR_NUMBER_16;
  gd32_sector_map[17] = CTL_SECTOR_NUMBER_17;
  gd32_sector_map[18] = CTL_SECTOR_NUMBER_18;
  gd32_sector_map[19] = CTL_SECTOR_NUMBER_19;
  gd32_sector_map[20] = CTL_SECTOR_NUMBER_20;
  gd32_sector_map[21] = CTL_SECTOR_NUMBER_21;
  gd32_sector_map[22] = CTL_SECTOR_NUMBER_22;
  gd32_sector_map[23] = CTL_SECTOR_NUMBER_23;
  gd32_sector_map[24] = CTL_SECTOR_NUMBER_24;
  gd32_sector_map[25] = CTL_SECTOR_NUMBER_25;
  gd32_sector_map[26] = CTL_SECTOR_NUMBER_26;
  gd32_sector_map[27] = CTL_SECTOR_NUMBER_27;
}

secbool flash_unlock_write(void) { return sectrue; }

secbool flash_lock_write(void) { return sectrue; }

/**
 * @brief  Flash memory read routine
 * @param  addr: address to be read from
 * @retval Pointer to the physical address where data should be read
 */
uint8_t *flash_read_bytes(uint32_t addr) { return (uint8_t *)(addr); }

const void *flash_get_address(uint8_t sector, uint32_t offset, uint32_t size) {
  if (sector >= FLASH_SECTOR_COUNT) {
    return NULL;
  }
  const uint32_t addr = FLASH_SECTOR_TABLE[sector] + offset;
  const uint32_t next = FLASH_SECTOR_TABLE[sector + 1];
  if (addr + size > next) {
    return NULL;
  }
  return (const void *)FLASH_PTR(addr);
}

uint32_t flash_sector_size(uint8_t sector) {
  if (sector >= FLASH_SECTOR_COUNT) {
    return 0;
  }
  return FLASH_SECTOR_TABLE[sector + 1] - FLASH_SECTOR_TABLE[sector];
}

secbool flash_erase(uint8_t sector) {
  /* unlock the flash program erase controller */
  fmc_unlock();
  /* clear pending flags */
  fmc_flag_clear(FMC_FLAG_END | FMC_FLAG_OPERR | FMC_FLAG_WPERR |
                 FMC_FLAG_PGMERR | FMC_FLAG_PGSERR);
  /* wait the erase operation complete*/
  if (FMC_READY != fmc_sector_erase(gd32_sector_map[sector])) {
    return secfalse;
  }
  /* lock the flash program erase controller */
  fmc_lock();
  // Check whether the sector was really deleted (contains only 0xFF).
  const uint32_t addr_start = FLASH_SECTOR_TABLE[sector],
                 addr_end = FLASH_SECTOR_TABLE[sector + 1];
  for (uint32_t addr = addr_start; addr < addr_end; addr += 4) {
    if (*((const uint32_t *)FLASH_PTR(addr)) != 0xFFFFFFFF) {
      return secfalse;
    }
  }
  return sectrue;
}

secbool flash_write_byte(uint8_t sector, uint32_t offset, uint8_t data) {
  uint8_t *address = (uint8_t *)flash_get_address(sector, offset, 1);
  if (address == NULL) {
    return secfalse;
  }

  if ((*address & data) != data) {
    return secfalse;
  }

  /* unlock the flash program erase controller */
  fmc_unlock();
  if (FMC_READY != fmc_byte_program((uint32_t)address, data)) {
    return secfalse;
  }
  /* lock the flash program erase controller */
  fmc_lock();

  if (*address != data) {
    return secfalse;
  }

  return sectrue;
}

secbool flash_write_word(uint8_t sector, uint32_t offset, uint32_t data) {
  uint32_t *address = (uint32_t *)flash_get_address(sector, offset, 4);
  if (address == NULL) {
    return secfalse;
  }

  if (offset % 4 != 0) {
    return secfalse;
  }

  if ((*address & data) != data) {
    return secfalse;
  }

  /* unlock the flash program erase controller */
  fmc_unlock();
  if (FMC_READY != fmc_word_program((uint32_t)address, data)) {
    return secfalse;
  }
  /* lock the flash program erase controller */
  fmc_lock();

  if (*address != data) {
    return secfalse;
  }

  return sectrue;
}

secbool flash_write_word_item(uint32_t offset, uint32_t data) {
  if (offset % 4 != 0) {
    return secfalse;
  }

  /* unlock the flash program erase controller */
  fmc_unlock();
  if (FMC_READY != fmc_word_program(offset, data)) {
    return secfalse;
  }
  /* lock the flash program erase controller */
  fmc_lock();

  if (*(uint32_t *)offset != data) {
    return secfalse;
  }

  return sectrue;
}

secbool flash_write_word_item_ex(uint32_t offset, uint32_t data) {
  if (offset % 4 != 0) {
    return secfalse;
  }

  if (FMC_READY != fmc_word_program(offset, data)) {
    return secfalse;
  }

  if (*(uint32_t *)offset != data) {
    return secfalse;
  }

  return sectrue;
}

void flash_unlock_ex(void) { fmc_unlock(); }

void flash_lock_ex(void) { fmc_lock(); }

// Page erase function (4KB page)
// page_addr must be 4KB aligned (0x1000)
// Only available for GD32F425, GD32F427, GD32F470
#if defined(GD32F425) || defined(GD32F427) || defined(GD32F470)
secbool flash_page_erase(uint32_t page_addr) {
  if (page_addr % 0x1000 != 0) {
    return secfalse;  // Address must be 4KB aligned
  }

  // Use the existing fmc_page_erase function from GD32 library
  fmc_state_enum fmc_state = fmc_page_erase(page_addr);
  if (FMC_READY != fmc_state) {
    return secfalse;
  }

  // Check whether the page was really erased (contains only 0xFF).
  for (uint32_t addr = page_addr; addr < page_addr + 0x1000; addr += 4) {
    if (*((const uint32_t *)FLASH_PTR(addr)) != 0xFFFFFFFF) {
      return secfalse;
    }
  }

  return sectrue;
}
#else
// For other chips, page erase is not supported, return error
secbool flash_page_erase(uint32_t page_addr) {
  (void)page_addr;
  return secfalse;
}
#endif
