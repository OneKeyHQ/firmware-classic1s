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
    [20] = 0x08300000,  // last element - not a valid sector
};

secbool flash_check_success(uint32_t status) {
  (void)status;
  return sectrue;
}

void flash_init(void) {}

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
  if (FMC_READY != fmc_sector_erase(CTL_SN(sector))) {
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
