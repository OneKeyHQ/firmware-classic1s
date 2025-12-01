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

#ifndef FLASH_H
#define FLASH_H

#include <stdint.h>
#include <stdlib.h>
#include "secbool.h"

#define FLASH_SECTOR_COUNT 28

// note: FLASH_SR_RDERR is STM32F42xxx and STM32F43xxx specific (STM32F427)
// (reference RM0090 section 3.7.5)
#ifndef STM32F427xx
#define FLASH_SR_RDERR 0
#endif

#define FLASH_STATUS_ALL_FLAGS                                            \
  (FLASH_SR_RDERR | FLASH_SR_PGSERR | FLASH_SR_PGPERR | FLASH_SR_PGAERR | \
   FLASH_SR_WRPERR | FLASH_SR_SOP | FLASH_SR_EOP)

secbool __wur flash_unlock_write(void);
secbool __wur flash_lock_write(void);
uint32_t flash_sector_size(uint8_t sector);

const void *flash_get_address(uint8_t sector, uint32_t offset, uint32_t size);
uint8_t *flash_read_bytes(uint32_t addr);
// secbool __wur flash_erase(uint8_t sector);
secbool flash_erase(uint8_t sector);
secbool flash_write_word_item(uint32_t offset, uint32_t data);
secbool flash_write_word_item_ex(uint32_t offset, uint32_t data);
void gd32_flash_init(void);

void flash_unlock_ex(void);
void flash_lock_ex(void);

secbool __wur flash_write_byte(uint8_t sector, uint32_t offset, uint8_t data);
secbool __wur flash_write_word(uint8_t sector, uint32_t offset, uint32_t data);

// page_addr must be 4KB aligned (0x1000)
secbool flash_page_erase(uint32_t page_addr);

#endif  // FLASH_H
