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

#include <stdint.h>
#include "blake2s.h"
#include "flash.h"
#include "gd32f4xx.h"
#include "memory.h"
#include "sha2.h"

void memory_protect(void) {
  /* enable security protection */
  fmc_unlock();
  ob_unlock();
  ob_security_protection_config(FMC_HSPC);
  ob_start();
  ob_lock();
  fmc_lock();
}

uint8_t memory_protect_state(void) { return (FMC_OBCTL0 >> 8) & 0xff; }

void memory_write_lock(void) {
  uint32_t option_byte0 = FMC_OBCTL0;

  if (((option_byte0 >> 16) & 0x0f) == (OB_WP_1 | OB_WP_2 | OB_WP_3)) {
    return;
  }
  /* disable security protection */
  fmc_unlock();
  ob_unlock();
  // bootloader's sectors  unlock
  ob_write_protection_enable(OB_WP_0 | OB_WP_1 | OB_WP_2 | OB_WP_3);
  ob_start();
  ob_lock();
  fmc_lock();
}

// Read protection is unaffected and always stays locked to the desired value.
void memory_write_unlock(void) {
  /* disable security protection */
  fmc_unlock();
  ob_unlock();
  // bootloader's sectors  unlock
  ob_write_protection_disable(OB_WP_0 | OB_WP_1 | OB_WP_2 | OB_WP_3);
  ob_start();
  ob_lock();
  fmc_lock();
}

int memory_bootloader_hash(uint8_t *hash) {
  sha256_Raw(FLASH_PTR(FLASH_BOOT_START), FLASH_BOOT_LEN, hash);
  sha256_Raw(hash, 32, hash);
  return 32;
}

void mpu_setup_gd32(uint8_t mode) {
  // TODO
  switch (mode) {
    case MPU_CONFIG_BOOT:
      mpu_setup_boot_region();
      break;
    case MPU_CONFIG_FIRM:
      mpu_setup_firm_region();
      break;
    case MPU_CONFIG_OFF:
      mpu_disable();
      break;
    default:
      break;
  }
}
int memory_firmware_hash(const uint8_t *challenge, uint32_t challenge_size,
                         void (*progress_callback)(uint32_t, uint32_t),
                         uint8_t hash[BLAKE2S_DIGEST_LENGTH]) {
  BLAKE2S_CTX ctx;
  if (challenge_size != 0) {
    if (blake2s_InitKey(&ctx, BLAKE2S_DIGEST_LENGTH, challenge,
                        challenge_size) != 0) {
      return 1;
    }
  } else {
    blake2s_Init(&ctx, BLAKE2S_DIGEST_LENGTH);
  }

  for (int i = FLASH_CODE_SECTOR_FIRST; i <= FLASH_CODE_SECTOR_LAST; i++) {
    uint32_t size = flash_sector_size(i);
    const void *data = flash_get_address(i, 0, size);
    if (data == NULL) {
      return 1;
    }
    blake2s_Update(&ctx, data, size);
    if (progress_callback != NULL) {
      progress_callback(i - FLASH_CODE_SECTOR_FIRST,
                        FLASH_CODE_SECTOR_LAST - FLASH_CODE_SECTOR_FIRST);
    }
  }

  return blake2s_Final(&ctx, hash, BLAKE2S_DIGEST_LENGTH);
}
