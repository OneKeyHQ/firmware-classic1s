/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2018 Pavol Rusnak <stick@satoshilabs.com>
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
#include <string.h>
#include "../flash.h"
#include "bl_data.h"
#include "ble.h"
#include "buttons.h"
#include "gettext.h"
#include "layout.h"
#include "memory.h"
#include "oled.h"
#include "util.h"

char bootloader_version[8] = {0};

#if BOOTLOADER_QA
static int known_bootloader(int r, const uint8_t *hash) {
  if (r != 32) return 0;
  // BEGIN AUTO-GENERATED QA BOOTLOADER ENTRIES (bl_check_qa.txt)
  if (0 ==
      memcmp(hash,
             "\x8a\x4e\xf9\x74\x03\xd0\x27\x56\xd9\xa5\x52\xaf\xf7\x3f\xcc\x82"
             "\xf2\xc6\xeb\x90\x08\x91\xdb\x5f\x17\x86\x15\x5c\x3c\xbc\xf8\x3e",
             32)) {
    memcpy(bootloader_version, "2.0.5", strlen("2.0.5"));
    return 1;  // 2.0.5 shipped with fw 3.5.0
  }
  if (0 ==
      memcmp(hash,
             "\x3c\xd7\x65\x34\x5c\xff\x3b\x3f\xcd\xdc\x59\x76\x15\x72\x72\x9b"
             "\x9d\xaf\x48\xa6\x7e\x9d\x4d\x55\x37\x9b\x71\xa7\x2d\xd0\xb5\x82",
             32)) {
    memcpy(bootloader_version, "2.0.6", strlen("2.0.6"));
    return 1;  // 2.0.6 shipped with fw 3.5.0
  }
  // END AUTO-GENERATED QA BOOTLOADER ENTRIES (bl_check_qa.txt)

  return 0;
}
#endif

#if PRODUCTION
static int known_bootloader(int r, const uint8_t *hash) {
  if (r != 32) return 0;
  // BEGIN AUTO-GENERATED BOOTLOADER ENTRIES (bl_check.txt)
  if (0 ==
      memcmp(hash,
             "\xdf\xce\xa3\xd8\xcc\x46\xe4\xec\xc9\xc8\xf6\x8c\xae\x61\x37\xa1"
             "\x37\x3d\xdd\x17\x58\x8d\xf7\x34\xbd\x8e\xc9\x11\x1a\x40\x2b\xc6",
             32)) {
    memcpy(bootloader_version, "2.0.5", strlen("2.0.5"));
    return 1;  // 2.0.5 shipped with fw 3.5.0
  }
  if (0 ==
      memcmp(hash,
             "\xc9\xe2\x30\x5f\xb3\x14\x6d\xbc\xf2\x2c\xd8\x71\xf4\x58\xaf\x6d"
             "\x6b\xee\x97\x37\x4d\x3d\x13\x52\x83\x8e\x90\xea\x27\x98\xa2\xe2",
             32)) {
    memcpy(bootloader_version, "2.0.6", strlen("2.0.6"));
    return 1;  // 2.0.6 shipped with fw 3.5.0
  }
  // END AUTO-GENERATED BOOTLOADER ENTRIES (bl_check.txt)
  return 0;
}

#endif

/**
 * If bootloader is older and known, replace with newer bootloader.
 * If bootloader is unknown, halt with error message.
 *
 * @param shutdown_on_replace: if true, shuts down device instead of return
 */
void check_and_replace_bootloader(bool shutdown_on_replace) {
#if PRODUCTION || BOOTLOADER_QA
  uint8_t hash[32] = {0};
  int r = memory_bootloader_hash(hash);

  if (!known_bootloader(r, hash)) {
    layoutDialog(&bmp_icon_error, NULL, NULL, NULL, "Unknown bootloader",
                 "detected.", NULL, "Shutdown your OneKey",
                 "contact our support.", NULL);
    delay_ms(1000);
    shutdown();
  }

  if (is_mode_unprivileged()) {
    return;
  }

  if (r == 32 && 0 == memcmp(hash, bl_hash, 32)) {
    // all OK -> done
    return;
  }

  if (sys_usbState() == false && battery_cap == 0xff) {
    layoutDialogCenterAdapterEx(NULL, NULL, NULL, NULL, "Get battery level...",
                                NULL, NULL, NULL);
    while (1) {
      if (battery_cap == 0xff) {
        ble_request_info(BLE_CMD_BATTERY);
      } else {
        break;
      }
      if (sys_usbState() == true) {
        break;
      }
      delay_ms(5);
    }
  }

  if (sys_usbState() == false && battery_cap < 2) {
    layoutDialogCenterAdapterEx(
        &bmp_icon_warning, NULL, &bmp_bottom_right_confirm, NULL,
        "Low Battery!Use cable or", "Charge to 25% before",
        "updating the bootloader", NULL);
    while (1) {
      uint8_t key = keyScan();
      if (key == KEY_CONFIRM) {
        return;
      }
      if (sys_usbState() == true) {
        break;
      }
    }
  }

  // ENABLE THIS AT YOUR OWN RISK
  // ATTEMPTING TO OVERWRITE BOOTLOADER WITH UNSIGNED FIRMWARE MAY BRICK
  // YOUR DEVICE.

  layoutDialogCenterAdapterEx(
      &bmp_icon_warning, NULL, NULL, NULL, "DO NOT power off during",
      "update,or it may cause", "irreversible malfunction", NULL);

  char delay_str[4] = "3s";
  for (int i = 2; i >= 0; i--) {
    oledclearLine(6);
    oledclearLine(7);
    delay_str[0] = '1' + i;
    oledDrawStringCenter(OLED_WIDTH / 2, 54, delay_str, FONT_STANDARD);
    oledRefresh();
    delay_ms(1000);
  }

  // unlock boot1's sectors
  // memory_write_unlock();

  for (uint8_t tries = 0; tries < 10; tries++) {
    // replace bootloader
    for (uint8_t isecs = FLASH_BOOT_SECTOR_FIRST;
         isecs <= FLASH_BOOT_SECTOR_LAST; isecs++) {
      flash_erase(isecs);
    }
    for (uint32_t items = 0; items < FLASH_BOOT_LEN / 4; items++) {
      const uint32_t *w = (const uint32_t *)(bl_data + items * 4);
      flash_write_word_item(FLASH_BOOT_START + items * 4, *w);
    }
    // check whether the write was OK
    r = memory_bootloader_hash(hash);
    if (r == 32 && 0 == memcmp(hash, bl_hash, 32)) {
      if (shutdown_on_replace) {
        // OK -> show info and halt
        layoutDialog(&bmp_icon_info, NULL, NULL, NULL, "Update finished",
                     "successfully.", NULL, "Please reconnect", "the device.",
                     NULL);
        shutdown();
      }
      return;
    }
  }
  // show info and halt
  layoutDialog(&bmp_icon_error, NULL, NULL, NULL, "Bootloader update",
               "broken.", NULL, "Unplug your OneKey", "contact our support.",
               NULL);
  delay_ms(1000);
  shutdown();
#endif
  // prevent compiler warning when PRODUCTION==0
  (void)shutdown_on_replace;
}
