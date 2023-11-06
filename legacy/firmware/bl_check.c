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
             "\xe3\xca\x51\x46\xd5\x57\x18\x49\x47\x45\x82\xa1\xbc\xfe\x76\xb0"
             "\x92\x68\x50\xe7\xbb\x68\x8f\xe7\xdd\x05\x99\xbc\x4e\x4e\xfe\xd6",
             32)) {
    memcpy(bootloader_version, "2.0.2", strlen("2.0.2"));
    return 1;  // 2.0.2 shipped with fw 3.4.0
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
             "\xfd\x01\x28\x10\x5e\x3c\xea\x6f\x4b\x6b\x4d\xd2\x1d\xca\x50\xcd"
             "\x19\x7b\xb2\x87\x38\x8a\xd9\x2a\xb3\x6b\xcd\x3e\xa0\x64\x75\x16",
             32)) {
    memcpy(bootloader_version, "2.0.2", strlen("2.0.2"));
    return 1;  // 2.0.2 shipped with fw 3.4.0
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
