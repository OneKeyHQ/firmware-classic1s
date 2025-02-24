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
             "\x80\xb8\x22\xf4\xd4\x08\x80\xfc\x90\x22\xc8\xe1\xb6\x75\x5b\xb0"
             "\x59\x51\x5b\x3b\x0b\x54\x61\x04\xbd\x37\xe3\xf1\x46\x06\x3a\xb2",
             32)) {
    memcpy(bootloader_version, "2.0.6", strlen("2.0.6"));
    return 1;  // 2.0.6 shipped with fw 3.5.0
  }
  if (0 ==
      memcmp(hash,
             "\xf1\xd1\x84\xfe\x18\xf4\x06\xa3\x8e\xde\xc9\x82\x9b\x98\x1d\x56"
             "\xcd\x71\xca\x3d\x7b\x71\x69\xd1\xe4\xf8\x8a\x8c\x5a\x64\x3a\xc1",
             32)) {
    memcpy(bootloader_version, "2.0.7", strlen("2.0.7"));
    return 1;  // 2.0.7 shipped with fw 3.5.0
  }
  if (0 ==
      memcmp(hash,
             "\x6d\x1a\x6c\x8d\x90\x74\xb2\x05\x07\x43\x1b\x84\xed\x94\xb5\x5d"
             "\x31\x48\xe4\x32\x9a\x79\xb4\x7e\xaa\xf1\x0e\xe4\x9b\x1f\x75\xd7",
             32)) {
    memcpy(bootloader_version, "2.0.8", strlen("2.0.8"));
    return 1;  // 2.0.8 shipped with fw 3.11.3
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
             "\xe4\xcf\xb4\x81\x66\x77\xc5\x65\xca\x73\x62\xf5\xf0\x13\x20\x95"
             "\x09\xc3\xb0\x8c\x71\x24\x27\x42\x0f\xc3\xac\xbc\xbb\xd8\xed\x5c",
             32)) {
    memcpy(bootloader_version, "2.0.6", strlen("2.0.6"));
    return 1;  // 2.0.6 shipped with fw 3.5.0
  }
  if (0 ==
      memcmp(hash,
             "\x45\xe1\x1f\x4d\x7d\x74\xf7\xc9\xaa\xa6\x71\xf5\x36\xe2\xc8\xd4"
             "\x8f\x5b\x1d\xa4\x71\x65\x78\x13\x6d\x6f\x68\x00\x6f\x9e\xd1\xcc",
             32)) {
    memcpy(bootloader_version, "2.0.7", strlen("2.0.7"));
    return 1;  // 2.0.7 shipped with fw 3.5.0
  }
  if (0 ==
      memcmp(hash,
             "\xf6\x98\x5a\xa0\xf3\xcf\x4a\x62\x85\xff\x4c\x63\x35\xbb\x6b\xf1"
             "\x94\x82\x0d\x3f\x49\xb8\x61\xb7\xb5\xef\x8b\x9e\x09\x07\x32\x55",
             32)) {
    memcpy(bootloader_version, "2.0.7", strlen("2.0.7"));
    return 1;  // 2.0.7 shipped with fw 3.7.0
  }
  if (0 ==
      memcmp(hash,
             "\xf5\xa6\x86\x65\x92\x2e\x94\x02\x84\x18\xee\xe9\x3a\xd8\xe0\xf6"
             "\xe1\xe9\x97\x5c\x54\x8d\x92\x55\x1a\x5c\x91\xa8\xba\xbb\x6b\x34",
             32)) {
    memcpy(bootloader_version, "2.0.8", strlen("2.0.8"));
    return 1;  // 2.0.8 shipped with fw 3.11.0
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
