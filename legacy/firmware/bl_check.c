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
             "\x17\x94\xa3\xfe\xf2\x32\xed\x05\xbc\x57\x21\xdf\xc4\x56\x0d\x62"
             "\x3d\xf2\xe0\xdb\x1d\xd9\xb8\x30\xc4\x76\x5d\x8a\x1a\x0d\xf9\x84",
             32)) {
    memcpy(bootloader_version, "2.0.1", strlen("2.0.1"));
    return 1;  // 2.0.1 shipped with fw 3.4.0
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
             "\x7d\xc2\x8c\x08\xce\x12\x60\x8d\x08\x1e\xc6\xd0\x89\x15\x8b\x1a"
             "\x10\xa1\xaf\x38\x57\x4d\xfb\x8f\x02\xf2\x03\xa0\xf7\xf8\x00\x59",
             32)) {
    memcpy(bootloader_version, "2.0.1", strlen("2.0.1"));
    return 1;  // 2.0.1 shipped with fw 3.4.0
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
    layoutDialog(&bmp_icon_error, NULL, NULL, NULL, _("Unknown bootloader"),
                 _("detected."), NULL, _("Shutdown your OneKey"),
                 _("contact our support."), NULL);
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
    layoutDialogCenterAdapterEx(NULL, NULL, NULL, NULL,
                                _("Get battery level..."), NULL, NULL, NULL);
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
        _("Low Battery!Use cable or"), _("Charge to 25% before"),
        _("updating the bootloader"), NULL);
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
      &bmp_icon_warning, NULL, NULL, NULL, _("DO NOT power off during"),
      _("update,or it may cause"), _("irreversible malfunction"), NULL);

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
        layoutDialog(&bmp_icon_info, NULL, NULL, NULL, _("Update finished"),
                     _("successfully."), NULL, _("Please reconnect"),
                     _("the device."), NULL);
        shutdown();
      }
      return;
    }
  }
  // show info and halt
  layoutDialog(&bmp_icon_error, NULL, NULL, NULL, _("Bootloader update"),
               _("broken."), NULL, _("Unplug your OneKey"),
               _("contact our support."), NULL);
  delay_ms(1000);
  shutdown();
#endif
  // prevent compiler warning when PRODUCTION==0
  (void)shutdown_on_replace;
}
