static void erase_code_progress(void) {
  flash_enter();
  // FLASH_FWHEADER_START is in sector 4 (FLASH_CODE_SECTOR_FIRST)
  // We need to skip erasing the 4KB page containing the firmware header
  // Sector 4 is 64KB, firmware header is at offset 0, so we skip the first 4KB
  // page Instead of erasing the whole sector, we'll erase everything except the
  // header page

  for (int i = FLASH_CODE_SECTOR_FIRST; i <= FLASH_CODE_SECTOR_LAST; i++) {
    layoutProgress("Preparing...",
                   1000 * (i - FLASH_CODE_SECTOR_FIRST) /
                       (FLASH_CODE_SECTOR_LAST - FLASH_CODE_SECTOR_FIRST));

    // Skip erasing sector 4's first 4KB page (contains firmware header)
    if (i == FLASH_CODE_SECTOR_FIRST) {
      // Use page erase to preserve the 4KB header at 0x08010000
      // Erase remaining 15 pages (60KB) from 0x08011000 to 0x0801FFFF
      for (uint32_t page_addr = 0x08011000; page_addr < 0x08020000;
           page_addr += 0x1000) {
        ensure(flash_page_erase(page_addr), "page erase failed");
      }
    } else {
      // Normal sector erase for other sectors
      ensure(flash_erase(i), "flash erase failed");
    }
  }
  for (int i = FLASH_SE_SECTOR_FIRST; i <= FLASH_SE_SECTOR_LAST; i++) {
    ensure(flash_erase(i), "flash erase failed");
  }
  layoutProgress("Installing...", 0);
  flash_exit();
}

static void erase_ble_code_progress(void) {
  flash_enter();
  for (int i = FLASH_BLE_SECTOR_FIRST; i <= FLASH_BLE_SECTOR_LAST; i++) {
    layoutProgress("Preparing...",
                   1000 * (i - FLASH_CODE_SECTOR_FIRST) /
                       (FLASH_CODE_SECTOR_LAST - FLASH_CODE_SECTOR_FIRST));
    ensure(flash_erase(i), "flash erase failed");
  }
  layoutProgress("Installing...", 0);
  flash_exit();
}
