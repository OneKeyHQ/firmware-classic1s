static void erase_code_progress(void) {
  flash_enter();
  for (int i = FLASH_CODE_SECTOR_FIRST; i <= FLASH_CODE_SECTOR_LAST; i++) {
    layoutProgress("Preparing...",
                   1000 * (i - FLASH_CODE_SECTOR_FIRST) /
                       (FLASH_CODE_SECTOR_LAST - FLASH_CODE_SECTOR_FIRST));
    ensure(flash_erase(i), "flash erase failed");
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
