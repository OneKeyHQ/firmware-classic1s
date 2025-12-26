#include "layout_boot.h"
#include "prompt.h"
#include "thd89_boot.h"

extern uint8_t se_state;

void layoutBootHome(void) {
  static uint32_t system_millis_logo_refresh = 0;
  if (layoutNeedRefresh()) {
    oledClear();
    oledDrawBitmap(20, 20, &bmp_boot_icon);
    // oledDrawStringCenter(85, 20, "OneKey", FONT_STANDARD);
#if BOOTLOADER_QA
    oledDrawString(50, 18, "Bootloader-QA", FONT_STANDARD);
#else
    oledDrawString(50, 18, "Bootloader", FONT_STANDARD);
#endif
    oledDrawString(50, 28,
                   VERSTR(VERSION_MAJOR) "." VERSTR(VERSION_MINOR) "." VERSTR(
                       VERSION_PATCH),
                   FONT_STANDARD);
    layoutFillBleName(7);
    oledRefresh();
  }

  if (layoutLast == layoutBlePasskey) {
    return;
  }
  // 1000 ms refresh
  if ((timer_ms() - system_millis_logo_refresh) >= 1000) {
#if !EMULATOR
    layoutStatusLogo();
    system_millis_logo_refresh = timer_ms();
    if (se_state == THD89_STATE_BOOT) {
      oledDrawStringCenter(OLED_WIDTH / 2, 50, "se in boot state",
                           FONT_STANDARD);
      oledRefresh();
    }
#endif
  }
}
