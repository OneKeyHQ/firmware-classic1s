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

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "bignum.h"
#include "bitmaps.h"
#include "ble.h"
#include "buttons.h"
#include "common.h"
#include "config.h"
#include "crypto.h"
#include "font.h"
#include "font_ex.h"
#include "fw_signatures.h"
#include "gettext.h"
#include "i18n/i18n.h"
#include "layout2.h"
#include "memory.h"
#include "memzero.h"
#include "menu_core.h"
#include "menu_list.h"
#include "messages.h"
#include "nem2.h"
#include "oled.h"
#include "oled_text.h"
#include "prompt.h"
#include "protect.h"
#include "qrcodegen.h"
#include "recovery.h"
#include "reset.h"
#include "se_chip.h"
#include "secp256k1.h"
#include "signing.h"
#include "sys.h"
#include "timer.h"
#include "util.h"

/* Display info timeout */
uint32_t system_millis_display_info_start = 0;
bool msg_command_inprogress = false;

#if !EMULATOR
static volatile uint8_t charge_dis_timer_counter = 0;
static volatile uint8_t dis_hint_timer_counter = 0;
static uint8_t charge_dis_counter_bak = 0;
static uint8_t cur_level_dis = 0xff;
static uint8_t dis_power_flag = 0;
#endif
static bool hide_icon = false;

bool use_dingmao = false;

#if !EMULATOR
void chargeDisTimer(void) {
  charge_dis_timer_counter =
      charge_dis_timer_counter > 8 ? 0 : charge_dis_timer_counter + 1;

  if ((sys_usbState() == true) && (dis_hint_timer_counter <= 14)) {
    dis_hint_timer_counter++;
  }
}
#endif
#define LOCKTIME_TIMESTAMP_MIN_VALUE 500000000

bool button_request(const ButtonRequestType code);
void hide_icons(bool hide) { hide_icon = hide; }
static uint8_t layoutPagination(char *title, char *content);
static void layoutDialogCenterStrict(const BITMAP *bmp_no,
                                     const BITMAP *bmp_yes, const char *desc);

const char *address_n_str(const uint32_t *address_n, size_t address_n_count,
                          bool address_is_account) {
  (void)address_is_account;
  if (address_n_count > 8) {
    return "Unknown long path";
  }
  if (address_n_count == 0) {
    return "Path: m";
  }

  //                  "Path: m"    /    i   '
  static char address_str[7 + 8 * (1 + 10 + 1) + 1];
  char *c = address_str + sizeof(address_str) - 1;

  *c = 0;
  c--;

  for (int n = (int)address_n_count - 1; n >= 0; n--) {
    uint32_t i = address_n[n];
    if (i & PATH_HARDENED) {
      *c = '\'';
      c--;
    }
    i = i & PATH_UNHARDEN_MASK;
    do {
      *c = '0' + (i % 10);
      c--;
      i /= 10;
    } while (i > 0);
    *c = '/';
    c--;
  }
  *c = 'm';

  return c;
}

// split longer string into 6 rows, rowlen chars each
const char **split_message(const uint8_t *msg, uint32_t len, uint32_t rowlen) {
  static char str[6][32 + 1];
  if (rowlen > 32) {
    rowlen = 32;
  }

  memzero(str, sizeof(str));
  for (int i = 0; i < 6; ++i) {
    size_t show_len = strnlen((char *)msg, MIN(rowlen, len));
    memcpy(str[i], (char *)msg, show_len);
    str[i][show_len] = '\0';
    msg += show_len;
    len -= show_len;
  }

  // if (len > 0) {
  //   str[3][rowlen - 1] = '.';
  //   str[3][rowlen - 2] = '.';
  //   str[3][rowlen - 3] = '.';
  //   str[3][rowlen - 4] = '.';
  //   str[3][rowlen - 5] = '.';
  // }
  static const char *ret[6] = {str[0], str[1], str[2], str[3], str[4], str[5]};
  return ret;
}

const char **split_message_hex(const uint8_t *msg, uint32_t len) {
  char hex[32 * 2 + 1] = {0};
  memzero(hex, sizeof(hex));
  uint32_t size = len;
  if (len > 32) {
    size = 32;
  }
  data2hex(msg, size, hex);
  if (len > 32) {
    hex[63] = '.';
    hex[62] = '.';
  }
  return split_message((const uint8_t *)hex, size * 2, 16);
}

void short_line_message(const char *msg, char *buf) {
  if (oledStringWidthAdapter(msg, FONT_STANDARD) < OLED_WIDTH) {
    strcpy(buf, msg);
  } else {
    const char ellipsis[] = "..";
    int ellipsis_len =
        oledStringWidthAdapter(ellipsis, FONT_STANDARD);  // space

    int left_width = 0, right_width = 0;
    int left_index = 0, right_index = strlen(msg) - 1;

    int split_width = (OLED_WIDTH - ellipsis_len) / 2;

    while ((left_width < split_width) && (left_index < right_index)) {
      left_width += oledCharWidthEx(msg[left_index++], FONT_STANDARD);
    }
    while ((right_width < split_width) && (right_index > left_index)) {
      right_width += oledCharWidthEx(msg[right_index--], FONT_STANDARD);
    }
    strncpy(buf, msg, left_index - 1);
    strcat(buf, ellipsis);
    strcat(buf, msg + right_index + 2);
  }
}

int get_truncate_position(const char *msg, bool *is_end) {
  int width = 0;
  int index = 0;
  while (msg[index] != '\0' && width <= OLED_WIDTH) {
    width += oledCharWidthEx(msg[index], FONT_STANDARD);
    if (width > OLED_WIDTH) {
      *is_end = false;
      return index;
    }
    index++;
  }
  *is_end = (msg[index] == '\0');
  return index;  // Return the position where the string fits in one line
}

static int countlines(char *text) {
  string_lines_t lines = split_string_to_lines(text, OLED_WIDTH, FONT_STANDARD);
  return lines.line_count;
}

void layout_index_count(int index, int count) {
  char index_str[16] = "";
  uint2str(index, index_str);
  strcat(index_str + strlen(index_str), "/");
  uint2str(count, index_str + strlen(index_str));
  int l = oledStringWidthAdapter(index_str, FONT_SMALL);
  oledDrawStringAdapter(OLED_WIDTH / 2 - l / 2, OLED_HEIGHT - 8, index_str,
                        FONT_SMALL);
}

void *layoutLast = NULL;

void layoutDialogSwipeWrapping(const BITMAP *icon, const char *btnNo,
                               const char *btnYes, const char *heading,
                               const char *description, const char *wrap_text) {
  const uint32_t row_len = 18;
  const char **str =
      split_message((const uint8_t *)wrap_text, strlen(wrap_text), row_len);
  layoutDialogSwipe(icon, btnNo, btnYes, NULL, heading, description, str[0],
                    str[1], str[2], str[3]);
}

const char **format_tx_message(const char *chain_name) {
  static char str[2][128 + 1];

  memzero(str, sizeof(str));
  snprintf(str[0], 128, "%s", _(T__STR_CHAIN_TRANSACTION));
  bracket_replace(str[0], chain_name);
  snprintf(str[1], 128, "%s",
           _(C__DO_YOU_WANT_TO_SIGN_THIS_CHAIN_STR_TRANSACTION_QUES));
  bracket_replace(str[1], chain_name);

  static const char *ret[2] = {str[0], str[1]};
  return ret;
}

void layoutDialogSwipe(const BITMAP *icon, const char *btnNo,
                       const char *btnYes, const char *desc, const char *line1,
                       const char *line2, const char *line3, const char *line4,
                       const char *line5, const char *line6) {
  layoutDialogSwipeEx(icon, btnNo, btnYes, desc, line1, line2, line3, line4,
                      line5, line6, FONT_STANDARD);
}

void layoutDialogSwipeEx(const BITMAP *icon, const char *btnNo,
                         const char *btnYes, const char *desc,
                         const char *line1, const char *line2,
                         const char *line3, const char *line4,
                         const char *line5, const char *line6, uint8_t font) {
  layoutLast = layoutDialogSwipe;
  (void)font;
  layoutSwipe();
  layoutDialogAdapter(icon, btnNo, btnYes, desc, line1, line2, line3, line4,
                      line5, line6);
}

void layoutProgressSwipe(const char *desc, int permil) {
  if (layoutLast == layoutProgressSwipe) {
    oledClear_ex();
  } else {
    layoutLast = layoutProgressSwipe;
    layoutSwipe();
  }
  layoutProgressAdapter(desc, permil);
}

void layoutScreensaver(void) {
  if (system_millis_busy_deadline > timer_ms()) {
    // Busy screen overrides the screensaver.
    layoutBusyscreen();
  } else {
    layoutLast = layoutScreensaver;
    oledClear();
    oledRefresh();
  }
}

void layoutLabel(char *label) {
  oledDrawStringCenterAdapter(OLED_WIDTH / 2, 16, label, FONT_STANDARD);
}
#if !EMULATOR
void getBleDevInformation(void) {
  if (!ble_name_state()) {
    ble_request_info(BLE_CMD_BT_NAME);
    delay_ms(5);
  }
  if (!ble_ver_state()) {
    ble_request_info(BLE_CMD_VER);
    delay_ms(5);
  }
  if (!ble_battery_state()) {
    ble_request_info(BLE_CMD_BATTERY);
    delay_ms(5);
  }
  if (!ble_switch_state()) {
    ble_request_switch_state();
    delay_ms(5);
  }
  if (ble_ver_state()) {  // > 1.5.1
    if (strcmp(ble_get_ver(), "1.5.1") > 0) {
      if (!ble_build_id_state()) {
        ble_request_info(BLE_CMD_BUILD_ID);
        delay_ms(5);
      }
      if (!ble_hash_state()) {
        ble_request_info(BLE_CMD_HASH);
        delay_ms(5);
      }
    }
  }
}

void disPcConnectTips(void) {
  layoutDialogCenterAdapterV2(
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__DATA_TRANSFER_MODE_USE_A_CHARGER_IF_YOU_WANNA_FASTER_CHARGING));
}
void disPowerChargeTips(void) {
  layoutDialogCenterAdapterV2(
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__SPEED_UP_CHARGING_WITH_5V_AND_200MA_CHARGE_HEAD_EXCLAM));
}
void disUsbConnectTips(void) {
  if (ble_hw_ver_is_pure()) {
    return;
  }
  oledClear();
  if (usb_connect_status == 1) {
    disPcConnectTips();
  } else {
    disPowerChargeTips();
  }
}
void refreshBatteryFlash(int offset_x) {
  if (charge_dis_counter_bak != charge_dis_timer_counter) {
    charge_dis_counter_bak = charge_dis_timer_counter;
    if (cur_level_dis == 0xff) {
      cur_level_dis = battery_cap;
    }
    cur_level_dis = cur_level_dis >= 4 ? battery_cap : cur_level_dis + 1;
  }
  disBatteryLevel(offset_x, cur_level_dis);
}

void refreshUsbConnectTips(void) {
  if ((dis_power_flag == 0) && (dis_hint_timer_counter == 4)) {
    dis_power_flag = 1;
    disUsbConnectTips();
  }

  if ((dis_power_flag == 1) && (dis_hint_timer_counter == 8)) {
    dis_hint_timer_counter = 15;
    layoutRefreshSet(true);
  }
}
void layoutStatusLogoEx(bool fresh) {
#if !EMULATOR
  if (hide_icon) return;
  if (ble_passkey_state()) return;
#endif

  static int logo_width = 0;
  int offset_x = 0;

  if (logo_width == 0) {
    logo_width = ble_hw_ver_is_pure()
                     ? STATUS_LOGO_WIDTH_MAX - BATTERY_LOGO_WIDTH
                     : STATUS_LOGO_WIDTH_MAX;
  }

  getBleDevInformation();

  oledBox(OLED_WIDTH - logo_width, 0, OLED_WIDTH, LOGO_HEIGHT - 1, false);

  if (sys_usbState()) {
    offset_x += LOGO_WIDTH;
    oledDrawBitmap(OLED_WIDTH - offset_x, 0, &bmp_status_charge);
  }

  if (!ble_hw_ver_is_pure()) {
    offset_x += BATTERY_LOGO_WIDTH;
    if (sys_usbState()) {
      refreshBatteryFlash(OLED_WIDTH - offset_x);
    } else {
      disBatteryLevel(OLED_WIDTH - offset_x, battery_cap);
    }
  }

  if (sys_usbState() == false) {
    usb_connect_status = 0;
  }
  if (usb_connect_status) {
    offset_x += LOGO_WIDTH;
    oledDrawBitmap(OLED_WIDTH - offset_x, 0, &bmp_status_usb);
  }

  offset_x += LOGO_WIDTH;

  if (sys_bleState() == true) {
    oledDrawBitmap(OLED_WIDTH - offset_x, 0, &bmp_status_ble_connect);
  } else if (ble_get_switch() == true) {
    oledDrawBitmap(OLED_WIDTH - offset_x, 0, &bmp_status_ble);
  }

  if (fresh) {
    oledRefresh();
  }
}

#endif

void drawScrollbar(int pages, int index) {
  int i, bar_start = 12, bar_end = 52;
  int bar_heght = MAX((40 - 2 * (pages - 1)), 6);
  for (i = bar_start; i < bar_end; i += 2) {  // 40 pixel
    oledDrawPixel(OLED_WIDTH - 1, i);
  }
  for (i = bar_start + 2 * ((int)index);
       i < (bar_start + bar_heght + 2 * ((int)index)) - 1; i++) {
    oledDrawPixel(OLED_WIDTH - 1, i);
    oledDrawPixel(OLED_WIDTH - 2, i);
  }
}

void drawScrollbar_ext(int pages, int index, int bar_start) {
  int i, bar_end = 52;
  int bar_heght = MAX((40 - 2 * (pages - 1)), 6);
  for (i = bar_start; i < bar_end; i += 2) {  // 40 pixel
    oledDrawPixel(OLED_WIDTH - 1, i);
  }
  if (index <= 12) {
    for (i = bar_start + 2 * ((int)index);
         i < (bar_start + bar_heght + 2 * ((int)index)) - 1; i++) {
      oledDrawPixel(OLED_WIDTH - 1, i);
      oledDrawPixel(OLED_WIDTH - 2, i);
    }
  } else {
    for (i = bar_start + 2 * 12; i < (bar_start + bar_heght + 2 * (12 - 1)) - 1;
         i++) {
      oledDrawPixel(OLED_WIDTH - 1, i);
      oledDrawPixel(OLED_WIDTH - 2, i);
    }
  }
}

void layout_language_set(uint8_t key) {
  static int index = 0;

  if (0 == ui_language) {
    config_setLanguage(i18n_lang_keys[1]);  // dingmao_9x9
  }

  layout_item_t items[I18N_LANGUAGE_ITEMS] = {
      {.label = i18n_langs[0], .value = NULL, .center = true},
      {.label = i18n_langs[1], .value = NULL, .center = true},
      {.label = i18n_langs[2], .value = NULL, .center = true},
      {.label = i18n_langs[3], .value = NULL, .center = true},
      {.label = i18n_langs[4], .value = NULL, .center = true},
      {.label = i18n_langs[5], .value = NULL, .center = true},
      {.label = i18n_langs[6], .value = NULL, .center = true},
      {.label = i18n_langs[7], .value = NULL, .center = true},
  };

  layout_screen_t screen = {
      .bmp_up = NULL,
      .bmp_down = NULL,
      .bmp_no = NULL,
      .bmp_yes = &bmp_bottom_right_arrow,
      .btn_no = NULL,
      .btn_yes = NULL,
      .title = "Select Language",
      .title_space = true,
      .input_desc = NULL,
      .items = items,
      .item_count = I18N_LANGUAGE_ITEMS,
      .item_index = 0,
      .item_offset = 0,
      .show_index = true,
      .show_scroll_bar = false,
  };

  screen.item_index = index;
  layout_screen(screen);

  switch (key) {
    case KEY_UP:
      if (index > 0) {
        index--;
      }
      break;
    case KEY_DOWN:
      if (index < I18N_LANGUAGE_ITEMS - 1) {
        index++;
      }
      break;
    case KEY_CONFIRM:
      config_setLanguage(i18n_lang_keys[index]);
      return;
    default:
      return;
  }
}

static void layoutWelcome(int index) {
  char h[64] = "";
  char line1[64] = "", line2[64] = "";
  int line1_len = 0, line2_len = 0, x = 0, offset = 0;

  oledClear_ex();
  layoutHeader(_(T__WELCOME_TO_ONEKEY_EXCLAM));

  if (0 == index) {
    snprintf(line1, 64, "%s", _(C__PRESS_BACK_KEY_TO_GO_BACK));
    snprintf(line2, 64, "%s", _(C__PRESS_POWER_KEY_TO_CONTINUE));
    line1_len = strlen(_(C__PRESS_BACK_KEY_TO_GO_BACK));
    line2_len = strlen(_(C__PRESS_POWER_KEY_TO_CONTINUE));

    if (line1_len > line2_len) {
      x = oledDrawStringCenterAdapterX(OLED_WIDTH / 2, 20, line1,
                                       FONT_STANDARD);
      oledDrawStringAdapter(x, 20, line1, FONT_STANDARD);
      oledDrawStringAdapter(x, 34, line2, FONT_STANDARD);
      char *str = strstr(line1, " ");
      memcpy(h, line1, str - line1);
      offset = x + oledStringWidthAdapter(h, FONT_STANDARD);
    } else {
      x = oledDrawStringCenterAdapterX(OLED_WIDTH / 2, 20, line2,
                                       FONT_STANDARD);
      oledDrawStringAdapter(x, 20, line1, FONT_STANDARD);
      oledDrawStringAdapter(x, 34, line2, FONT_STANDARD);
      char *str = strstr(line2, " ");
      memcpy(h, line2, str - line2);
      offset = x + oledStringWidthAdapter(h, FONT_STANDARD);
    }

    if (ui_language == 0) {
      oledDrawBitmap(offset, 19, &bmp_icon_exit);
      oledDrawBitmap(offset, 33, &bmp_icon_enter);
    } else {
      oledDrawBitmap(offset, 20, &bmp_icon_exit);
      oledDrawBitmap(offset, 34, &bmp_icon_enter);
    }

    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
    oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_arrow);
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_arrow);
  } else {
    layout_index_count(index, 7);
    if (1 == index) {
      oledDrawBitmap((OLED_WIDTH - bmp_Icon_fc.width) / 2, 8, &bmp_Icon_fc);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 44, "FCC ID: 2BB8VC1",
                                  FONT_STANDARD);
      layoutHeader(_(T__WELCOME_TO_ONEKEY_EXCLAM));
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
    } else if (2 == index) {
      oledDrawBitmap((OLED_WIDTH - bmp_Icon_bc.width) / 2, 13, &bmp_anatel);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 46, "22316-23-16343",
                                  FONT_STANDARD);
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
    } else if (3 == index) {
      oledDrawBitmap((OLED_WIDTH - bmp_Icon_bc.width) / 2, 13, &bmp_Icon_bc);
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
    } else if (4 == index) {
      oledDrawBitmap(20, 13, &bmp_Icon_ce);
      oledDrawBitmap(72, 13, &bmp_Icon_weee);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
    } else if (5 == index) {
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
      oledDrawStringAdapter(0, 16, _(I__PRODUCT_NAME_UPPERCASE_COLON),
                            FONT_STANDARD);
      oledDrawStringAdapter(0, 25, config_get_device_model(), FONT_STANDARD);
      oledDrawStringAdapter(0, 34, _(I__MODEL_UPPERCASE_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 43, "C1", FONT_STANDARD);
    } else if (6 == index) {
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
      oledDrawStringAdapter(0, 16, _(I__BRAND_NAME_UPPERCASE_COLON),
                            FONT_STANDARD);
      oledDrawStringAdapter(0, 25, "OneKey", FONT_STANDARD);
      oledDrawStringAdapter(0, 34, _(I__COUNTRY_OF_ORIGIN_UPPERCASE_COLON),
                            FONT_STANDARD);
      oledDrawStringAdapter(0, 43, "Made in China", FONT_STANDARD);
    } else if (7 == index) {
      char *se_sn = NULL;
      se_get_sn(&se_sn);

      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
      oledDrawStringAdapter(0, 16, _(I__SERIAL_NUMBER_UPPERCASE_COLON),
                            FONT_STANDARD);
      oledDrawStringAdapter(0, 25, se_sn, FONT_STANDARD);
      oledDrawStringAdapter(0, 34, _(I__CERTIFICATION_NUMBER_UPPERCASE_COLON),
                            FONT_STANDARD);
      oledDrawStringAdapter(0, 43, "22316-23-16343", FONT_STANDARD);
    }
    drawScrollbar(7, index - 1);
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_arrow);
  }
  oledRefresh();
}

static int setup_wallet(uint8_t key) {
  static int index = 0;

  layout_item_t items[2] = {
      {.label = _(O__CREATE_NEW_WALLET), .value = NULL, .center = true},
      {.label = _(O__IMPORT_WALLET), .value = NULL, .center = true},
  };

  layout_screen_t screen = {
      .bmp_up = &bmp_bottom_middle_arrow_up,
      .bmp_down = &bmp_bottom_middle_arrow_down,
      .bmp_no = &bmp_bottom_left_arrow,
      .bmp_yes = &bmp_bottom_right_arrow,
      .btn_no = NULL,
      .btn_yes = NULL,
      .title = _(T__SET_UP),
      .title_space = true,
      .items = items,
      .item_count = 2,
      .item_index = index,
      .item_offset = 0,
      .show_index = false,
      .show_scroll_bar = false,
  };

  layout_screen(screen);

  switch (key) {
    case KEY_UP:
      if (index > 0) index--;
      break;
    case KEY_DOWN:
      if (index < 1) index++;
      break;
    case KEY_CONFIRM:
      break;
    default:
      break;
  }
  return index;
}

void onboarding(uint8_t key) {
  int x, l, pages = 5, line_num = 0;
  static int index = 0, welcome_index = 0;
  static int type = 0;
  static bool get_ble_name = true;
  int height = font_get_height(), offset = 0;
  layoutLast = onboarding;
  if (get_ble_name) {
#if !EMULATOR
    getBleDevInformation();
#endif
    get_ble_name = false;
  }

  switch (index) {
    case 0:
      layout_language_set(key);
      break;
    case 1:
      layoutWelcome(welcome_index);
      break;
    case 2:
      layoutDialogCenterAdapterV2(
          _(T__QUICK_START), NULL, &bmp_bottom_left_arrow,
          &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
          _(C__NEXT_FOLLOW_THE_ONSCREEN_INSTRUCTIONS_TO_SET_UP_YOUR_ONEKEY_CLASSIC));
      break;
    // case 3:
    //   layoutDialogAdapterEx(
    //       _("Authenticity Check"), &bmp_bottom_left_arrow, _("Back"),
    //       &bmp_bottom_right_arrow, _("Next"),
    //       _("Want to check authenticity\nof this device? Go to the \nwebsite
    //       "
    //         "below for help:\nonekey.so/auth"),
    //       NULL, NULL, NULL, NULL);
    //   break;
    case 3:
      type = setup_wallet(key);
      break;
    case 4:
      if (0 == type) {
        // Create New Wallet
        reset_on_device();
      } else {
        // Import Wallet
        recovery_on_device();
      }
      if (config_isInitialized()) {
        layoutLast = onboarding;
      done1:
        layoutDialogCenterAdapterV2(
            _(T__CONGRATULATIONS_EXCLAM), NULL, NULL, &bmp_bottom_right_arrow,
            NULL, NULL, NULL, NULL, NULL, NULL,
            _(C__WALLET_IS_READY_EXCLAM_DOWNLOAD_ONEKEY_APPS_AND_HAVE_FUN_WITH_YOUR_ONEKEY_CLASSIC));
        key = protectWaitKey(0, 1);
        if (protectAbortedByInitializeOnboarding) return;
        if (key != KEY_CONFIRM) {
          goto done1;
        }

      done2:
        layoutDialogCenterAdapterV2(
            _(T__DOWNLOAD_ONEKEY_APPS), NULL, &bmp_bottom_left_arrow,
            &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
            _(C__DOWNLOAD_ONEKEY_APPS_AT_COLON_ONEKEY_SO_DOWNLOAD));
        l = oledStringWidthAdapter("onekey.so/download", FONT_STANDARD);
        line_num =
            countlines(_(C__DOWNLOAD_ONEKEY_APPS_AT_COLON_ONEKEY_SO_DOWNLOAD));
        x = oledDrawStringCenterAdapterX(OLED_WIDTH / 2, 10,
                                         "onekey.so/download", FONT_STANDARD);

        offset = line_num <= 3 ? 17 : 13;
        offset += height * line_num;
        oledBox(x, offset, x + l, offset, true);
        oledRefresh();
        key = protectWaitKey(0, 1);
        if (protectAbortedByInitializeOnboarding) return;
        if (key != KEY_CONFIRM) {
          goto done1;
        }

        layoutDialogCenterAdapterV2(
            _(T__SUPPORT), NULL, &bmp_bottom_left_arrow,
            &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
            _(C__ANY_QUESTIONS_QUES_VISIT_HELP_CENTER_FOR_SOLUTIONS_COLON_HELP_ONEKEY_SO));
        l = oledStringWidthAdapter("help.onekey.so", FONT_STANDARD);
        line_num = countlines(_(
            C__ANY_QUESTIONS_QUES_VISIT_HELP_CENTER_FOR_SOLUTIONS_COLON_HELP_ONEKEY_SO));
        x = oledDrawStringCenterAdapterX(OLED_WIDTH / 2, 10, "help.onekey.so",
                                         FONT_STANDARD);
        offset = line_num <= 3 ? 17 : 13;
        offset += height * line_num;
        oledBox(x, offset, x + l, offset, true);
        oledRefresh();
        key = protectWaitKey(0, 1);
        if (protectAbortedByInitializeOnboarding) return;
        if (key != KEY_CONFIRM) {
          goto done2;
        }

        layoutDialogCenterAdapterV2(
            _(T__DONE_EXCLAM), NULL, NULL, &bmp_bottom_right_confirm, NULL,
            NULL, NULL, NULL, NULL, NULL,
            _(C__ONEKEY_CLASSIC_IS_SET_UP_IT_WILL_BACK_TO_HOME_SCREEN));
        protectWaitKey(0, 0);
        index = 0;
        layoutHome();
      } else {
        index = 3;
        layoutLast = onboarding;
        break;
      }
      break;
    default:
      break;
  }

  switch (key) {
    case KEY_UP:
      if ((index == 1) && (welcome_index > 0)) {  // welcome
        welcome_index--;
      }
      break;
    case KEY_DOWN:
      if ((index == 1) && (welcome_index < 7)) {  // welcome
        welcome_index++;
      }
      break;
    case KEY_CONFIRM:
      if ((index == 1) && (welcome_index != 0) && (welcome_index < 7)) {
        welcome_index++;
        break;
      }
      if (index < pages - 1) {
        index++;
      }
      break;
    case KEY_CANCEL:
      if ((index == 1) && (welcome_index != 0)) break;
      if (index > 0) {
        index--;
      }
      welcome_index = 0;
      break;
    default:
      break;
  }
}

static void _layout_home(bool update_menu) {
  if (layoutLast == layoutHome || layoutLast == layoutScreensaver) {
    oledClear_ex();
  } else {
    layoutSwipe();
  }
  layoutLast = layoutHome;

  bool no_backup = false;
  bool unfinished_backup = false;
  bool needs_backup = false;
  config_getNoBackup(&no_backup);
  config_getUnfinishedBackup(&unfinished_backup);
  config_getNeedsBackup(&needs_backup);
  uint8_t homescreen[HOMESCREEN_SIZE] = {0};
  if (config_getHomescreen(homescreen, sizeof(homescreen))) {
    BITMAP b = {0};
    b.width = 128;
    b.height = 64;
    b.data = homescreen;
    oledDrawBitmap(0, 0, &b);
    const int bar_height = 12;
    oledBox(0, OLED_HEIGHT - bar_height, OLED_WIDTH - 1, OLED_HEIGHT - 1,
            false);

    oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                   &bmp_bottom_right_arrow);

    if (session_isUnlocked() || !config_hasPin()) {
      oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_lock);
    }

    if (session_isUnlocked() || !config_hasPin()) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 10,
                                  ble_get_name(), FONT_STANDARD);
    } else {
      if (no_backup) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 9, "SEEDLESS",
                                    FONT_STANDARD);
      } else if (unfinished_backup) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 9,
                                    "BACKUP FAILED!", FONT_STANDARD);
      } else if (needs_backup) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 9,
                                    "Need Backup", FONT_STANDARD);
      } else {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 10,
                                    ble_get_name(), FONT_STANDARD);
      }
    }
  } else {
    char label[MAX_LABEL_LEN + 1] = "";
    config_getLabel(label, sizeof(label));
    oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                   &bmp_bottom_right_arrow);
    if (session_isUnlocked() || !config_hasPin()) {
      oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_lock);
    }
    if (session_isUnlocked() || !config_hasPin()) {
      oledDrawBitmap(52, 0, &bmp_onekey_logo);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 29, label, FONT_STANDARD);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 10,
                                  ble_get_name(), FONT_STANDARD);
    } else {
      oledDrawBitmap(128 / 2 - 4, 0, &bmp_status_locked);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 19, label, FONT_STANDARD);
      if (no_backup) {
        oledBox(0, OLED_HEIGHT - 8, 127, 8, false);
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 9, "SEEDLESS",
                                    FONT_STANDARD);
      } else if (unfinished_backup) {
        oledBox(0, OLED_HEIGHT - 8, 127, 8, false);
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 9,
                                    "BACKUP FAILED!", FONT_STANDARD);
      } else if (needs_backup) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 9,
                                    "Need Backup", FONT_STANDARD);
      } else {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 10,
                                    ble_get_name(), FONT_STANDARD);
      }
    }
  }

  oledRefresh();

  bool initialized = config_isInitialized();

  if (update_menu && initialized) {
    main_menu_init(initialized);
  }
  if (!initialized && !se_isFactoryMode()) {
    layoutLast = onboarding;
  }

  hide_icon = false;

  // Reset lock screen timeout
  system_millis_lock_start = timer_ms();
}

void layoutBusyscreen(void) {
  if (layoutLast == layoutBusyscreen || layoutLast == layoutScreensaver) {
    oledClear();
  } else {
    layoutSwipe();
  }
  layoutLast = layoutBusyscreen;

  layoutDialog(&bmp_icon_warning, NULL, NULL, NULL, _(C__PLEASE_WAIT), NULL,
               "Coinjoin in progress.", NULL, "Do not disconnect",
               "your OneKey.");
}

void layoutHome(void) {
#if !EMULATOR
  static bool first_boot = true;
  if (first_boot && !config_isInitialized() && !se_isFactoryMode()) {
    first_boot = false;
    onboarding(KEY_UP);
  } else
#endif
  {
    _layout_home(true);
  }
}

void layoutHomeEx(void) { _layout_home(false); }

static void render_address_dialog(const CoinInfo *coin, const char *address,
                                  const char *line1, const char *line2,
                                  const char *extra_line) {
  if (coin && coin->cashaddr_prefix) {
    /* If this is a cashaddr address, remove the prefix from the
     * string presented to the user
     */
    int prefix_len = strlen(coin->cashaddr_prefix);
    if (strncmp(address, coin->cashaddr_prefix, prefix_len) == 0 &&
        address[prefix_len] == ':') {
      address += prefix_len + 1;
    }
  }
  int addrlen = strlen(address);
  int numlines = addrlen <= 42 ? 2 : 3;
  int linelen = (addrlen - 1) / numlines + 1;
  if (linelen > 21) {
    linelen = 21;
  }
  const char **str = split_message((const uint8_t *)address, addrlen, linelen);
  layoutLast = layoutDialogSwipe;
  layoutSwipe();
  oledClear_ex();
  oledDrawBitmap(0, 0, &bmp_icon_question);
  oledDrawStringAdapter(20, 0 * 9, line1, FONT_STANDARD);
  oledDrawStringAdapter(20, 1 * 9, line2, FONT_STANDARD);
  int left = linelen > 18 ? 0 : 20;
  oledDrawStringAdapter(left, 2 * 9, str[0], FONT_FIXED);
  oledDrawStringAdapter(left, 3 * 9, str[1], FONT_FIXED);
  oledDrawStringAdapter(left, 4 * 9, str[2], FONT_FIXED);
  oledDrawStringAdapter(left, 5 * 9, str[3], FONT_FIXED);
  if (!str[3][0]) {
    if (extra_line) {
      oledDrawStringAdapter(0, 5 * 9, extra_line, FONT_STANDARD);
    } else {
      oledHLine(OLED_HEIGHT - 13);
    }
  }
  layoutButtonNoAdapter("Cancel", &bmp_btn_cancel);
  layoutButtonYesAdapter("Confirm", &bmp_btn_confirm);
  oledRefresh();
}

static size_t format_coin_amount(uint64_t amount, const char *prefix,
                                 const CoinInfo *coin, AmountUnit amount_unit,
                                 char *output, size_t output_len) {
  // " " + (optional "m"/u") + shortcut + ending zero -> 16 should suffice
  char suffix[16];
  memzero(suffix, sizeof(suffix));
  suffix[0] = ' ';
  uint32_t decimals = coin->decimals;
  switch (amount_unit) {
    case AmountUnit_SATOSHI:
      decimals = 0;
      strlcpy(suffix + 1, "sat", sizeof(suffix) - 1);
      if (strcmp(coin->coin_shortcut, "BTC") != 0) {
        strlcpy(suffix + 4, " ", sizeof(suffix) - 4);
        strlcpy(suffix + 5, coin->coin_shortcut, sizeof(suffix) - 5);
      }
      break;
    case AmountUnit_MILLIBITCOIN:
      if (decimals >= 6) {
        decimals -= 6;
        suffix[1] = 'u';
        strlcpy(suffix + 2, coin->coin_shortcut, sizeof(suffix) - 2);
      } else {
        strlcpy(suffix + 1, coin->coin_shortcut, sizeof(suffix) - 1);
      }
      break;
    case AmountUnit_MICROBITCOIN:
      if (decimals >= 3) {
        decimals -= 3;
        suffix[1] = 'm';
        strlcpy(suffix + 2, coin->coin_shortcut, sizeof(suffix) - 2);
      } else {
        strlcpy(suffix + 1, coin->coin_shortcut, sizeof(suffix) - 1);
      }
      break;
    default:  // AmountUnit_BITCOIN
      strlcpy(suffix + 1, coin->coin_shortcut, sizeof(suffix) - 1);
      break;
  }
  return bn_format_amount(amount, prefix, suffix, decimals, output, output_len);
}

bool layoutConfirmOutput(const CoinInfo *coin, AmountUnit amount_unit,
                         const TxOutputType *out) {
  int index = 0;
  uint8_t key = KEY_NULL;
  uint8_t pages = 2;
  char title[65] = {0};
  char str_out[32 + 3] = {0};
  char desc[32] = {0};

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  snprintf(title, 65, "%s", _(T__STR_CHAIN_TRANSACTION));
  bracket_replace(title, coin->coin_name);
  strcat(desc, _(I__AMOUNT_COLON));

  format_coin_amount(out->amount, NULL, coin, amount_unit, str_out,
                     sizeof(str_out) - 3);
  const char *address = out->address;
  const char *extra_line =
      (out->address_n_count > 0)
          ? address_n_str(out->address_n, out->address_n_count, false)
          : 0;
  if (coin && coin->cashaddr_prefix) {
    /* If this is a cashaddr address, remove the prefix from the
     * string presented to the user
     */
    int prefix_len = strlen(coin->cashaddr_prefix);
    if (strncmp(address, coin->cashaddr_prefix, prefix_len) == 0 &&
        address[prefix_len] == ':') {
      address += prefix_len + 1;
    }
  }
  if (extra_line) pages++;

refresh_menu:
  oledClear();
  layoutHeader(title);
  if (((bool)extra_line ? 2 : 1) == index) {
    oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, str_out, FONT_STANDARD);
  } else if (0 == index) {
    oledDrawStringAdapter(0, 13, _(I__SEND_TO_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, address, FONT_STANDARD);
  } else if (1 == index && (bool)extra_line) {
    oledDrawStringAdapter(0, 13, _(I__SEND_TO_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, extra_line, FONT_STANDARD);
  }

  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  oledRefresh();

  WAIT_KEY_OR_ABORT(0, 0, key);
  switch (key) {
    case KEY_UP:
      goto refresh_menu;
    case KEY_DOWN:
      goto refresh_menu;
    case KEY_CONFIRM:
      if (index == pages - 1) {
        return true;
      }
      if (index < pages - 1) {
        index++;
      }
      goto refresh_menu;
    case KEY_CANCEL:
      return false;
    default:
      return false;
  }

  return true;
}

void layoutConfirmOmni(const uint8_t *data, uint32_t size) {
  const char *desc = NULL;
  char str_out[32] = {0};
  uint32_t tx_type = 0, currency = 0;
  REVERSE32(*(const uint32_t *)(data + 4), tx_type);
  if (tx_type == 0x00000000 && size == 20) {  // OMNI simple send
    desc = "Simple send of ";
    REVERSE32(*(const uint32_t *)(data + 8), currency);
    const char *suffix = " UNKN";
    bool divisible = false;
    switch (currency) {
      case 1:
        suffix = " OMNI";
        divisible = true;
        break;
      case 2:
        suffix = " tOMNI";
        divisible = true;
        break;
      case 3:
        suffix = " MAID";
        divisible = false;
        break;
      case 31:
        suffix = " USDT";
        divisible = true;
        break;
    }
    uint64_t amount_be = 0, amount = 0;
    memcpy(&amount_be, data + 12, sizeof(uint64_t));
    REVERSE64(amount_be, amount);
    bn_format_amount(amount, NULL, suffix, divisible ? 8 : 0, str_out,
                     sizeof(str_out));
  } else {
    desc = "Unknown transaction";
    str_out[0] = 0;
  }
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
                    "Confirm OMNI Transaction:", NULL, desc, NULL, str_out,
                    NULL);
}

uint8_t layoutConfirmOpReturn(const CoinInfo *coin, uint8_t *data,
                              uint32_t size, int64_t amount) {
  oledClear();
  if (amount != 0) {
    oledDrawBitmap(56, 2, &bmp_icon_warning);
    uint8_t key = oledDrawPageableStringAdapter(
        0, 23, _(TITLE__OP_RETURN_DESC), FONT_STANDARD, &bmp_bottom_left_close,
        &bmp_bottom_right_arrow);
    if (key == KEY_CANCEL) {
      return KEY_CANCEL;
    }
  }
  oledClear();
  layoutHeader("OP_RETURN");

  int y = 13;
  if (amount != 0) {
    char str_amount[32] = {0};
    format_coin_amount((uint64_t)amount, NULL, coin, AmountUnit_BITCOIN,
                       str_amount, sizeof(str_amount));
    oledDrawStringAdapter(0, y, _(I__AMOUNT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, str_amount, FONT_STANDARD);
    y += 20;
  }
  char op_return_data[161] = {0};
  if (!is_printable(data, size)) {
    data2hex(data, size, op_return_data);
  } else {
    memcpy(op_return_data, (const char *)data, size);
  }
  return oledDrawPageableStringAdapter(
      0, amount != 0 ? y + 5 : y, op_return_data, FONT_STANDARD,
      &bmp_bottom_left_close, &bmp_bottom_right_arrow);
}

static bool formatAmountDifference(const CoinInfo *coin, AmountUnit amount_unit,
                                   uint64_t amount1, uint64_t amount2,
                                   char *output, size_t output_length) {
  uint64_t abs_diff = 0;
  const char *sign = NULL;
  if (amount1 >= amount2) {
    abs_diff = amount1 - amount2;
  } else {
    abs_diff = amount2 - amount1;
    sign = "-";
  }

  return format_coin_amount(abs_diff, sign, coin, amount_unit, output,
                            output_length) != 0;
}

// Computes numer / denom and rounds to the nearest integer.
static uint64_t div_round(uint64_t numer, uint64_t denom) {
  return numer / denom + (2 * (numer % denom) >= denom);
}

static bool formatComputedFeeRate(uint64_t fee, uint64_t tx_weight,
                                  char *output, size_t output_length,
                                  bool segwit, bool parentheses) {
  // Convert transaction weight to virtual transaction size, which is defined
  // as tx_weight / 4 rounded up to the next integer.
  // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-size-calculations
  uint64_t tx_size = (tx_weight + 3) / 4;

  // Compute fee rate and modify it in place for the bn_format_amount()
  // function. We multiply by 100, because we want bn_format_amount() to display
  // two decimal digits.
  uint64_t fee_rate_multiplied = div_round(100 * fee, tx_size);

  size_t length =
      bn_format_amount(fee_rate_multiplied, parentheses ? "(" : NULL,
                       segwit ? " sat/vB" : " sat/B", 2, output, output_length);
  if (length == 0) {
    return false;
  }

  if (parentheses) {
    if (length + 2 > output_length) {
      return false;
    }
    output[length] = ')';
    output[length + 1] = '\0';
  }
  return true;
}

static bool formatFeeRate(uint64_t fee_per_kvbyte, char *output,
                          size_t output_length, bool segwit) {
  return formatComputedFeeRate(fee_per_kvbyte, 4000, output, output_length,
                               segwit, false);
}

bool layoutConfirmTx(const CoinInfo *coin, AmountUnit amount_unit,
                     uint64_t total_in, uint64_t external_in,
                     uint64_t total_out, uint64_t change_out,
                     uint64_t tx_weight) {
  (void)tx_weight;
  (void)external_in;
  uint8_t key = KEY_NULL;
  char str_out[32] = {0};
  char str_fee[32] = {0};
  const char **tx_msg = format_tx_message(coin->coin_name);

  formatAmountDifference(coin, amount_unit, total_in, change_out, str_out,
                         sizeof(str_out));
  formatAmountDifference(coin, amount_unit, total_in, total_out, str_fee,
                         sizeof(str_fee));
  int total_index = 2;
  int current_index = 0;
  while (1) {
    oledClear();
    layoutHeader(tx_msg[0]);
    // index indicator
    char index_str[16] = {0};
    memzero(index_str, sizeof(index_str));
    uint2str(current_index + 1, index_str);
    strcat(index_str + strlen(index_str), "/");
    uint2str(total_index, index_str + strlen(index_str));
    int l = oledStringWidthAdapter(index_str, FONT_SMALL);
    oledDrawStringAdapter(OLED_WIDTH / 2 - l / 2, OLED_HEIGHT - 8, index_str,
                          FONT_SMALL);

    if (current_index == 0) {  // total amount
      oledDrawStringAdapter(0, 13, _(I__TOTAL_AMOUNT_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, str_out, FONT_STANDARD);
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                     &bmp_bottom_middle_arrow_down);
    } else if (current_index == total_index - 1) {  // fee
      oledDrawStringAdapter(0, 13, _(I__FEE_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, str_fee, FONT_STANDARD);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                     &bmp_bottom_middle_arrow_up);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    oledRefresh();
    while (1) {
      WAIT_KEY_OR_ABORT(0, 0, key);
      if (key == KEY_CONFIRM) {
        return true;
      } else if (key == KEY_CANCEL || key == KEY_NULL) {
        return false;
      } else if (key == KEY_DOWN) {
        if (current_index < total_index - 1) {
          current_index++;
          break;
        }
      } else if (key == KEY_UP) {
        if (current_index > 0) {
          current_index--;
          break;
        }
      }
      delay_ms(10);
    }
  }
  oledClear();
  layoutHeader(_(T__SIGN_TRANSACTION));
  layoutTxConfirmPage(tx_msg[1]);
  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  oledRefresh();
  while (1) {
    WAIT_KEY_OR_ABORT(0, 1, key);
    if (key == KEY_CONFIRM) {
      break;
    }
    if (key == KEY_CANCEL || key == KEY_NULL) {
      return false;
    }
    delay_ms(10);
  }
  return true;
}

void layoutConfirmReplacement(const char *description, uint8_t txid[32]) {
  const char **str = split_message_hex(txid, 32);
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, description,
                    str[0], str[1], str[2], str[3], NULL);
}

void layoutConfirmModifyOutput(const CoinInfo *coin, AmountUnit amount_unit,
                               TxOutputType *out, TxOutputType *orig_out,
                               int page) {
  if (page == 0) {
    render_address_dialog(coin, out->address, "Modify amount for",
                          _(I__ADDRESS_COLON), NULL);
  } else {
    char *question = NULL;
    uint64_t amount_change = 0;
    if (orig_out->amount < out->amount) {
      question = "Increase amount by:";
      amount_change = out->amount - orig_out->amount;
    } else {
      question = "Decrease amount by:";
      amount_change = orig_out->amount - out->amount;
    }

    char str_amount_change[32] = {0};
    format_coin_amount(amount_change, NULL, coin, amount_unit,
                       str_amount_change, sizeof(str_amount_change));

    char str_amount_new[32] = {0};
    format_coin_amount(out->amount, NULL, coin, amount_unit, str_amount_new,
                       sizeof(str_amount_new));

    layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, question,
                      str_amount_change, NULL, "New amount:", str_amount_new,
                      NULL);
  }
}

void layoutConfirmModifyFee(const CoinInfo *coin, AmountUnit amount_unit,
                            uint64_t fee_old, uint64_t fee_new,
                            uint64_t tx_weight) {
  char str_fee_change[32] = {0};
  char str_fee_new[32] = {0};
  char *question = NULL;

  uint64_t fee_change = 0;
  if (fee_old < fee_new) {
    question = "Increase your fee by:";
    fee_change = fee_new - fee_old;
  } else {
    question = "Decrease your fee by:";
    fee_change = fee_old - fee_new;
  }
  format_coin_amount(fee_change, NULL, coin, amount_unit, str_fee_change,
                     sizeof(str_fee_change));

  format_coin_amount(fee_new, NULL, coin, amount_unit, str_fee_new,
                     sizeof(str_fee_new));

  char str_fee_rate[32] = {0};

  formatComputedFeeRate(fee_new, tx_weight, str_fee_rate, sizeof(str_fee_rate),
                        coin->has_segwit, true);

  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, question,
                    str_fee_change, _(I_TRANSACTION_FEE_COLON), str_fee_new,
                    str_fee_rate, NULL);
}

void layoutFeeOverThreshold(const CoinInfo *coin, AmountUnit amount_unit,
                            uint64_t fee) {
  char str_fee[32] = {0};
  format_coin_amount(fee, NULL, coin, amount_unit, str_fee, sizeof(str_fee));
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, "Fee",
                    str_fee, "is unexpectedly high.", NULL, "Send anyway?",
                    NULL);
}

void layoutFeeRateOverThreshold(const CoinInfo *coin, uint32_t fee_per_kvbyte) {
  char str_fee_rate[32] = {0};
  formatFeeRate(fee_per_kvbyte, str_fee_rate, sizeof(str_fee_rate),
                coin->has_segwit);
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, "Fee rate",
                    str_fee_rate, "is unexpectedly high.", NULL,
                    "Proceed anyway?", NULL);
}

void layoutChangeCountOverThreshold(uint32_t change_count) {
  char str_change[21] = {0};
  snprintf(str_change, sizeof(str_change), "There are %" PRIu32, change_count);
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, "Warning!",
                    str_change, "change-outputs.", NULL, "Continue?", NULL);
}

void layoutConfirmUnverifiedExternalInputs(void) {
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, "Warning!",
                    "The transaction", "contains unverified",
                    "external inputs.", "Continue?", NULL);
}

void layoutConfirmNondefaultLockTime(const CoinInfo *coin, uint32_t lock_time,
                                     bool lock_time_disabled) {
  oledClear();
  const char **tx_msg = format_tx_message(coin->coin_name);
  layoutHeader(tx_msg[0]);
  if (lock_time_disabled) {
    oledDrawStringAdapter(0, 16, _(LOCKTIME_INVALID_WARNING_TEXT),
                          FONT_STANDARD);
  } else {
    char str_locktime[20] = {0};
    char *str_type = NULL;
    if (lock_time < LOCKTIME_TIMESTAMP_MIN_VALUE) {
      str_type = _(BLOCKHEIGHT);
      snprintf(str_locktime, sizeof(str_locktime), "%" PRIu32, lock_time);
    } else {
      str_type = _(TIMESTAMP);
      time_t time = lock_time;
      const struct tm *tm = gmtime(&time);
      strftime(str_locktime, sizeof(str_locktime), "%F %T", tm);
    }
    char desc[32] = {0};
    strcat(desc, str_type);
    strcat(desc, ":");
    oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, str_locktime, FONT_STANDARD);
  }
  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  oledRefresh();
}

void layoutAuthorizeCoinJoin(const CoinInfo *coin, uint64_t max_rounds,
                             uint32_t max_fee_per_kvbyte) {
  char str_max_rounds[32] = {0};
  char str_fee_rate[32] = {0};
  bn_format_amount(max_rounds, NULL, NULL, 0, str_max_rounds,
                   sizeof(str_max_rounds));
  formatFeeRate(max_fee_per_kvbyte, str_fee_rate, sizeof(str_fee_rate),
                coin->has_segwit);
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm",
                    "Authorize coinjoin", "Maximum rounds:", str_max_rounds,
                    "Maximum mining fee:", str_fee_rate, NULL, NULL);
}

void layoutConfirmCoinjoinAccess(void) {
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
                    "Do you want to allow", "access to your",
                    "coinjoin account?", NULL, NULL, NULL);
}

void layoutVerifyAddress(const CoinInfo *coin, const char *address) {
  render_address_dialog(coin, address, _(T__CONFIRM_ADDRESS),
                        _(I__SIGNED_BY_COLON), 0);
}

void layoutCipherKeyValue(bool encrypt, const char *key) {
  const char **str = split_message((const uint8_t *)key, strlen(key), 16);
  layoutDialogSwipe(
      &bmp_icon_question, "Cancel", "Confirm",
      encrypt ? "Encrypt value of this key?" : "Decrypt value of this key?",
      str[0], str[1], str[2], str[3], NULL, NULL);
}

void layoutEncryptMessage(const uint8_t *msg, uint32_t len, bool signing) {
  const char **str = split_message(msg, len, 16);
  layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm",
                    signing ? "Encrypt+Sign message?" : "Encrypt message?",
                    str[0], str[1], str[2], str[3], NULL, NULL);
}

void layoutDecryptMessage(const uint8_t *msg, uint32_t len,
                          const char *address) {
  const char **str = split_message(msg, len, 16);
  layoutDialogSwipe(&bmp_icon_info, NULL, "OK",
                    address ? "Decrypted signed message" : "Decrypted message",
                    str[0], str[1], str[2], str[3], NULL, NULL);
}

void layoutResetWord(const char *word, int pass, int word_pos, bool last) {
  layoutLast = layoutResetWord;
  oledClear();
  char header_str[64] = {0};

  if (pass == 1) {
    strcat(header_str, __("Check Word "));
    strcat(header_str, "#");
  } else {
    strcat(header_str, __("Word"));
    strcat(header_str, " #");
  }
  uint2str(word_pos, header_str + strlen(header_str));

  layoutHeader(header_str);
  oledDrawStringCenterAdapter(OLED_WIDTH / 2, 24, word, FONT_DOUBLE);

  if (last) {
    if (pass == 1) {
      oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11,
                     &bmp_bottom_right_confirm);
    } else {
      oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_next);
    }
  } else {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_arrow);
  }

  oledRefresh();
}

#define QR_MAX_VERSION 9

uint8_t layoutAddress(const char *address, const char *address_type,
                      const char *desc, bool qrcode, bool path, bool ignorecase,
                      const uint32_t *address_n, size_t address_n_count,
                      bool address_is_account, bool is_multisig) {
  if (layoutLast != layoutAddress && layoutLast != layoutXPUBMultisig) {
    layoutSwipe();
  } else {
    oledClear_ex();
  }
  layoutLast = layoutAddress;
  uint8_t key = KEY_NULL;

  uint32_t addrlen = strlen(address);
  if (qrcode) {
    char address_upcase[addrlen + 1];
    memset(address_upcase, 0, sizeof(address_upcase));
    if (ignorecase) {
      for (uint32_t i = 0; i < addrlen + 1; i++) {
        address_upcase[i] = address[i] >= 'a' && address[i] <= 'z'
                                ? address[i] + 'A' - 'a'
                                : address[i];
      }
    }
    uint8_t codedata[qrcodegen_BUFFER_LEN_FOR_VERSION(11)] = {0};
    uint8_t tempdata[qrcodegen_BUFFER_LEN_FOR_VERSION(11)] = {0};

    int side = 0;
    if (qrcodegen_encodeText(ignorecase ? address_upcase : address, tempdata,
                             codedata, qrcodegen_Ecc_LOW, 11, 11,
                             qrcodegen_Mask_AUTO, true)) {
      side = qrcodegen_getSize(codedata);
    }

    oledInvert(33, 1, 95, 63);
    int offset = 32 - (side / 2);
    for (int i = 0; i < side; i++) {
      for (int j = 0; j < side; j++) {
        if (qrcodegen_getModule(codedata, i, j)) {
          oledClearPixel(32 + offset + i, offset + j);
        }
      }
    }
  } else if (path) {
    layoutHeader(desc);
    oledDrawStringAdapter(0, 13, _(I__PATH_COLON), FONT_STANDARD);
    oledDrawString(
        0, 13 + 10,
        address_n_str(address_n, address_n_count, address_is_account),
        FONT_STANDARD);
  } else {
    uint32_t rowlen = 21;
    int index = 0, rowcount = addrlen / rowlen + 1;
    if (rowcount > 3) {
      const char **str =
          split_message((const uint8_t *)address, addrlen, rowlen);

    refresh_addr:
      oledClear_ex();
      layoutHeader(desc);

      if (0 == index) {
        if (address_type) {
          oledDrawStringAdapter(0, 13, address_type, FONT_STANDARD);
        } else {
          oledDrawStringAdapter(0, 13, _(I__ADDRESS_COLON), FONT_STANDARD);
        }
        oledDrawStringAdapter(0, 13 + 1 * 10, str[0], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[2], FONT_STANDARD);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else {
        oledDrawStringAdapter(0, 13, str[index - 1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[index], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[index + 1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[index + 2], FONT_STANDARD);
        if (index == rowcount - 3) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }
      }

      // scrollbar
      drawScrollbar(rowcount - 2, index);

      layoutButtonNoAdapter(NULL, &bmp_bottom_left_qrcode);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);

      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, key);
      switch (key) {
        case KEY_UP:
          if (index > 0) {
            index--;
          }
          goto refresh_addr;
        case KEY_DOWN:
          if (index < rowcount - 3) {
            index++;
          }
          goto refresh_addr;
        case KEY_CONFIRM:
          if (index == rowcount - 3) {
            return KEY_CONFIRM;
          }
          index++;
          goto refresh_addr;
        case KEY_CANCEL:
          return KEY_CANCEL;
        default:
          break;
      }
      return KEY_NULL;
    } else {
      layoutHeader(desc);
      if (address_type) {
        oledDrawStringAdapter(0, 13, address_type, FONT_STANDARD);
      } else {
        oledDrawStringAdapter(0, 13, _(I__ADDRESS_COLON), FONT_STANDARD);
      }
      oledDrawString(0, 13 + 10, address, FONT_STANDARD);
    }
  }

  if (!qrcode) {
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_qrcode);
  } else {
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
  }

  if ((!is_multisig && path) || qrcode) {
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else {
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();

  return KEY_NULL;
}

void layoutQRCode(const char *index, const BITMAP *bmp_up,
                  const BITMAP *bmp_down, const char *title, const char *text) {
  int y = 0, h = OLED_HEIGHT - 1;

  uint8_t codedata[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_MAX_VERSION)] = {0};
  uint8_t tempdata[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_MAX_VERSION)] = {0};
  uint8_t times = 0;

  int side = 0;
  oledClear_ex();
  oledDrawStringAdapter(0, 0, index, FONT_STANDARD | FONT_FIXED);
  if (bmp_up) {
    oledDrawBitmap(60, y, bmp_up);
    y += 8;
    h -= 8;
  }
  if (bmp_down) {
    oledDrawBitmap(60, OLED_HEIGHT - 8, bmp_down);
    h -= 8;
  }
  if (title) {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y, title, FONT_STANDARD);
    y += 9;
    h -= 9;
  }
  if (qrcodegen_encodeText(text, tempdata, codedata, qrcodegen_Ecc_LOW,
                           qrcodegen_VERSION_MIN, QR_MAX_VERSION,
                           qrcodegen_Mask_AUTO, true)) {
    side = qrcodegen_getSize(codedata);
    times = h / side;
    int x = 64 - times * side / 2;
    y += (h - times * side) / 2;
    oledInvert(x - 1, y - 1, x + side * times, y + side * times);
    for (int i = 0; i < side; i++) {
      for (int j = 0; j < side; j++) {
        if (qrcodegen_getModule(codedata, i, j)) {
          oledBox(x + i * times, y + j * times, x + (i + 1) * times - 1,
                  y + (j + 1) * times - 1, false);
        }
      }
    }
  } else {
    layoutDialogAdapter(NULL, __("Cancel"), __("Confirm"), NULL,
                        "Generate QR Code fail", NULL, NULL, NULL, NULL, NULL);
  }
  oledRefresh();
}

void layoutPublicKey(const uint8_t *pubkey) {
  char desc[16] = {0};
  strlcpy(desc, "Public Key: 00", sizeof(desc));
  if (pubkey[0] == 1) {
    /* ed25519 public key */
    // pass - leave 00
  } else {
    data2hex(pubkey, 1, desc + 12);
  }
  const char **str = split_message_hex(pubkey + 1, 32 * 2);
  layoutDialogSwipe(&bmp_icon_question, NULL, __("Continue"), NULL, desc,
                    str[0], str[1], str[2], str[3], NULL);
}

// static void _layout_xpub(const char *xpub, const char *desc, int page) {
//   // 21 characters per line, 4 lines, minus 3 chars for "..." = 81
//   // skip 81 characters per page
//   xpub += page * 81;
//   const char **str = split_message((const uint8_t *)xpub, strlen(xpub), 21);
//   oledDrawString(0, 0 * 9, desc, FONT_STANDARD);
//   for (int i = 0; i < 4; i++) {
//     oledDrawString(0, (i + 1) * 9 + 4, str[i], FONT_FIXED);
//   }
// }

bool layoutXPUB(const char *coin_name, const char *xpub,
                const uint32_t *address_n, size_t address_n_count) {
  bool result = false;
  int index = 0, sub_index = 0;
  uint8_t key = KEY_NULL;
  uint8_t max_index = 2, max_sub_index = 2;
  char title[64] = {0};
  const char **str = split_message((const uint8_t *)xpub, strlen(xpub), 20);
  if (strlen(xpub) < 60) {
    max_sub_index = 1;
  }
  strcat(title, _(T__CHAIN_STR_PUBLIC_KEY));
  bracket_replace(title, coin_name);

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_PublicKey;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_menu:
  if (layoutLast != layoutAddress && layoutLast != layoutXPUB) {
    layoutSwipe();
  } else {
    oledClear_ex();
  }
  layoutLast = layoutXPUB;
  if (index == 0) {
    layoutHeader(title);
    if (max_sub_index > 1 && sub_index == 0) {
      oledDrawString(0, 13, "xPub:", FONT_STANDARD);
      oledDrawString(0, 13 + 10, str[0], FONT_STANDARD);
      oledDrawString(0, 13 + 2 * 10, str[1], FONT_STANDARD);
      oledDrawString(0, 13 + 3 * 10, str[2], FONT_STANDARD);
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
      drawScrollbar(2, sub_index);
    } else if (max_sub_index > 1) {
      if (str[3]) oledDrawString(0, 13, str[3], FONT_STANDARD);
      if (str[4]) oledDrawString(0, 13 + 1 * 10, str[4], FONT_STANDARD);
      if (str[5]) oledDrawString(0, 13 + 2 * 10, str[5], FONT_STANDARD);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_up);
      drawScrollbar(2, sub_index);
    } else {
      oledDrawString(0, 13, "xPub:", FONT_STANDARD);
      if (str[0]) oledDrawString(0, 13 + 1 * 10, str[0], FONT_STANDARD);
      if (str[1]) oledDrawString(0, 13 + 2 * 10, str[1], FONT_STANDARD);
      if (str[2]) oledDrawString(0, 13 + 3 * 10, str[2], FONT_STANDARD);
    }

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index - 1 == index) {
    layoutHeader(title);
    oledDrawStringAdapter(0, 13, _(I__PATH_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10,
                          address_n_str(address_n, address_n_count, false),
                          FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();
  WAIT_KEY_OR_ABORT(0, 0, key);
  switch (key) {
    case KEY_UP:
      if (sub_index > 0) {
        sub_index--;
      }
      goto refresh_menu;
    case KEY_DOWN:
      if (sub_index < max_sub_index - 1) {
        sub_index++;
      }
      goto refresh_menu;
    case KEY_CONFIRM:
      if (max_index - 1 == index) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      goto refresh_menu;
    case KEY_CANCEL:
      if (0 == index || max_index == index) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_menu;
    default:
      break;
  }

  return result;
}

uint8_t layoutXPUBMultisig(const char *header, const char *xpub, int xpub_index,
                           int page, bool ours, bool last_page) {
  (void)page;
  uint8_t key = KEY_NULL;

  uint32_t xpublen = strlen(xpub);
  uint32_t rowlen = 21;
  int index = 0, rowcount = xpublen / rowlen + 1;

  layoutLast = layoutXPUBMultisig;
  char desc[32] = {0};
  snprintf(desc, 32, "xPub #%d (%s)", xpub_index + 1,
           ours ? _(C__MINE) : _(C__COSIGNER));
  if (rowcount > 3) {
    const char **str = split_message((const uint8_t *)xpub, xpublen, rowlen);

  refresh_addr:
    oledClear_ex();
    layoutHeader(header);

    if (0 == index) {
      oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 1 * 10, str[0], FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 2 * 10, str[1], FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 3 * 10, str[2], FONT_STANDARD);
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
    } else {
      oledDrawStringAdapter(0, 13, str[index - 1], FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 1 * 10, str[index], FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 2 * 10, str[index + 1], FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 3 * 10, str[index + 2], FONT_STANDARD);
      if (index == rowcount - 3) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      }
    }

    // scrollbar
    drawScrollbar(rowcount - 2, index);

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    if (last_page)
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
    else
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);

    oledRefresh();
    key = protectWaitKey(0, 0);
    switch (key) {
      case KEY_UP:
        if (index > 0) {
          index--;
        }
        goto refresh_addr;
      case KEY_DOWN:
        if (index < rowcount - 3) {
          index++;
        }
        goto refresh_addr;
      case KEY_CONFIRM:
        return KEY_CONFIRM;
      case KEY_CANCEL:
        return KEY_CANCEL;
      default:
        break;
    }
    return KEY_NULL;
  } else {
    layoutHeader(desc);
    oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);
    oledDrawString(0, 13 + 10, xpub, FONT_STANDARD);
  }

  return KEY_NULL;
}

void layoutSignIdentity(const IdentityType *identity, const char *challenge) {
  char row_proto[8 + 11 + 1] = {0};
  char row_hostport[64 + 6 + 1] = {0};
  char row_user[64 + 8 + 1] = {0};

  bool is_gpg = (strcmp(identity->proto, "gpg") == 0);

  if (identity->has_proto && identity->proto[0]) {
    if (strcmp(identity->proto, "https") == 0) {
      strlcpy(row_proto, "Web sign in to:", sizeof(row_proto));
    } else if (is_gpg) {
      strlcpy(row_proto, "GPG sign for:", sizeof(row_proto));
    } else {
      strlcpy(row_proto, identity->proto, sizeof(row_proto));
      char *p = row_proto;
      while (*p) {
        *p = toupper((int)*p);
        p++;
      }
      strlcat(row_proto, " login to:", sizeof(row_proto));
    }
  } else {
    strlcpy(row_proto, "Login to:", sizeof(row_proto));
  }

  if (identity->has_host && identity->host[0]) {
    strlcpy(row_hostport, identity->host, sizeof(row_hostport));
    if (identity->has_port && identity->port[0]) {
      strlcat(row_hostport, ":", sizeof(row_hostport));
      strlcat(row_hostport, identity->port, sizeof(row_hostport));
    }
  } else {
    row_hostport[0] = 0;
  }

  if (identity->has_user && identity->user[0]) {
    strlcpy(row_user, "user: ", sizeof(row_user));
    strlcat(row_user, identity->user, sizeof(row_user));
  } else {
    row_user[0] = 0;
  }

  if (is_gpg) {
    // Split "First Last <first@last.com>" into 2 lines:
    // "First Last"
    // "first@last.com"
    char *email_start = strchr(row_hostport, '<');
    if (email_start) {
      strlcpy(row_user, email_start + 1, sizeof(row_user));
      *email_start = 0;
      char *email_end = strchr(row_user, '>');
      if (email_end) {
        *email_end = 0;
      }
    }
  }

  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"),
                    "Do you want to sign in?", row_proto[0] ? row_proto : NULL,
                    row_hostport[0] ? row_hostport : NULL,
                    row_user[0] ? row_user : NULL, challenge, NULL, NULL);
}

void layoutDecryptIdentity(const IdentityType *identity) {
  char row_proto[8 + 11 + 1] = {0};
  char row_hostport[64 + 6 + 1] = {0};
  char row_user[64 + 8 + 1] = {0};

  if (identity->has_proto && identity->proto[0]) {
    strlcpy(row_proto, identity->proto, sizeof(row_proto));
    char *p = row_proto;
    while (*p) {
      *p = toupper((int)*p);
      p++;
    }
    strlcat(row_proto, " decrypt for:", sizeof(row_proto));
  } else {
    strlcpy(row_proto, "Decrypt for:", sizeof(row_proto));
  }

  if (identity->has_host && identity->host[0]) {
    strlcpy(row_hostport, identity->host, sizeof(row_hostport));
    if (identity->has_port && identity->port[0]) {
      strlcat(row_hostport, ":", sizeof(row_hostport));
      strlcat(row_hostport, identity->port, sizeof(row_hostport));
    }
  } else {
    row_hostport[0] = 0;
  }

  if (identity->has_user && identity->user[0]) {
    strlcpy(row_user, "user: ", sizeof(row_user));
    strlcat(row_user, identity->user, sizeof(row_user));
  } else {
    row_user[0] = 0;
  }

  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"),
                    "Do you want to decrypt?", row_proto[0] ? row_proto : NULL,
                    row_hostport[0] ? row_hostport : NULL,
                    row_user[0] ? row_user : NULL, NULL, NULL, NULL);
}

#if U2F_ENABLED

void layoutU2FDialog(const char *verb, const char *appname) {
  layoutDialogAdapter(&bmp_webauthn, __("Reject"), verb, NULL, verb,
                      "U2F security key?", NULL, appname, NULL, NULL);
}

#endif

void layoutShowPassphrase(const char *passphrase) {
  if (layoutLast != layoutShowPassphrase) {
    layoutSwipe();
  } else {
    oledClear();
  }

  layoutHeader(_(T__USE_THIS_PASSPHRASE_QUES));

  layout_index_count(strlen(passphrase), 50);

  oledDrawStringAdapter(0, 13, passphrase, FONT_STANDARD);

  oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_close);
  oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_confirm);

  oledRefresh();
}

#if !BITCOIN_ONLY

void layoutNEMDialog(const BITMAP *icon, const char *btnNo, const char *btnYes,
                     const char *desc, const char *line1, const char *address) {
  static char first_third[NEM_ADDRESS_SIZE / 3 + 1];
  strlcpy(first_third, address, sizeof(first_third));

  static char second_third[NEM_ADDRESS_SIZE / 3 + 1];
  strlcpy(second_third, &address[NEM_ADDRESS_SIZE / 3], sizeof(second_third));

  const char *third_third = &address[NEM_ADDRESS_SIZE * 2 / 3];

  layoutDialogSwipe(icon, btnNo, btnYes, desc, line1, first_third, second_third,
                    third_third, NULL, NULL);
}

void layoutNEMTransferXEM(const char *desc, uint64_t quantity,
                          const bignum256 *multiplier, uint64_t fee) {
  char str_out[32] = {0}, str_fee[32] = {0};

  nem_mosaicFormatAmount(NEM_MOSAIC_DEFINITION_XEM, quantity, multiplier,
                         str_out, sizeof(str_out));
  nem_mosaicFormatAmount(NEM_MOSAIC_DEFINITION_XEM, fee, NULL, str_fee,
                         sizeof(str_fee));

  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Next"), desc,
                    "Confirm transfer of", str_out, "and network fee of",
                    str_fee, NULL, NULL);
}

void layoutNEMNetworkFee(const char *desc, bool confirm, const char *fee1_desc,
                         uint64_t fee1, const char *fee2_desc, uint64_t fee2) {
  char str_fee1[32] = {0}, str_fee2[32] = {0};

  nem_mosaicFormatAmount(NEM_MOSAIC_DEFINITION_XEM, fee1, NULL, str_fee1,
                         sizeof(str_fee1));

  if (fee2_desc) {
    nem_mosaicFormatAmount(NEM_MOSAIC_DEFINITION_XEM, fee2, NULL, str_fee2,
                           sizeof(str_fee2));
  }

  layoutDialogSwipe(&bmp_icon_question, __("Cancel"),
                    confirm ? __("Confirm") : __("Next"), desc, fee1_desc,
                    str_fee1, fee2_desc, fee2_desc ? str_fee2 : NULL, NULL,
                    NULL);
}

void layoutNEMTransferMosaic(const NEMMosaicDefinition *definition,
                             uint64_t quantity, const bignum256 *multiplier,
                             uint8_t network) {
  char str_out[32] = {0}, str_levy[32] = {0};

  nem_mosaicFormatAmount(definition, quantity, multiplier, str_out,
                         sizeof(str_out));

  if (definition->has_levy) {
    nem_mosaicFormatLevy(definition, quantity, multiplier, network, str_levy,
                         sizeof(str_levy));
  }

  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Next"),
                    definition->has_name ? definition->name : __("Mosaic"),
                    __("Confirm transfer of"), str_out,
                    definition->has_levy ? __("and levy of") : NULL,
                    definition->has_levy ? str_levy : NULL, NULL, NULL);
}

void layoutNEMTransferUnknownMosaic(const char *namespace, const char *mosaic,
                                    uint64_t quantity,
                                    const bignum256 *multiplier) {
  char mosaic_name[32] = {0};
  nem_mosaicFormatName(namespace, mosaic, mosaic_name, sizeof(mosaic_name));

  char str_out[32] = {0};
  nem_mosaicFormatAmount(NULL, quantity, multiplier, str_out, sizeof(str_out));

  char *decimal = strchr(str_out, '.');
  if (decimal != NULL) {
    *decimal = '\0';
  }

  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), "I take the risk",
                    "Unknown Mosaic", "Confirm transfer of", str_out,
                    "raw units of", mosaic_name, NULL, NULL);
}

void layoutNEMTransferPayload(const uint8_t *payload, size_t length,
                              bool encrypted) {
  if (length >= 1 && payload[0] == 0xFE) {
    char encoded[(length - 1) * 2 + 1];
    memset(encoded, 0, sizeof(encoded));

    data2hex(&payload[1], length - 1, encoded);

    const char **str =
        split_message((uint8_t *)encoded, sizeof(encoded) - 1, 16);
    layoutDialogSwipe(
        &bmp_icon_question, __("Cancel"), __("Next"),
        encrypted ? __("Encrypted hex data") : __("Unencrypted hex data"),
        str[0], str[1], str[2], str[3], NULL, NULL);
  } else {
    const char **str = split_message(payload, length, 16);
    layoutDialogSwipe(
        &bmp_icon_question, __("Cancel"), __("Next"),
        encrypted ? __("Encrypted message") : __("Unencrypted message"), str[0],
        str[1], str[2], str[3], NULL, NULL);
  }
}

void layoutNEMMosaicDescription(const char *description) {
  const char **str =
      split_message((uint8_t *)description, strlen(description), 16);
  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Next"),
                    __("Mosaic Description"), str[0], str[1], str[2], str[3],
                    NULL, NULL);
}

void layoutNEMLevy(const NEMMosaicDefinition *definition, uint8_t network) {
  const NEMMosaicDefinition *mosaic = NULL;
  if (nem_mosaicMatches(definition, definition->levy_namespace,
                        definition->levy_mosaic, network)) {
    mosaic = definition;
  } else {
    mosaic = nem_mosaicByName(definition->levy_namespace,
                              definition->levy_mosaic, network);
  }

  char mosaic_name[32] = {0};
  if (mosaic == NULL) {
    nem_mosaicFormatName(definition->levy_namespace, definition->levy_mosaic,
                         mosaic_name, sizeof(mosaic_name));
  }

  char str_out[32] = {0};

  switch (definition->levy) {
    case NEMMosaicLevy_MosaicLevy_Percentile:
      bn_format_amount(definition->fee, NULL, NULL, 0, str_out,
                       sizeof(str_out));

      layoutDialogSwipe(
          &bmp_icon_question, __("Cancel"), __("Next"), __("Percentile Levy"),
          __("Raw levy value is"), str_out, __("in"),
          mosaic ? (mosaic == definition ? __("the same mosaic") : mosaic->name)
                 : mosaic_name,
          NULL, NULL);
      break;

    case NEMMosaicLevy_MosaicLevy_Absolute:
    default:
      nem_mosaicFormatAmount(mosaic, definition->fee, NULL, str_out,
                             sizeof(str_out));
      layoutDialogSwipe(
          &bmp_icon_question, __("Cancel"), __("Next"), __("Absolute Levy"),
          __("Levy is"), str_out,
          mosaic ? (mosaic == definition ? __("in the same mosaic") : NULL)
                 : __("in raw units of"),
          mosaic ? NULL : mosaic_name, NULL, NULL);
      break;
  }
}

#endif

static inline bool is_slip18(const uint32_t *address_n,
                             size_t address_n_count) {
  // m / 10018' / [0-9]'
  return address_n_count == 2 && address_n[0] == (PATH_HARDENED + 10018) &&
         (address_n[1] & PATH_HARDENED) &&
         (address_n[1] & PATH_UNHARDEN_MASK) <= 9;
}

void layoutCosiSign(const uint32_t *address_n, size_t address_n_count,
                    const uint8_t *data, uint32_t len) {
  char *desc = __("CoSi sign message?");
  char desc_buf[32] = {0};
  if (is_slip18(address_n, address_n_count)) {
    strlcpy(desc_buf, __("CoSi sign index #?"), sizeof(desc_buf));
    desc_buf[16] = '0' + (address_n[1] & PATH_UNHARDEN_MASK);
    desc = desc_buf;
  }
  char str[4][17] = {0};
  if (len == 32) {
    data2hex(data, 8, str[0]);
    data2hex(data + 8, 8, str[1]);
    data2hex(data + 16, 8, str[2]);
    data2hex(data + 24, 8, str[3]);
  } else {
    strlcpy(str[0], "Data", sizeof(str[0]));
    strlcpy(str[1], "of", sizeof(str[1]));
    strlcpy(str[2], "unsupported", sizeof(str[2]));
    strlcpy(str[3], "length", sizeof(str[3]));
  }
  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"), desc,
                    str[0], str[1], str[2], str[3], NULL, NULL);
}

void layoutHomeInfo(void) {
  uint8_t key = KEY_NULL;
  key = keyScan();
  msg_command_inprogress = false;
  if (layoutLast == onboarding) {
#if !EMULATOR
    if (ble_passkey_state()) {
      return;
    }
#endif
    onboarding(key);
  } else {
    layoutEnterSleep(0);
    if (layoutNeedRefresh()) {
      layoutHome();
    }
    if (layoutLast == layoutHome) {
#if !EMULATOR
      refreshUsbConnectTips();
#endif
      if (key == KEY_CANCEL && (session_isUnlocked() || !config_hasPin())) {
        layoutDialogCenterStrict(&bmp_bottom_left_close,
                                 &bmp_bottom_right_confirm,
                                 _(C__LOCK_THE_SCREEN));
        uint8_t k = protectWaitKey(timer1s * 5, 1);
        if (k == KEY_CONFIRM) {
          session_clear(true);
          layoutHome();
          return;
        }
        layoutHome();
      } else if (key == KEY_UP || key == KEY_DOWN || key == KEY_CONFIRM) {
        if (protectPinOnDevice(true, true)) {
          menu_run(KEY_NULL, 0);
        } else {
          layoutHome();
        }
      }
    } else if (layoutLast == menu_run) {
      menu_run(key, 0);
    }

    // wake from screensaver on any button
    if (layoutLast == layoutScreensaver &&
        (button.NoUp || button.YesUp || button.UpUp || button.DownUp)) {
      layoutHome();
      return;
    }
    if (layoutLast != layoutHome && layoutLast != layoutScreensaver) {
      if (button.NoUp) {
        recovery_abort();
        signing_abort();
      }
    }
  }
}

void layoutDialogSwipeCenterAdapter(const BITMAP *icon, const BITMAP *bmp_no,
                                    const char *btnNo, const BITMAP *bmp_yes,
                                    const char *btnYes, const char *desc,
                                    const char *line1, const char *line2,
                                    const char *line3, const char *line4,
                                    const char *line5, const char *line6) {
  layoutLast = layoutDialogSwipe;
  layoutSwipe();
  layoutDialogCenterAdapter(icon, bmp_no, btnNo, bmp_yes, btnYes, desc, line1,
                            line2, line3, line4, line5, line6);
}

void layoutConfirmAutoLockDelay(uint32_t delay_ms) {
  char line[sizeof("device after 4294967296 minutes?")] = {0};
  char line_cn[64] = {0};
  const char *unit = __("second");
  uint32_t num = delay_ms / 1000U;

  strcat(line_cn, "确定要在 ");
  if (delay_ms >= 60 * 60 * 1000) {
    unit = __("hour");
    num /= 60 * 60U;
  } else if (delay_ms >= 60 * 1000) {
    unit = __("minute");
    num /= 60U;
  }

  strlcpy(line, __("device after "), sizeof(line));
  size_t off = strlen(line);
  bn_format_amount(num, NULL, NULL, 0, &line[off], sizeof(line) - off);
  strlcat(line, " ", sizeof(line));
  strlcat(line, unit, sizeof(line));
  memcpy(line_cn + strlen(line_cn), &line[off], strlen(line) - off);
  if (num > 1 && ui_language == 0) {
    strlcat(line, "s", sizeof(line));
  }
  strlcat(line, "?", sizeof(line));

  oledClear_ex();
  layoutHeader(__("Change Auto-Lock Time"));
  if (ui_language) {
    strcat(line_cn, "后自动锁");
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, 18, line_cn, FONT_STANDARD);
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, 28, "定屏幕吗?", FONT_STANDARD);
  } else {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, 18, "Do you want to auto-lock",
                                FONT_STANDARD);
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, 28, line, FONT_STANDARD);
  }
  oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_close);
  oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_confirm);
  oledRefresh();
}

static int line_index(char *text, int lines) {
  string_lines_t split_lines =
      split_string_to_lines(text, OLED_WIDTH, FONT_STANDARD);
  int line_index =
      lines > split_lines.line_count ? split_lines.line_count : lines;
  return split_lines.line_start[line_index] - text;
}

static uint8_t layoutPagination(char *title, char *content) {
  uint8_t key = KEY_NULL;
  int rows = 0, pages = 0, index = 0;
  int p1 = 0, p2 = 0;
  char text[256] = {0};

  rows = countlines(content);
  if (rows > 4) {
    pages = rows - 4 + 1;
  } else {
    pages = 1;
  }

  BITMAP *bmp_no = (BITMAP *)&bmp_bottom_left_close;
  BITMAP *bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  BITMAP *bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
  BITMAP *bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;

_layout:
  oledClear_ex();

  p1 = line_index(content, index);
  p2 = line_index(content, index + 4);
  memset(text, 0, 256);
  memcpy(text, content + p1, p2 - p1);

  if (pages == 1) {
    bmp_up = NULL;
    bmp_down = NULL;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow;
  } else if (index == 0) {
    bmp_up = NULL;
    bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  } else if (index == pages - 1) {
    bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;
    bmp_down = NULL;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow;
  } else {
    bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;
    bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  }

  layoutDialogCenterAdapterV2(title, NULL, (const BITMAP *)bmp_no,
                              (const BITMAP *)bmp_yes, (const BITMAP *)bmp_up,
                              (const BITMAP *)bmp_down, NULL, NULL, NULL, NULL,
                              text);
  if (pages > 1) drawScrollbar(pages, index);
  oledRefresh();

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (index > 0) {
        index--;
      }
      goto _layout;
    case KEY_DOWN:
      if (index < pages - 1) {
        index++;
      }
      goto _layout;
    case KEY_CONFIRM:
      if (index == pages - 1) {
        return KEY_CONFIRM;
      }
      if (index < pages - 1) {
        index++;
      }
      goto _layout;
      break;
      ;
    default:
      return KEY_CANCEL;
  }

  return key;
}

void layoutTxConfirmPage(const char *data) {
  oledDrawStringCenterAdapter(OLED_WIDTH / 2, 13 + 8, data, FONT_STANDARD);
}

bool layoutConfirmSafetyChecks(SafetyCheckLevel safety_ckeck_level,
                               bool interactive) {
  uint8_t key = KEY_NULL;
  if (interactive) {
    ButtonRequest resp = {0};
    memzero(&resp, sizeof(ButtonRequest));
    resp.has_code = true;
    resp.code = ButtonRequestType_ButtonRequest_ProtectCall;
    msg_write(MessageType_MessageType_ButtonRequest, &resp);
  }
  if (safety_ckeck_level == SafetyCheckLevel_Strict) {
    // Disallow unsafe actions. This is the default.
    key = layoutPagination(
        _(T__SAFETY_CHECKS),
        _(C__AFTER_ENABLE_SAFETY_CHECK_IT_WILL_PROTECT_YOU_FROM_NON_BIP44_COMPLIANT_ADDRESS_DIRIVATION_OR_PERFORMING_POTENTIALLY_RISKY_TX_OR_UNEXPECTED_HIGH_FEES));
    if (key == KEY_CANCEL) return false;
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__ARE_YOU_SURE_TO_ENABLE_SAFETY_CHECKS_QUES));
    WAIT_KEY_OR_ABORT(0, 1, key);
    if (key == KEY_CANCEL) {
      return false;
    }
  } else if (safety_ckeck_level == SafetyCheckLevel_PromptTemporarily) {
    // Ask user before unsafe action. Reverts to Strict after reboot.
    layoutDialogCenterAdapterV2(
        _(T__SAFETY_CHECKS), NULL, &bmp_bottom_left_close,
        &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__IT_WILL_TEMPORARILY_ALLOW_YOU_TO_PERFORM_SOME_ACTIONS_WITH_POTENTIALLY_RISKY));
    WAIT_KEY_OR_ABORT(0, 1, key);
    if (key == KEY_CANCEL) {
      return false;
    }
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__ARE_YOU_SURE_TO_TEMPORARILY_DISABLE_SAFETY_CHECKS_QUES));
    WAIT_KEY_OR_ABORT(0, 1, key);
    if (key == KEY_CANCEL) {
      return false;
    }
  }

  return true;
}

void layoutConfirmHash(const BITMAP *icon, const char *description,
                       const uint8_t *hash, uint32_t len) {
  const char **str = split_message_hex(hash, len);

  layoutSwipe();
  oledClear();
  oledDrawBitmap(0, 0, icon);
  oledDrawString(20, 0 * 9, description, FONT_STANDARD);
  oledDrawString(20, 1 * 9, str[0], FONT_FIXED);
  oledDrawString(20, 2 * 9, str[1], FONT_FIXED);
  oledDrawString(20, 3 * 9, str[2], FONT_FIXED);
  oledDrawString(20, 4 * 9, str[3], FONT_FIXED);
  oledHLine(OLED_HEIGHT - 13);

  layoutButtonNo(__("Cancel"), &bmp_btn_cancel);
  layoutButtonYes(__("Confirm"), &bmp_btn_confirm);
  oledRefresh();
}

void layoutConfirmOwnershipProof(void) {
  layoutDialogSwipe(&bmp_icon_question, __("Cancel"), __("Confirm"), NULL,
                    __("Do you want to"), __("create a proof of"),
                    __("ownership?"), NULL, NULL, NULL);
}

// layout chinese
void layoutButtonNoAdapter(const char *btnNo, const BITMAP *icon) {
  const struct font_desc *font = find_cur_font();
  int icon_width = 0;
  if (!btnNo) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, icon);
    return;
  }
  if (icon) {
    oledDrawBitmap(1, OLED_HEIGHT - 8 - 1, icon);
    icon_width = icon->width;
  }
  oledDrawStringAdapter(3 + icon_width, OLED_HEIGHT - (font->pixel + 1), btnNo,
                        FONT_STANDARD);
  oledInvert(0, OLED_HEIGHT - (font->pixel + 2),
             icon_width + oledStringWidthAdapter(btnNo, FONT_STANDARD) + 4,
             OLED_HEIGHT);
}

void layoutButtonYesAdapter(const char *btnYes, const BITMAP *icon) {
  const struct font_desc *font = find_cur_font();
  int icon_width = 0;
  if (!btnYes) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, icon);
    return;
  }
  if (icon) {
    oledDrawBitmap(OLED_WIDTH - 8 - 1, OLED_HEIGHT - 8 - 1, icon);
    icon_width = icon->width;
  }
  oledDrawStringRightAdapter(OLED_WIDTH - icon_width - 3,
                             OLED_HEIGHT - (font->pixel + 1), btnYes,
                             FONT_STANDARD);
  oledInvert(OLED_WIDTH - oledStringWidthAdapter(btnYes, FONT_STANDARD) -
                 icon_width - 4,
             OLED_HEIGHT - (font->pixel + 2), OLED_WIDTH, OLED_HEIGHT);
}

static void _layoutDialogAdapter(const BITMAP *icon, const BITMAP *bmp_no,
                                 const char *btnNo, const BITMAP *bmp_yes,
                                 const char *btnYes, const char *desc,
                                 const char *line1, const char *line2,
                                 const char *line3, const char *line4,
                                 const char *line5, const char *line6,
                                 bool spilt, bool center) {
  int left = 0;
  const struct font_desc *font = find_cur_font();

  oledClear_ex();
  if (icon) {
    oledDrawBitmap(0, 0, icon);
    left = icon->width + 4;
  }
  if (line1) {
    oledDrawStringAdapter(left, 0 * (font->pixel + 1), line1, FONT_STANDARD);
  }
  if (line2) {
    oledDrawStringAdapter(left, 1 * (font->pixel + 1), line2, FONT_STANDARD);
  }
  if (line3) {
    bool change_line = false;
    if (line2 &&
        (oledStringWidthAdapter(line2, FONT_STANDARD) > (OLED_WIDTH - left))) {
      change_line = true;
    }
    if (change_line) {
      if (center) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 3 * (font->pixel + 1),
                                    line3, FONT_STANDARD);
      } else {
        oledDrawStringAdapter(left, 3 * (font->pixel + 1), line3,
                              FONT_STANDARD);
      }
    } else {
      if (center) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 2 * (font->pixel + 1),
                                    line3, FONT_STANDARD);
      } else {
        oledDrawStringAdapter(left, 2 * (font->pixel + 1), line3,
                              FONT_STANDARD);
      }
    }
  }
  if (line4) {
    oledDrawStringAdapter(0, 3 * (font->pixel + 1), line4, FONT_STANDARD);
  }

  if (desc) {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2,
                                OLED_HEIGHT - 2 * (font->pixel + 1) - 1, desc,
                                FONT_STANDARD);
    if (btnYes || btnNo) {
      if (spilt) {
        oledHLine(OLED_HEIGHT - 2 * (font->pixel + 1) - 3);
      }
    }
  } else {
    if (line5) {
      oledDrawStringAdapter(0, 4 * (font->pixel + 1), line5, FONT_STANDARD);
    }
    if (line6) {
      oledDrawStringAdapter(0, 5 * (font->pixel + 1), line6, FONT_STANDARD);
    }
    if (btnYes || btnNo) {
      if (spilt) {
        oledHLine(OLED_HEIGHT - (font->pixel + 4));
      }
    }
  }

  layoutButtonNoAdapter(btnNo, bmp_no);
  layoutButtonYesAdapter(btnYes, bmp_yes);
  oledRefresh();
}

void layoutDialogAdapter(const BITMAP *icon, const char *btnNo,
                         const char *btnYes, const char *desc,
                         const char *line1, const char *line2,
                         const char *line3, const char *line4,
                         const char *line5, const char *line6) {
  _layoutDialogAdapter(icon, &bmp_btn_cancel, btnNo, &bmp_btn_confirm, btnYes,
                       desc, line1, line2, line3, line4, line5, line6, true,
                       true);
}

void layoutDialogAdapter_ex(const BITMAP *icon, const BITMAP *bmp_no,
                            const char *btnNo, const BITMAP *bmp_yes,
                            const char *btnYes, const char *desc,
                            const char *line1, const char *line2,
                            const char *line3, const char *line4,
                            const char *line5, const char *line6) {
  _layoutDialogAdapter(icon, bmp_no, btnNo, bmp_yes, btnYes, desc, line1, line2,
                       line3, line4, line5, line6, false, false);
}

void layoutDialogCenterAdapter(const BITMAP *icon, const BITMAP *bmp_no,
                               const char *btnNo, const BITMAP *bmp_yes,
                               const char *btnYes, const char *desc,
                               const char *line1, const char *line2,
                               const char *line3, const char *line4,
                               const char *line5, const char *line6) {
  const struct font_desc *font = find_cur_font();

  oledClear_ex();
  if (icon) {
    oledDrawBitmap(56, 2, icon);
  } else {
    if (line1) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 0 * (font->pixel + 1), line1,
                                  FONT_STANDARD);
    }
    if (line2) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 1 * (font->pixel + 1), line2,
                                  FONT_STANDARD);
    }
    if (line3) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 2 * (font->pixel + 1), line3,
                                  FONT_STANDARD);
    }
  }
  if (line4) {
    if (icon && (ui_language == 1)) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 2 * (font->pixel + 1) + 1,
                                  line4, FONT_STANDARD);
    } else if (icon && (ui_language == 0)) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 2 * (font->pixel + 1) + 3,
                                  line4, FONT_STANDARD);
    } else {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 3 * (font->pixel + 1), line4,
                                  FONT_STANDARD);
    }
  }

  if (desc) {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT - 2 * (font->pixel),
                                desc, FONT_STANDARD);
    if (btnYes || btnNo) {
      oledHLine(OLED_HEIGHT - 2 * (font->pixel) - 1);
    }

  } else {
    if (line5) {
      if (icon && (ui_language == 1)) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 3 * (font->pixel + 1) + 1,
                                    line5, FONT_STANDARD);
      } else if (icon && (ui_language == 0)) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 3 * (font->pixel + 1) + 3,
                                    line5, FONT_STANDARD);
      } else {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 4 * (font->pixel + 1) + 1,
                                    line5, FONT_STANDARD);
      }
    }
    if (line6) {
      if (icon && (ui_language == 1)) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 4 * (font->pixel + 1) + 1,
                                    line6, FONT_STANDARD);
      } else if (icon && (ui_language == 0)) {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 4 * (font->pixel + 1) + 3,
                                    line6, FONT_STANDARD);
      } else {
        oledDrawStringCenterAdapter(OLED_WIDTH / 2, 5 * (font->pixel + 1) + 1,
                                    line6, FONT_STANDARD);
      }
    }
  }
  if (btnNo || bmp_no) {
    layoutButtonNoAdapter(btnNo, bmp_no);
  }
  if (btnYes) {
    layoutButtonYesAdapter(btnYes, bmp_yes);
  } else if (bmp_yes) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, bmp_yes);
  }

  oledRefresh();
}

void layoutDialogAdapterEx(const char *title, const BITMAP *bmp_no,
                           const char *btnNo, const BITMAP *bmp_yes,
                           const char *btnYes, const char *desc,
                           const char *line1, const char *line2,
                           const char *line3, const char *line4) {
  const struct font_desc *font = find_cur_font();
  int i, len, lines = 0, y = 0;

  oledClear_ex();
  if (title) {
    y = 14;
    if (ui_language) y--;
    layoutHeader(title);
  }

  if (desc) {
    lines = 1;
    len = strlen(desc);
    for (i = 0; i < len; i++) {
      if (desc[i] == '\n') lines++;
    }
    if (lines <= 3) {
      y = 17;
    }
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y, desc, FONT_STANDARD);
  } else {
    if (line1) lines++;
    if (line2) lines++;
    if (line3) lines++;
    if (line4) lines++;
    if (lines <= 3) {
      // y = 17; TODO
    }
    if (line1) {
      oledDrawStringAdapter(0, y + 0 * (font->pixel + 1), line1, FONT_STANDARD);
    }
    if (line2) {
      oledDrawStringAdapter(0, y + 1 * (font->pixel + 1), line2, FONT_STANDARD);
    }
    if (line3) {
      oledDrawStringAdapter(0, y + 2 * (font->pixel + 1), line3, FONT_STANDARD);
    }
    if (line4) {
      oledDrawStringAdapter(0, y + 3 * (font->pixel + 1), line4, FONT_STANDARD);
    }
  }

  if (btnNo || bmp_no) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, bmp_no);
  }
  if (btnYes || bmp_yes) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, bmp_yes);
  }
  oledRefresh();
}

void layoutDialogCenterAdapterV2(const char *title, const BITMAP *icon,
                                 const BITMAP *bmp_no, const BITMAP *bmp_yes,
                                 const BITMAP *bmp_up, const BITMAP *bmp_down,
                                 const char *line1, const char *line2,
                                 const char *line3, const char *line4,
                                 const char *desc) {
  const struct font_desc *font = find_cur_font();
  int lines = 0, y = 0;

  oledClear_ex();
  if (icon) {
    y = 21;
    oledDrawBitmap(56, 2, icon);
  } else if (title) {
    y = 14;
    if (ui_language) y--;
    layoutHeader(title);
  }

  if (desc) {
    if (!icon) {
      lines += countlines((char *)desc);
      if (lines <= 3) {
        y = 17;
      } else {
        y = 13;
      }
    }
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y, desc, FONT_STANDARD);
  } else {
    if (line1) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y + 0 * (font->pixel + 1),
                                  line1, FONT_STANDARD);
    }
    if (line2) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y + 1 * (font->pixel + 1),
                                  line2, FONT_STANDARD);
    }
    if (line3) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y + 2 * (font->pixel + 1),
                                  line3, FONT_STANDARD);
    }
    if (line4) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y + 3 * (font->pixel + 1),
                                  line4, FONT_STANDARD);
    }
  }
  if (bmp_no) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, bmp_no);
  }
  if (bmp_yes) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, bmp_yes);
  }
  if (bmp_up) {
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8, bmp_up);
  }
  if (bmp_down) {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8, bmp_down);
  }
  oledRefresh();
}

static void layoutDialogCenterStrict(const BITMAP *bmp_no,
                                     const BITMAP *bmp_yes, const char *desc) {
  if (!desc) return;
  int lines = countlines((char *)desc);
  int height = font_get_height();
  int total = lines * height;
  int y = (OLED_HEIGHT - total) / 2;
  if (y < 0) y = 0;

  oledClear_ex();
  oledDrawStringCenterAdapter(OLED_WIDTH / 2, y, desc, FONT_STANDARD);

  if (bmp_no) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, bmp_no);
  }
  if (bmp_yes) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, bmp_yes);
  }
  oledRefresh();
}

void layoutProgressAdapter(const char *desc, int permil) {
  int i = 0, permil_tmp = permil / 10;
  char buf[65] = {0};
  char percent_asc[5] = {0};
  if (permil_tmp < 10) {
    percent_asc[i++] = permil_tmp + 0x30;
  } else if (permil_tmp < 100) {
    percent_asc[i++] = permil_tmp / 10 + 0x30;
    percent_asc[i++] = permil_tmp % 10 + 0x30;
  } else {
    permil_tmp = 100;
    percent_asc[i++] = permil_tmp / 100 + 0x30;
    percent_asc[i++] = permil_tmp % 100 / 10 + 0x30;
    percent_asc[i++] = permil_tmp % 10 + 0x30;
  }
  percent_asc[i] = '%';
  snprintf(buf, 65, "%s (%s)", desc, percent_asc);

  oledClear();
  oledDrawStringCenterAdapter(OLED_WIDTH / 2, OLED_HEIGHT / 2 - 6, buf,
                              FONT_STANDARD);

  // progressbar
  oledBox(2, OLED_HEIGHT - 13, OLED_WIDTH - 2, OLED_HEIGHT - 2, 0);
  oledBox(5, OLED_HEIGHT - 13, OLED_WIDTH - 3, OLED_HEIGHT - 13, 1);
  oledBox(5, OLED_HEIGHT - 3, OLED_WIDTH - 3, OLED_HEIGHT - 3, 1);

  permil = permil * (OLED_WIDTH - 4) / 1000;
  if (permil > OLED_WIDTH - 4) {
    permil = OLED_WIDTH - 4;
  }
  oledBox(2, OLED_HEIGHT - 10, 2, OLED_HEIGHT - 6, 1);
  oledBox(3, OLED_HEIGHT - 12, 4, OLED_HEIGHT - 4, 1);
  if (permil > 3) {
    oledBox(5, OLED_HEIGHT - 12, permil + 1, OLED_HEIGHT - 4, 1);
  }

  oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 13, OLED_WIDTH - 3, OLED_HEIGHT - 3, 0);

  oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 12, OLED_WIDTH - 4, OLED_HEIGHT - 11,
          1);
  oledClearPixel(OLED_WIDTH - 5, OLED_HEIGHT - 11);
  oledBox(OLED_WIDTH - 3, OLED_HEIGHT - 10, OLED_WIDTH - 3, OLED_HEIGHT - 6, 1);
  oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 5, OLED_WIDTH - 4, OLED_HEIGHT - 4, 1);
  oledClearPixel(OLED_WIDTH - 5, OLED_HEIGHT - 5);

  if (permil >= OLED_WIDTH - 6) {
    oledBox(OLED_WIDTH - 5, OLED_HEIGHT - 11, OLED_WIDTH - 5, OLED_HEIGHT - 5,
            1);
    if (permil > OLED_WIDTH - 6) {
      oledBox(OLED_WIDTH - 4, OLED_HEIGHT - 11, OLED_WIDTH - 4, OLED_HEIGHT - 5,
              1);
    }
  }
  oledRefresh();
}

void _layout_iterm_select(int x, int y, const BITMAP *bmp, const char *text,
                          uint8_t font, bool vert) {
  int l = 0;
  int y0 = font & FONT_DOUBLE ? 8 : 0;
  oledBox(x - 4, y - 8, x + 4, y + 16 + y0, false);
  if (ui_language == 1) {
    oledDrawBitmap(x - 4, y - 7 + 1, &bmp_arrow_up_w5);
    oledDrawBitmap(x - 4, y + 11 + y0 + 1, &bmp_arrow_down_w5);
  } else {
    oledDrawBitmap(x - 4, y - 7, &bmp_arrow_up_w5);
    oledDrawBitmap(x - 4, y + 11 + y0, &bmp_arrow_down_w5);
  }
  l = oledStringWidth(text, font);
  if (bmp) {
    if (ui_language == 1) {
      oledDrawBitmap(x - 4, y + 2, bmp);
    } else {
      oledDrawBitmap(x - 4, y + 1, bmp);
    }
  } else {
    oledDrawStringAdapter(x - l / 2, y, text, font);
    if (vert) {
      oledInvert(x - l / 2 - 1, y - 1, x + l / 2, y + 8);
      oledClearPixel(x - l / 2 - 1, y - 1);
      oledClearPixel(x - l / 2 - 1, y + 8);
      oledClearPixel(x + l / 2, y - 1);
      oledClearPixel(x + l / 2, y + 8);
    }
  }

  oledRefresh();
}

void layoutItemsSelect(int x, int y, const char *text, uint8_t font) {
  _layout_iterm_select(x, y, NULL, text, font, false);
}

void layoutItemsSelect_ex(int x, int y, const char *text, uint8_t font,
                          bool vert) {
  _layout_iterm_select(x, y, NULL, text, font, vert);
}

void layoutBmpSelect(int x, int y, const BITMAP *bmp) {
  _layout_iterm_select(x, y, bmp, NULL, FONT_STANDARD, false);
}

void layoutInputPin(uint8_t pos, const char *text, int index,
                    bool cancel_allowed) {
  int l, y = 9;
  char pin_show[9] = "_________";
  char table[][2] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", " "};
  char buf[2] = {0};
  int x = 6;

  layoutLast = layoutInputPin;
  for (uint8_t i = 0; i < pos; i++) {
    pin_show[i] = '*';
  }
  oledClear_ex();
  layoutHeader(text);
  y += 18;

  for (uint32_t i = 0; i < sizeof(pin_show); i++) {
    buf[0] = pin_show[i];
    l = oledStringWidth(buf, FONT_STANDARD);
    if (i < pos) {
      if (ui_language == 1) {
        oledDrawBitmap(x + 13 * i + 7 - l / 2, y + 2, &bmp_pin_filled);
      } else {
        oledDrawBitmap(x + 13 * i + 7 - l / 2, y + 1, &bmp_pin_filled);
      }
    } else {
      oledDrawStringAdapter(x + 13 * i + 7 - l / 2, y, buf, FONT_STANDARD);
    }
  }
  if (index < 10) {
    layoutItemsSelect(x + 13 * pos + 7, y, table[index], FONT_STANDARD);
  } else {
    layoutBmpSelect(x + 13 * pos + 7, y, &bmp_input_submit);
  }

  if (pos == 0) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_close);
  } else if (pos != 0 || cancel_allowed) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_delete);
  }

  if ((pos < MAX_PIN_LEN - 1) && (index < 10)) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_arrow);
  } else {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11,
                   &bmp_bottom_right_confirm);
  }

  oledRefresh();
}

void layoutInputWord(const char *text, uint8_t prefix_len, const char *prefix,
                     const char *letter) {
  int l, y = 9;
  char word_show[8] = "________";
  char buf[2] = {0};
  int x = 25;

  for (uint8_t i = 0; i < prefix_len; i++) {
    word_show[i] = prefix[i];
  }
  oledClear_ex();
  layoutHeader(text);
  y += 18;
  for (uint32_t i = 0; i < sizeof(word_show); i++) {
    buf[0] = word_show[i];
    l = oledStringWidth(buf, FONT_STANDARD);
    oledDrawStringAdapter(x + 9 * i + 7 - l / 2, y, buf, FONT_STANDARD);
  }

  layoutItemsSelect(x + 9 * prefix_len + 7, y, letter, FONT_STANDARD);
  oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_arrow);
  oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_arrow);

  oledRefresh();
}

static char *input1[4] = {"a", "A", "0", "="};
static char *inputTitle[4] = {"Switch Input (Lowercase)",
                              "Switch Input (Uppercase)",
                              "Switch Input (Number)", "Switch Input (Symbol)"};

void layoutInputMethod(uint8_t index) {
  layout_item_t items[4] = {
      {.label = "abc", .value = NULL, .center = true},
      {.label = "ABC", .value = NULL, .center = true},
      {.label = "123", .value = NULL, .center = true},
      {.label = "=/<", .value = NULL, .center = true},
  };

  layout_screen_t screen = {
      .bmp_up = &bmp_bottom_middle_arrow_up,
      .bmp_down = &bmp_bottom_middle_arrow_down,
      .bmp_no = &bmp_bottom_left_close,
      .bmp_yes = &bmp_bottom_right_confirm,
      .btn_no = NULL,
      .btn_yes = NULL,
      .title = gettext_from_en(inputTitle[index]),
      .title_space = true,
      .items = items,
      .item_count = 4,
      .item_index = index,
      .item_offset = 0,
      .show_index = true,
      .show_scroll_bar = true,
  };

  layout_screen(screen);
}

void layoutInputPassphrase(const char *text, uint8_t prefix_len,
                           const char *prefix, uint8_t char_index,
                           uint8_t input_type) {
  int l, y = 10;
  char word_show[14] = "______________";
  char buf[2] = {0};
  uint8_t location = 0;
  int x = 0;

  if (prefix_len < 14) {
    memcpy(word_show, prefix, prefix_len);
  } else {
    memcpy(word_show, prefix + prefix_len - 13, 13);
  }
  oledClear_ex();

  layoutHeader(text);

  layout_index_count(prefix_len + 1, 50);

  y += 18;
  if (prefix_len < 14) {
    for (uint32_t i = 0; i < sizeof(word_show); i++) {
      buf[0] = word_show[i];
      l = oledStringWidth(buf, FONT_STANDARD);
      oledDrawStringAdapter(x + 9 * i + 7 - l / 2, y, buf, FONT_STANDARD);
    }
  } else {
    oledDrawStringAdapter(4, y - 3, "...", FONT_STANDARD);
    for (uint32_t i = 1; i < sizeof(word_show); i++) {
      buf[0] = word_show[i];
      l = oledStringWidth(buf, FONT_STANDARD);
      oledDrawStringAdapter(x + 9 * i + 7 - l / 2, y, buf, FONT_STANDARD);
    }
  }

  location = prefix_len > 13 ? 13 : prefix_len;
  if (char_index == 0) {
    layoutItemsSelect_ex(x + 9 * location + 7, y, input1[input_type],
                         FONT_STANDARD, true);
    oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                   &bmp_bottom_right_change);
  } else if (char_index == 0xFF) {
    layoutBmpSelect(x + 9 * location + 7, y, &bmp_btn_confirm);
    oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                   &bmp_bottom_right_confirm);
  } else {
    buf[0] = char_index;
    layoutItemsSelect_ex(x + 9 * location + 7, y, buf, FONT_STANDARD, false);
    if (prefix_len == (MAX_PASSPHRASE_LEN - 1)) {
      oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                     &bmp_bottom_right_confirm);
    } else {
      oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                     &bmp_bottom_right_confirm);
    }
  }

  if (prefix_len == 0) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_close);
  } else {
    oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_delete);
  }

  oledRefresh();
}

void layoutItemsSelectAdapter(const BITMAP *bmp_up, const BITMAP *bmp_down,
                              const BITMAP *bmp_no, const BITMAP *bmp_yes,
                              const char *btnNo, const char *btnYes,
                              uint32_t index, uint32_t count, const char *title,
                              const char *prefex, const char *current,
                              const char *previous, const char *next) {
  int x, l, y, y1;
  int step = 3;
  char index_str[16] = "";
  const struct font_desc *cur_font = find_cur_font();

  y = 0;
  l = 0;

  oledClear_ex();
  if (title) {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, 0, title, FONT_STANDARD);
    y += cur_font->pixel + 1;
    y++;
    oledHLine(y);
    y += 2;
    y1 = 34;
  } else {
    y1 = 28;
  }

  if (index > 0) {
    uint2str(index, index_str);
    strcat(index_str + strlen(index_str), "/");
    uint2str(count, index_str + strlen(index_str));
    oledDrawStringAdapter(0, 0, index_str, FONT_STANDARD | FONT_FIXED);
  }
  if (previous) {
    oledDrawBitmap(60, y, bmp_up);
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y1 - cur_font->pixel - step,
                                previous, FONT_STANDARD);
  }

  if (prefex) {
    char buf[64] = "";
    strcat(buf, prefex);
    strcat(buf, "   ");
    strcat(buf, current);
    l = oledStringWidthAdapter(buf, FONT_STANDARD);
    x = (OLED_WIDTH - l) / 2;
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y1, buf, FONT_STANDARD);
  } else {
    l = oledStringWidthAdapter(current, FONT_STANDARD);
    x = (OLED_WIDTH - l) / 2;
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y1, current, FONT_STANDARD);
  }

  oledInvert(x - 2, y1 - 1, x + l + 1, y1 + cur_font->pixel);
  oledClearPixel(x - 2, y1 - 1);
  oledClearPixel(x - 2, y1 + cur_font->pixel);
  oledClearPixel(x + l + 1, y1 - 1);
  oledClearPixel(x + l + 1, y1 + cur_font->pixel);

  if (next) {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y1 + cur_font->pixel + step,
                                next, FONT_STANDARD);
    oledDrawBitmap(60, OLED_HEIGHT - 8, bmp_down);
  }
  if (btnNo) {
    layoutButtonNoAdapter(btnNo, bmp_no);
  }
  if (btnYes) {
    layoutButtonYesAdapter(btnYes, bmp_yes);
  }

  oledRefresh();
}

void layoutHeader(const char *title) {
#if !EMULATOR
  hide_icon = true;
#endif
  oledBox(0, 0, OLED_WIDTH, 10, false);
  if (0 == ui_language) {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, 2, title, FONT_STANDARD);
  } else {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, 1, title, FONT_STANDARD);
  }
  oledInvert(0, 0, OLED_WIDTH, 10);

  oledBox(0, 0, 2, 2, false);
  oledBox(1, 1, 2, 2, true);
  oledBox(0, 10 - 2, 2, 10, false);
  oledBox(1, 10 - 2, 2, 10 - 1, true);

  oledBox(OLED_WIDTH - 3, 0, OLED_WIDTH - 1, 2, false);
  oledBox(OLED_WIDTH - 3, 1, OLED_WIDTH - 2, 2, true);
  oledBox(OLED_WIDTH - 3, 10 - 2, OLED_WIDTH - 1, 10, false);
  oledBox(OLED_WIDTH - 3, 10 - 3, OLED_WIDTH - 2, 10 - 1, true);
}

void layout_screen_item(int x, int y, layout_item_t item, bool reverse) {
  int l = 0;
  if (item.center) {
    l = oledStringWidthAdapter(item.label, FONT_STANDARD);
    x = (OLED_WIDTH - l) / 2;
    oledDrawStringAdapter(x, y, item.label, FONT_STANDARD);
    if (reverse) {
      if (ui_language == 0) {
        oledInvert(x - 3, y - 2, x + l + 2, y + 8 + 2);
      } else {
        oledInvert(x - 3, y - 1, x + l + 2, y + 9 + 1);
      }
    }
  } else {
    oledDrawStringAdapter(x, y, item.label, FONT_STANDARD);
    if (item.value) {
      l = oledStringWidthAdapter(item.value, FONT_STANDARD);
      oledDrawStringAdapter(OLED_WIDTH - l - 1, y, item.value, FONT_STANDARD);
    }
    if (reverse) {
      if (ui_language == 0) {
        oledInvert(0, y - 2, OLED_WIDTH, y + 8);
      } else {
        oledInvert(0, y - 1, OLED_WIDTH, y + 9);
      }
    }
  }
}

void layout_screen(layout_screen_t screen) {
  int x = 1, y = 1, step = 2, item_height = 9;
  int max_item_count = 4;
  const struct font_desc *cur_font = find_cur_font();

  oledClear_ex();

  if (screen.title || screen.title_space) {
#if !EMULATOR
    hide_icon = true;
#endif
    if (screen.title) {
      layoutHeader(screen.title);
    }
    step = 4;
    y = 18;
    max_item_count = 3;
  } else {
#if !EMULATOR
    hide_icon = false;
#endif
    if (cur_font->pixel > 8) {
      y = 9;
    } else {
      y = 10;
    }
  }

  if (screen.input_desc) {
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y, screen.input_desc,
                                FONT_STANDARD);
  } else {
    int start_index = 0, end_index = 0;

    if (screen.item_count <= max_item_count) {
      start_index = 0;
      end_index = screen.item_count - 1;
    } else {
      int half = max_item_count / 2;

      if (max_item_count % 2 == 0) {
        start_index = screen.item_index - half + 1;
      } else {
        start_index = screen.item_index - half;
      }

      if (start_index < 0) {
        start_index = 0;
      }

      end_index = start_index + max_item_count - 1;
      if (end_index >= screen.item_count) {
        end_index = screen.item_count - 1;
        start_index = end_index - max_item_count + 1;
      }
    }

    for (int i = start_index; i <= end_index; i++) {
      if (i == screen.item_index) {
        layout_screen_item(x, y, screen.items[i - screen.item_offset], true);
      } else {
        layout_screen_item(x, y, screen.items[i - screen.item_offset], false);
      }
      y += item_height + step;
    }

    if ((start_index < screen.item_index || screen.loop) && screen.bmp_up) {
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8, screen.bmp_up);
    }
    if ((end_index > screen.item_index || screen.loop) && screen.bmp_down) {
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8, screen.bmp_down);
    }

    if (screen.show_scroll_bar) {
      drawScrollbar(screen.item_count, screen.item_index);
    }

    if (screen.show_index) {
      layout_index_count(screen.item_index + 1, screen.item_count);
    }

    if (screen.bmp_no) {
      oledDrawBitmap(0, OLED_HEIGHT - 11, screen.bmp_no);
    }
    if (screen.bmp_yes) {
      oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, screen.bmp_yes);
    }
  }
  oledRefresh();
}

void layoutItemsSelectAdapterWords(
    const BITMAP *bmp_up, const BITMAP *bmp_down, const BITMAP *bmp_no,
    const BITMAP *bmp_yes, const char *btnNo, const char *btnYes,
    uint32_t index, uint32_t count, const char *title, const char *input_desc,
    const char *current, const char *previous, const char *pre_previous,
    const char *pre_pre_previous, const char *next, const char *next_next,
    const char *next_next_next, bool show_index, bool is_select) {
  (void)btnNo;
  (void)btnYes;
  int x, l, y, p = 0;
  int item_height = 11;
  y = 1;
  l = 0;
  if (ui_language != 0) p = 1;
  oledClear_ex();
  if (title) {
    layoutHeader(title);
    y = 18;
  } else {
#if !EMULATOR
    hide_icon = false;
#endif
    y = 11;
  }

  if (count > 4 || (title && count > 3)) {
    // scrollbar
    drawScrollbar(count, index - 1);

    if (pre_previous && (index == count)) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, pre_previous,
                                  FONT_STANDARD);
      y += item_height;
    }
    if (previous) {
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8, bmp_up);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, previous,
                                  FONT_STANDARD);
      y += item_height;
    }

    l = oledStringWidthAdapter(input_desc, FONT_STANDARD);
    x = (OLED_WIDTH - l) / 2;
    oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, input_desc,
                                FONT_STANDARD);
    if (l % 2) {
      oledInvert(x - 2, y - 2, x + l + 2, y + item_height - 3);
    } else {
      oledInvert(x - 3, y - 2, x + l + 1, y + item_height - 3);
    }
    y += item_height;

    if (next) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, next, FONT_STANDARD);
      y += item_height;
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8, bmp_down);
    }

    if (next_next && (index == 1)) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, next_next,
                                  FONT_STANDARD);
      y += item_height;
    }

  } else {
    if (count == 1) y = 27;
    if (count == 2) y = 21;
    if (count == 3) y = 18;
    if (pre_pre_previous) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, pre_pre_previous,
                                  FONT_STANDARD);
      y += item_height;
    }
    if (pre_previous) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, pre_previous,
                                  FONT_STANDARD);
      y += item_height;
    }
    if (previous) {
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8, bmp_up);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, previous,
                                  FONT_STANDARD);
      y += item_height;
    }

    l = oledStringWidthAdapter(current, FONT_STANDARD);
    x = (OLED_WIDTH - l) / 2;
    if (is_select) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, current,
                                  FONT_STANDARD);
      if (l % 2) {
        oledInvert(x - 2, y - 2, x + l + 2, y + item_height - 3);
      } else {
        oledInvert(x - 3, y - 2, x + l + 1, y + item_height - 3);
      }
    } else {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, current,
                                  FONT_STANDARD | FONT_DOUBLE);
    }
    y += item_height;

    if (next) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, next, FONT_STANDARD);
      y += item_height;
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8, bmp_down);
    }
    if (next_next) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, next_next,
                                  FONT_STANDARD);
      y += item_height;
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8, bmp_down);
    }
    if (next_next_next) {
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, y - p, next_next_next,
                                  FONT_STANDARD);
      y += item_height;
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8, bmp_down);
    }
  }

  if (show_index) {
    layout_index_count(index, count);
  }

  if (bmp_no) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, bmp_no);
  }
  if (bmp_yes) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, bmp_yes);
  }

  oledRefresh();
}

void layoutWords(const char *title, const BITMAP *bmp_up,
                 const BITMAP *bmp_down, const BITMAP *bmp_no,
                 const BITMAP *bmp_yes, uint32_t index, uint32_t count,
                 const char *word1, const char *word2, const char *word3,
                 const char *word4, const char *word5, const char *word6) {
  char desc[32] = {0};

  oledClear_ex();
  layoutHeader(title);

  // scrollbar
  drawScrollbar(count, index - 1);

  // word1
  memzero(desc, 32);
  uint2str((index - 1) * 6 + 1, desc);
  strcat(desc, ".  ");
  strcat(desc, word1);
  oledDrawString(0, 19, desc, FONT_STANDARD);

  // word2
  memzero(desc, 32);
  uint2str((index - 1) * 6 + 2, desc);
  strcat(desc, ".  ");
  strcat(desc, word2);
  oledDrawString(0, 29, desc, FONT_STANDARD);

  // word3
  memzero(desc, 32);
  uint2str((index - 1) * 6 + 3, desc);
  strcat(desc, ".  ");
  strcat(desc, word3);
  oledDrawString(0, 39, desc, FONT_STANDARD);

  // word4
  memzero(desc, 32);
  uint2str((index - 1) * 6 + 4, desc);
  strcat(desc, ".  ");
  strcat(desc, word4);
  oledDrawString(64, 19, desc, FONT_STANDARD);

  // word5
  memzero(desc, 32);
  uint2str((index - 1) * 6 + 5, desc);
  strcat(desc, ".  ");
  strcat(desc, word5);
  oledDrawString(64, 29, desc, FONT_STANDARD);

  // word6
  memzero(desc, 32);
  uint2str((index - 1) * 6 + 6, desc);
  strcat(desc, ".  ");
  strcat(desc, word6);
  oledDrawString(64, 39, desc, FONT_STANDARD);

  if (bmp_down && (index != count)) {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8, bmp_down);
  }
  if (bmp_up && (index != 1)) {
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8, bmp_up);
  }

  if (bmp_no) {
    oledDrawBitmap(0, OLED_HEIGHT - 11, bmp_no);
  }
  if (bmp_yes) {
    oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, bmp_yes);
  }
  oledRefresh();
}

#define DEVICE_INFO_PAGE_NUM 5
#if EMULATOR
char bootloader_version[8] = "0.0.0";
#else
extern char bootloader_version[8];
#endif

void layouKeyValue(int y, const char *desc, const char *value) {
  oledDrawStringAdapter(0, y, desc, FONT_STANDARD);
  oledDrawStringRightAdapter(OLED_WIDTH - 1, y, value, FONT_STANDARD);
}

bool layoutEraseDevice(void) {
  uint8_t key = KEY_NULL;
  char title[64] = {0};
  strlcpy(title, _(T__WARNING_EXCLAM_BRACKET_STR_BRACKET), 64);
  bracket_replace(title, "1/2");
  key = layoutPagination(
      title,
      _(C__THIS_WILL_ERASE_ALL_DATA_STORED_ON_SE_AND_INTERNAL_STORAGE_INCLUDING_PRIVATE_KEYS_AND_SETTINGS));
  if (key == KEY_CANCEL) return false;
  strlcpy(title, _(T__WARNING_EXCLAM_BRACKET_STR_BRACKET), 64);
  bracket_replace(title, "2/2");
  key = layoutPagination(
      title,
      _(C__RECOVERY_PHRASE_IS_THE_ONLY_WAY_TO_RESTORE_THE_PRIVATE_KEYS_THAT_OWN_YOUR_ASSETS_MAKE_SURE_YOU_STILL_HAVE_BACKUP_OF_CURRENT_WALLET));
  if (key == KEY_CANCEL) return false;

  return true;
}

bool layoutInputDirection(int direction) {
  uint8_t key = KEY_NULL;
  char title[128] = {0};

  oledClear_ex();
  if (direction) {
    strcat(title, _(T__REVERSE_INPUT_DIRECTION));
  } else {
    strcat(title, _(T__DEFAULT_INPUT_DIRECTION));
  }
  // strcat(title, _(T__INPUT_DIRECTION));
  layoutHeader(title);

  if (direction) {
    layoutDialogCenterAdapterV2(
        title, NULL, &bmp_bottom_left_close, &bmp_bottom_right_arrow, NULL,
        NULL, NULL, NULL, NULL, NULL,
        _(C__WHEN_ENTERING_PIN_CLICK_THE_UP_BTN_TO_INCREASE_CLICK_THE_DOWN_BTN_TO_DECREASE));
  } else {
    layoutDialogCenterAdapterV2(
        title, NULL, &bmp_bottom_left_close, &bmp_bottom_right_arrow, NULL,
        NULL, NULL, NULL, NULL, NULL,
        _(C__WHEN_ENTERING_PIN_CLICK_THE_UP_BTN_TO_DECREASE_AND_CLICK_THE_DOWN_BTN_TO_INCREASE));
  }
  switch (ui_language) {
    case I18N_LANG_EN:
      if (direction) {
        oledDrawBitmap(42, 21, &bmp_icon_up);
        oledDrawBitmap(101, 30, &bmp_icon_down);
      } else {
        oledDrawBitmap(42, 21, &bmp_icon_up);
        oledDrawBitmap(10, 39, &bmp_icon_down);
      }
      break;
    case I18N_LANG_ZH_CN:
    case I18N_LANG_ZH_TW:
      oledDrawBitmap(92, 17, &bmp_icon_up);
      oledDrawBitmap(72, 27, &bmp_icon_down);
      break;
    case I18N_LANG_JA:
      if (direction) {
        oledDrawBitmap(17, 22, &bmp_icon_up);
        oledDrawBitmap(50, 32, &bmp_icon_down);
      } else {
        oledDrawBitmap(18, 22, &bmp_icon_up);
        oledDrawBitmap(62, 32, &bmp_icon_down);
      }
      break;
    case I18N_LANG_ES:
      oledDrawBitmap(65, 23, &bmp_icon_up);
      oledDrawBitmap(5, 42, &bmp_icon_down);
      break;
    case I18N_LANG_PT_BR:
      oledDrawBitmap(36, 23, &bmp_icon_up);
      if (direction) {
        oledDrawBitmap(70, 32, &bmp_icon_down);
      } else {
        oledDrawBitmap(66, 32, &bmp_icon_down);
      }
      break;
    case I18N_LANG_DE:
      if (direction) {
        oledDrawBitmap(71, 17, &bmp_icon_up);
        oledDrawBitmap(71, 27, &bmp_icon_down);
      } else {
        oledDrawBitmap(23, 22, &bmp_icon_down);
        oledDrawBitmap(103, 32, &bmp_icon_up);
      }
      break;
    case I18N_LANG_KO_KR:
      oledDrawBitmap(83, 16, &bmp_icon_up);
      oledDrawBitmap(105, 26, &bmp_icon_down);
      break;
    default:
      break;
  }
  oledRefresh();

  WAIT_KEY_OR_ABORT(0, 1, key);
  if (key != KEY_CONFIRM) {
    return false;
  }

  return true;
}

void layoutDeviceParameters(int num) {
  (void)num;
  const struct font_desc *font = find_cur_font();
  char *se_sn = NULL;
  int y = 0;
  int index = 0;
  uint8_t key = KEY_NULL;
  char firmware_ver[32] = "";
  char se_ver[32] = "";
  char bt_ver[32] = "";
  char boot_version[32] = "";
  uint8_t hash[32] = {0};
  char hash_str[12] = {0};
  const image_header *hdr = (const image_header *)FLASH_PTR(
      FLASH_FWHEADER_START);  // allow both v2 and v3 signatures

  data2hexaddr(get_firmware_hash(hdr), 4, hash_str);
  hash_str[7] = 0;
  snprintf(firmware_ver, 32, "%s[%s-%s]", ONEKEY_VERSION,
           BUILD_ID + strlen(BUILD_ID) - 7, hash_str);

  data2hexaddr((uint8_t *)se_get_hash(), 4, hash_str);
  hash_str[7] = 0;
  snprintf(se_ver, 32, "%s[%s-%s]", se_get_version(), se_get_build_id(),
           hash_str);

  memory_bootloader_hash(hash);
  data2hexaddr(hash, 4, hash_str);
  hash_str[7] = 0;
  snprintf(boot_version, 32, "%s[%s]", bootloader_version, hash_str);

  if (ble_build_id_state() && ble_hash_state()) {
    data2hexaddr((uint8_t *)ble_get_hash(), 4, hash_str);
    hash_str[7] = 0;
    snprintf(bt_ver, 32, "%s[%s-%s]", ble_get_ver(), ble_get_build_id(),
             hash_str);
  } else {
    snprintf(bt_ver, 32, "%s", ble_get_ver());
  }

refresh_menu:
  y = 9;
  oledClear_ex();

  layout_index_count(index + 1, DEVICE_INFO_PAGE_NUM);

  switch (index) {
    case 0:

      oledDrawStringAdapter(0, y, _(I__MODEL_UPPERCASE_COLON), FONT_STANDARD);
      y += font->pixel + 1;
      oledDrawStringAdapter(0, y, config_get_device_model(), FONT_STANDARD);
      y += font->pixel + 4;

      oledDrawStringAdapter(0, y, _(I__BLUETOOTH_NAME_UPPERCASE_COLON),
                            FONT_STANDARD);
      y += font->pixel + 1;
      oledDrawStringAdapter(0, y, ble_get_name(), FONT_STANDARD);

      break;
    case 1:

      oledDrawStringAdapter(0, y, _(I__FIRMWARE_UPPERCASE_COLON),
                            FONT_STANDARD);
      y += font->pixel + 1;
      oledDrawStringAdapter(0, y, firmware_ver, FONT_STANDARD);
      y += font->pixel + 4;

      oledDrawStringAdapter(0, y, _(I__BLUETOOTH_UPPERCASE_COLON),
                            FONT_STANDARD);
      y += font->pixel + 1;
      oledDrawStringAdapter(0, y, bt_ver, FONT_STANDARD);
      break;

    case 2:
      oledDrawStringAdapter(0, y, _(I__SE_VERSION_UPPERCASE_COLON),
                            FONT_STANDARD);
      y += font->pixel + 1;
      oledDrawStringAdapter(0, y, se_ver, FONT_STANDARD);
      y += font->pixel + 4;

#if !EMULATOR
      oledDrawStringAdapter(0, y, _(I__BOOTLOADER_UPPERCASE_COLON),
                            FONT_STANDARD);
      y += font->pixel + 1;
      oledDrawStringAdapter(0, y, boot_version, FONT_STANDARD);
      y += font->pixel + 1;
#endif
      break;

    case 3:
      oledDrawStringAdapter(0, y, _(I__SERIAL_NUMBER_UPPERCASE_COLON),
                            FONT_STANDARD);
      y += font->pixel + 1;

      se_get_sn(&se_sn);
      oledDrawStringAdapter(0, y, se_sn, FONT_STANDARD);
      break;
    case 4:
      oledDrawStringAdapter(0, y, _(I__DEVICE_ID_UPPERCASE_COLON),
                            FONT_STANDARD);
      y += font->pixel + 1;

      // split uuid
      char uuid1[32] = {0};
      char uuid2[32] = {0};

      for (int i = 0; i < 2 * UUID_SIZE; i++) {
        uuid1[i] = config_uuid_str[i];
        if (oledStringWidthAdapter(uuid1, FONT_STANDARD) > OLED_WIDTH) {
          uuid1[i] = 0;
          strcat(uuid2, config_uuid_str + i);
          break;
        }
      }

      oledDrawStringAdapter(0, y, uuid1, FONT_STANDARD);
      y += font->pixel + 1;
      oledDrawStringAdapter(0, y, uuid2, FONT_STANDARD);
      break;

    default:
      break;
  }

  if (index == 0) {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
  } else if (index == 4) {
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  } else {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  }
  oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                 &bmp_bottom_right_confirm);

  // drawScrollbar(5, index);
  int i, bar_start = 12 - 3, bar_end = 52;
  int bar_heght = 44 - 2 * (5 - 1);
  for (i = bar_start; i < bar_end; i += 2) {
    oledDrawPixel(OLED_WIDTH - 1, i);
  }
  for (i = bar_start + 2 * ((int)index);
       i < (bar_start + bar_heght + 2 * ((int)index)) - 1; i++) {
    oledDrawPixel(OLED_WIDTH - 1, i);
    oledDrawPixel(OLED_WIDTH - 2, i);
  }

  oledRefresh();
  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (index > 0) {
        index--;
      }
      goto refresh_menu;
    case KEY_DOWN:
      if (index < 4) {
        index++;
      }
      goto refresh_menu;
    case KEY_CONFIRM:
      return;
    case KEY_CANCEL:
      goto refresh_menu;
    default:
      return;
  }
}

void layoutAboutCertifications(int num) {
  (void)num;
  int index = 0;
  uint8_t key = KEY_NULL;

refresh_menu:
  oledClear_ex();

  layout_index_count(index + 1, 4);

  switch (index) {
    case 0:
      oledDrawBitmap((OLED_WIDTH - bmp_Icon_fc.width) / 2, 4, &bmp_Icon_fc);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 40, "FCC ID: 2BB8VC1",
                                  FONT_STANDARD);
      break;
    case 1:
      oledDrawBitmap((OLED_WIDTH - bmp_Icon_bc.width) / 2, 13, &bmp_anatel);
      oledDrawStringCenterAdapter(OLED_WIDTH / 2, 46, "22316-23-16343",
                                  FONT_STANDARD);
      break;
    case 2:
      oledDrawBitmap((OLED_WIDTH - bmp_Icon_bc.width) / 2, 12, &bmp_Icon_bc);
      break;
    case 3:
      oledDrawBitmap(20, 12, &bmp_Icon_ce);
      oledDrawBitmap(72, 12, &bmp_Icon_weee);
      break;
    default:
      break;
  }

  if (index == 0) {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
  } else if (index == 3) {
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  } else {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  }
  oledDrawBitmap(OLED_WIDTH - 16 - 1, OLED_HEIGHT - 11,
                 &bmp_bottom_right_confirm);

  // scrollbar
  // drawScrollbar(3, index);
  int i, bar_start = 12 - 3, bar_end = 52;
  int bar_heght = 44 - 2 * (4 - 1);
  for (i = bar_start; i < bar_end; i += 2) {
    oledDrawPixel(OLED_WIDTH - 1, i);
  }
  for (i = bar_start + 2 * ((int)index);
       i < (bar_start + bar_heght + 2 * ((int)index)) - 1; i++) {
    oledDrawPixel(OLED_WIDTH - 1, i);
    oledDrawPixel(OLED_WIDTH - 2, i);
  }

  oledRefresh();
  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (index > 0) {
        index--;
      }
      goto refresh_menu;
    case KEY_DOWN:
      if (index < 3) {
        index++;
      }
      goto refresh_menu;
    case KEY_CONFIRM:
      return;
    case KEY_CANCEL:
      goto refresh_menu;
    default:
      return;
  }
}

bool layoutEnterSleep(int mode) {
#if !EMULATOR
  static uint32_t system_millis_logo_refresh = 0;

  if (config_getSleepDelayMs() > 0) {
    if (timer_get_sleep_count() >= config_getSleepDelayMs()) {
      if (mode) {
        return true;
      }
      enter_sleep();
    }
  }
  if (layoutLast != layoutScreensaver) {
    // 1000 ms refresh
    if ((timer_ms() - system_millis_logo_refresh) >= 1000) {
      layoutStatusLogoEx(true);
      system_millis_logo_refresh = timer_ms();
    }
  }

#else
  if ((timer_ms() - system_millis_lock_start) >= config_getAutoLockDelayMs()) {
    session_clear(true);
    layoutScreensaver();
  }
#endif
  return false;
}

void layoutScroollbarButtonYesAdapter(const char *btnYes, const BITMAP *icon) {
  const struct font_desc *font = find_cur_font();
  int icon_width = 0;
  if (icon) {
    oledDrawBitmap(OLED_WIDTH - 8 - 4, OLED_HEIGHT - 8 - 1, icon);
    icon_width = icon->width;
  }
  oledDrawStringRightAdapter(OLED_WIDTH - icon_width - 6,
                             OLED_HEIGHT - (font->pixel + 1), btnYes,
                             FONT_STANDARD);
  oledInvert(OLED_WIDTH - oledStringWidthAdapter(btnYes, FONT_STANDARD) -
                 icon_width - 7,
             OLED_HEIGHT - (font->pixel + 2), OLED_WIDTH - 4, OLED_HEIGHT);
}

bool layoutTransactionSign(const char *chain_name, uint64_t chain_id,
                           bool token_transfer, const char *amount,
                           const char *to_str, const char *signer,
                           const char *recipient, const char *token_id,
                           const uint8_t *data, uint16_t len, const char *key1,
                           const char *value1, const char *key2,
                           const char *value2, const char *key3,
                           const char *value3, const char *key4,
                           const char *value4) {
  (void)signer;
  (void)recipient;
  (void)chain_id;
  bool result = false;
  int index = 0, y = 0;
  uint8_t max_index = 2;
  char title[64] = {0};
  char title_data[32] = {0}, bytes_buf[16] = {0};
  uint8_t bubble_key;

  const char **tx_msg = format_tx_message(chain_name);
  if (token_transfer && (token_id == NULL)) {
    strcat(title, _(T__TOKEN_TRANSFER));
  } else {
    strcpy(title, tx_msg[0]);
  }
  strcat(title_data, _(T__VIEW_DATA_BRACKET_STR));
  uint2str(len, bytes_buf);
  strcat(bytes_buf, " bytes");
  bracket_replace(title_data, bytes_buf);

  if (len > 0) max_index++;
  if (key1) max_index++;
  if (key2) max_index++;
  if (key3) max_index++;
  if (key4) max_index++;
  if (!button_request(ButtonRequestType_ButtonRequest_SignTx)) {
    return false;
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;
  bubble_key = KEY_NULL;
  if (1 == index) {  // amount
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__AMOUNT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, amount, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (0 == index) {  // To
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__SEND_TO_COLON), FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(0, y + 10, to_str, FONT_STANDARD,
                                               &bmp_bottom_left_close,
                                               &bmp_bottom_right_arrow);
  } else if (len > 0 && 2 == index) {  // data
    layoutHeader(title_data);
    oledDrawStringAdapter(0, y, _(I__DATA_COLON), FONT_STANDARD);
    bool data_is_printable = is_printable(data, len);
    size_t message_len = (data_is_printable ? len : len * 2) + 1;
    char message[message_len];
    if (data_is_printable) {
      memcpy(message, data, len);
      message[len] = 0;
    } else {
      data2hex(data, len, message);
    }
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, message, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else {  // key*
    layoutHeader(title);
    if (index == (len > 0 ? 3 : 2)) {
      oledDrawStringAdapter(0, y, key1, FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, value1, FONT_STANDARD);
    } else if (index == (len > 0 ? 4 : 3)) {
      oledDrawStringAdapter(0, y, key2, FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, value2, FONT_STANDARD);
    } else if (index == (len > 0 ? 5 : 4)) {
      oledDrawStringAdapter(0, y, key3, FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, value3, FONT_STANDARD);
    } else if (index == (len > 0 ? 6 : 5)) {
      oledDrawStringAdapter(0, y, key4, FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, value4, FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}

bool layoutTransactionSignEVM(const char *chain_name, uint64_t chain_id,
                              bool token_transfer, const char *amount,
                              const char *to_str, const char *signer,
                              const char *recipient, const char *token_id,
                              const uint8_t *data, uint16_t len,
                              const char *key1, const char *value1,
                              const char *key2, const char *value2,
                              const char *key3, const char *value3,
                              const char *key4, const char *value4) {
  (void)signer;
  bool result = false, has_chain_id = false, is_nft_transfer = false;
  int index = 0, tokenid_len = 0, token_id_rowcount = 0;
  int y = 0;
  uint8_t bubble_key;
  uint8_t max_index = 2, nft_total_index = 3, nft_index = 0,
          detail_total_index = 0, detail_index = 0;
  char title[64] = {0};
  char title_data[32] = {0}, bytes_buf[16] = {0};
  char chain_id_str[21] = {0};
  uint32_t rowlen = 21;
  const char **str;
  if (token_id) {
    tokenid_len = strlen(token_id);
    token_id_rowcount = tokenid_len / rowlen + 1;
  }
  if (strncmp(chain_name, "EVM", 3) == 0) {
    has_chain_id = true;
    max_index++;
#if EMULATOR
    snprintf(chain_id_str, 21, "%u", (uint32_t)chain_id);
#else
    snprintf(chain_id_str, 21, "%lu", (uint32_t)chain_id);
#endif
  }

  const char **tx_msg = format_tx_message(chain_name);
  if (token_transfer && (token_id == NULL)) {
    strcat(title, _(T__TOKEN_TRANSFER));
  } else if (token_transfer && (token_id != NULL)) {
    strcat(title, _(T__NFT_TRANSFER));
    is_nft_transfer = true;
  } else {
    snprintf(title, 64, "%s", _(T__STR_CHAIN_TRANSACTION));
    bracket_replace(title, chain_name);
  }
  strcat(title_data, _(T__VIEW_DATA_BRACKET_STR));
  uint2str(len, bytes_buf);
  strcat(bytes_buf, " bytes");
  bracket_replace(title_data, bytes_buf);

  bool show_raw_data = len > 0 && !is_nft_transfer && !token_transfer;
  if (show_raw_data) max_index++;
  if (key1) detail_total_index++;
  if (key2) detail_total_index++;
  if (key3) detail_total_index++;
  if (key4) detail_total_index++;
  if (token_id_rowcount > 3) nft_total_index = 4;
  if (!is_nft_transfer) detail_total_index++;

  if (!button_request(ButtonRequestType_ButtonRequest_SignTx)) {
    return false;
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  bubble_key = KEY_NULL;
  y = 13;
  if (has_chain_id && (0 == index)) {
    char warning[64] = {0};
    snprintf(warning, 64, "%s", _(C__UNKNOWN_EVM_CHAIN_THE_CHAIN_ID_IS_STR));
    bracket_replace(warning, chain_id_str);
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                                NULL, NULL, warning);
  } else if (is_nft_transfer && index == (has_chain_id ? 2 : 1)) {
    nft_index = 0;
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(title);
      if (0 == nft_index) {
        oledDrawStringAdapter(0, y, _(I__AMOUNT_COLON), FONT_STANDARD);
        oledDrawStringAdapter(0, y + 10, amount, FONT_STANDARD);
        layoutButtonNoAdapter(NULL, has_chain_id ? &bmp_bottom_left_arrow
                                                 : &bmp_bottom_left_close);
        layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      } else if (1 == nft_index) {
        oledDrawStringAdapter(0, y, _(I__TOKEN_CONTRACT_COLON), FONT_STANDARD);
        oledDrawStringAdapter(0, y + 10, to_str, FONT_STANDARD);
        layoutButtonNoAdapter(NULL, has_chain_id ? &bmp_bottom_left_arrow
                                                 : &bmp_bottom_left_close);
        layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      } else if (2 == nft_index) {
        if (token_id_rowcount > 3) {
          str = split_message((const uint8_t *)token_id, tokenid_len, rowlen);
          oledDrawStringAdapter(0, 13, _(I__TOKEN_ID_COLON), FONT_STANDARD);
          oledDrawStringAdapter(0, 13 + 1 * 10, str[0], FONT_STANDARD);
          oledDrawStringAdapter(0, 13 + 2 * 10, str[1], FONT_STANDARD);
          oledDrawStringAdapter(0, 13 + 3 * 10, str[2], FONT_STANDARD);
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        } else {
          oledDrawStringAdapter(0, y, _(I__TOKEN_ID_COLON), FONT_STANDARD);
          oledDrawStringAdapter(0, y + 10, token_id, FONT_STANDARD);
        }

        layoutButtonNoAdapter(NULL, has_chain_id ? &bmp_bottom_left_arrow
                                                 : &bmp_bottom_left_close);
        layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      } else if (3 == nft_index) {
        str = split_message((const uint8_t *)token_id, tokenid_len, rowlen);
        oledDrawStringAdapter(0, 13, _(I__TOKEN_ID_COLON), FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[3], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[4], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[5], FONT_STANDARD);
        layoutButtonNoAdapter(NULL, has_chain_id ? &bmp_bottom_left_arrow
                                                 : &bmp_bottom_left_close);
        layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      }

      drawScrollbar(nft_total_index, nft_index);

      layout_index_count(nft_index + 1, nft_total_index);

      if (nft_index == 0) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
      } else if (nft_index == nft_total_index - 1) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        index = 0;  // exit
        break;
      }
      if (bubble_key == KEY_UP) {
        if (nft_index > 0) {
          nft_index--;
        }
      }
      if (bubble_key == KEY_DOWN) {
        if (nft_index < nft_total_index - 1) {
          nft_index++;
        }
      }
      if (bubble_key == KEY_CONFIRM) {
        break;
      }
    }

  } else if (index == (has_chain_id ? 1 : 0)) {  // To
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__SEND_TO_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, is_nft_transfer ? recipient : to_str,
                          FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if ((is_nft_transfer && index == (has_chain_id ? 3 : 2)) ||
             (!is_nft_transfer &&
              index == (has_chain_id ? 2 : 1))) {  // details
    detail_index = 0;
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(_(T__TRANSACTION_DETAILS));
      int adjusted_index = is_nft_transfer ? detail_index : detail_index - 1;
      if (!is_nft_transfer && 0 == detail_index) {
        oledDrawStringAdapter(0, y, _(I__AMOUNT_COLON), FONT_STANDARD);
        oledDrawStringAdapter(0, y + 10, amount, FONT_STANDARD);
      } else if (adjusted_index >= 0 && adjusted_index < 4) {
        const char *keys[] = {key1, key2, key3, key4};
        const char *values[] = {value1, value2, value3, value4};
        if (keys[adjusted_index] && values[adjusted_index]) {
          oledDrawStringAdapter(0, y, keys[adjusted_index], FONT_STANDARD);
          oledDrawStringAdapter(0, y + 10, values[adjusted_index],
                                FONT_STANDARD);
        }
      }
      // scrollbar
      drawScrollbar(detail_total_index, detail_index);
      layoutButtonNoAdapter(NULL, (detail_total_index - 1 == detail_index)
                                      ? &bmp_bottom_left_close
                                      : &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);

      layout_index_count(detail_index + 1, detail_total_index);

      if (detail_index == 0) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
      } else if (detail_index == detail_total_index - 1) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        index = 0;  // exit
        break;
      } else if (bubble_key == KEY_CONFIRM) {
        break;
      } else if (bubble_key == KEY_UP) {
        if (detail_index > 0) {
          detail_index--;
        }
      } else if (bubble_key == KEY_DOWN) {
        if (detail_index < detail_total_index - 1) {
          detail_index++;
        }
      }
    }
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else if (show_raw_data) {  // data
    layoutHeader(title_data);
    bool data_is_printable = is_printable(data, len);
    size_t message_len = (data_is_printable ? len : len * 2) + 1;
    char message[message_len];
    if (data_is_printable) {
      memcpy(message, data, len);
      message[len] = 0;
    } else {
      data2hex(data, len, message);
    }
    oledDrawStringAdapter(0, y, _(I__DATA_COLON), FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, message, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}

bool layoutTransactionSafeApproveHash(const char *chain_name,
                                      const char *to_addr, const char *signer,
                                      const char *approve_hash,
                                      const char *nonce, const char *gas_fee,
                                      const char *max_fee_per_gas,
                                      const char *max_priority_fee_per_gas,
                                      const char *chain_id_str) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t bubble_key;
  uint8_t max_index = 6, detail_total_index = 1, detail_index = 0;

  const char **tx_msg = format_tx_message(chain_name);

  if (max_fee_per_gas) detail_total_index++;
  if (max_priority_fee_per_gas) detail_total_index++;

  if (!button_request(ButtonRequestType_ButtonRequest_SignTx)) {
    return false;
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  bubble_key = KEY_NULL;
  y = 13;
  if (index == 0) {  // to address
    layoutHeader(_(T_CONFIRM_SAFE_TX));
    oledDrawStringAdapter(0, y, _(I__SEND_TO_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, to_addr, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {  // from address
    layoutHeader(_(T_CONFIRM_SAFE_TX));
    ;
    oledDrawStringAdapter(0, y, _(I__ACCOUNT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, signer, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 2) {  // details
    detail_index = 0;
    const char *keys[] = {
        _(I__ETH_MAXIMUM_FEE_COLON),
        _(I__MAXIMUM_FEE_PER_GAS_COLON),
        _(I__PRIORITY_FEE_PER_GAS_COLON),
    };
    const char *values[] = {gas_fee, max_fee_per_gas, max_priority_fee_per_gas};
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(_(T__TRANSACTION_DETAILS));
      if (detail_index < detail_total_index) {
        if (keys[detail_index] && values[detail_index]) {
          oledDrawStringAdapter(0, y, keys[detail_index], FONT_STANDARD);
          oledDrawStringAdapter(0, y + 10, values[detail_index], FONT_STANDARD);
        }
      }
      // scrollbar
      drawScrollbar(detail_total_index, detail_index);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);

      layout_index_count(detail_index + 1, detail_total_index);

      if (detail_index == 0) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
      } else if (detail_index == detail_total_index - 1) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        break;
      } else if (bubble_key == KEY_CONFIRM) {
        break;
      } else if (bubble_key == KEY_UP) {
        if (detail_index > 0) {
          detail_index--;
        }
      } else if (bubble_key == KEY_DOWN) {
        if (detail_index < detail_total_index - 1) {
          detail_index++;
        }
      }
    }
  } else if (index == 3) {  // approve hash
    layoutHeader(_(T_CONFIRM_SAFE_TX));
    oledDrawStringAdapter(0, y, "SafeTxHash", FONT_STANDARD);
    bubble_key = oledDrawPageableStringAdapter(
        0, y + 10, approve_hash, FONT_STANDARD, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow);
  } else if (index == 4) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, y, "Nonce", FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, nonce, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 5) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, y, "ChainID", FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, chain_id_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}
bool layoutTransactionEIP7702(
    const char *chain_name, const char *delegator_address,
    const char *delegator_name, const char *delegator_network, bool is_revoke,
    const char *signer, const char *key1, const char *value1, const char *key2,
    const char *value2, const char *key3, const char *value3, const char *key4,
    const char *value4, const char *key5, const char *value5) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t bubble_key;
  uint8_t max_index = 3 + (is_revoke ? 0 : 1), detail_total_index = 1,
          detail_index = 0;
  char title[64] = {0};
  if (is_revoke) {
    strcat(title, _(T_REVOKE_SMART_ACCOUNT_DELEGATION));
  } else {
    strcat(title, _(T_UPGRADE_SMART_ACCOUNT));
  }
  const char **tx_msg = format_tx_message(chain_name);

  if (key1) detail_total_index++;
  if (key2) detail_total_index++;
  if (key3) detail_total_index++;
  if (key4) detail_total_index++;
  if (key5) detail_total_index++;

  if (!button_request(ButtonRequestType_ButtonRequest_SignTx)) {
    return false;
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  bubble_key = KEY_NULL;
  y = 13;
  if (index == 0) {
    char warning[168] = {0};
    if (!is_revoke) {
      snprintf(warning, sizeof(warning), "%s",
               _(I_UPGRADING_SMART_ACCOUNT_WARNING));
      bracket_replace(warning, delegator_name);
    }
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
        is_revoke ? _(I_REVOKE_SMART_ACCOUNT_WARNING) : warning);
  } else if (index == 1) {  // Authority address
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__ACCOUNT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, signer, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 2 && !is_revoke) {  // Delegator address
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I_DELEGATE_TO), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, delegator_address, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == (2 + (is_revoke ? 0 : 1))) {  // details
    detail_index = 0;
    while (1) {
      layoutSwipe();
      oledClear();
      layoutHeader(title);
      if (detail_index < detail_total_index) {
        const char *keys[] = {
            is_revoke ? _(I_REVOKE_ON_NETWORK) : _(I_DELEGATE_ON_NETWORK),
            key1,
            key2,
            key3,
            key4,
            key5};
        const char *values[] = {
            delegator_network, value1, value2, value3, value4, value5};
        if (keys[detail_index] && values[detail_index]) {
          oledDrawStringAdapter(0, y, keys[detail_index], FONT_STANDARD);
          oledDrawStringAdapter(0, y + 10, values[detail_index], FONT_STANDARD);
        }
      }
      // scrollbar
      drawScrollbar(detail_total_index, detail_index);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);

      layout_index_count(detail_index + 1, detail_total_index);

      if (detail_index == 0) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
      } else if (detail_index == detail_total_index - 1) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_down);
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                       &bmp_bottom_middle_arrow_up);
      }
      oledRefresh();
      WAIT_KEY_OR_ABORT(0, 0, bubble_key);
      if (bubble_key == KEY_CANCEL) {
        break;
      } else if (bubble_key == KEY_CONFIRM) {
        break;
      } else if (bubble_key == KEY_UP) {
        if (detail_index > 0) {
          detail_index--;
        }
      } else if (bubble_key == KEY_DOWN) {
        if (detail_index < detail_total_index - 1) {
          detail_index++;
        }
      }
    }
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}

bool layoutBlindSign(const char *chain_name, bool is_contract,
                     const char *contract_address, const char *address,
                     const uint8_t *data, uint16_t len, const char *key1,
                     const char *value1, const char *key2, const char *value2,
                     const char *key3, const char *value3) {
  bool result = false, is_details_page = false;
  int index = 0, sub_index = 0;
  int i, bar_heght, bar_start = 12, bar_end = 52;
  uint8_t max_index = 6, detail_total_index = 0, detail_index = 0;
  uint8_t key = KEY_NULL;
  char title_data[32] = {0}, bytes_buf[16] = {0};
  char lines[21] = {0};
  uint32_t rowlen = 21;
  const char **str;
  uint32_t addrlen = strlen(address);
  int address_rowcount = addrlen / rowlen + 1;
  int data_rowcount = len % 10 ? len / 10 + 1 : len / 10;
  const char **tx_msg = format_tx_message(chain_name);

  if (key1) detail_total_index++;
  if (key2) detail_total_index++;
  if (key3) detail_total_index++;
  if (key1 == NULL && key2 == NULL && key3 == NULL) max_index--;

  strcat(title_data, _(T__VIEW_DATA_BRACKET_STR));
  uint2str(len, bytes_buf);
  strcat(bytes_buf, " bytes");
  bracket_replace(title_data, bytes_buf);

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

#if !EMULATOR
  enableLongPress(true);
#endif

refresh_layout:
  layoutSwipe();
  oledClear();
  if (0 == index) {
    is_details_page = false;
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__UNBALE_TO_DECODE_TX_DATA_SIGN_AT_YOUR_OWN_RISK_EXCLAM));
  } else if (1 == index) {
    is_details_page = false;
    layoutHeader(tx_msg[0]);
    if (is_contract) {
      oledDrawStringAdapter(0, 13, _(I__CONTRACT_ADDRESS_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, contract_address, FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, 13, _(I__FORMAT_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, _(I__UNKNOWN), FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (2 == index) {
    is_details_page = false;
    layoutHeader(tx_msg[0]);
    if (address_rowcount > 3) {
      str = split_message((const uint8_t *)address, addrlen, rowlen);
      if (0 == sub_index) {
        oledDrawStringAdapter(0, 13, _(I__SIGNER_COLON), FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[0], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[2], FONT_STANDARD);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else {
        oledDrawStringAdapter(0, 13, str[sub_index - 1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[sub_index], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[sub_index + 1],
                              FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[sub_index + 2],
                              FONT_STANDARD);
        if (sub_index == address_rowcount - 3) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }
      }

      // scrollbar
      drawScrollbar(2, sub_index);

    } else {
      oledDrawStringAdapter(0, 13, _(I__SIGNER_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, address, FONT_STANDARD);
    }

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (3 == index) {
    is_details_page = false;
    layoutHeader(title_data);
    if (data_rowcount > 4) {
      data2hexaddr(data + 10 * (sub_index), 10, lines);
      oledDrawStringAdapter(0, 13, lines, FONT_STANDARD);
      data2hexaddr(data + 10 * (sub_index + 1), 10, lines);
      oledDrawStringAdapter(0, 13 + 1 * 10, lines, FONT_STANDARD);
      data2hexaddr(data + 10 * (sub_index + 2), 10, lines);
      oledDrawStringAdapter(0, 13 + 2 * 10, lines, FONT_STANDARD);
      if (sub_index == data_rowcount - 4) {
        if (len % 10) {
          memset(lines, 0, 21);
          data2hexaddr(data + 10 * (sub_index + 3), len % 10, lines);
        } else {
          data2hexaddr(data + 10 * (sub_index + 3), 10, lines);
        }
      } else {
        data2hexaddr(data + 10 * (sub_index + 3), 10, lines);
      }
      oledDrawStringAdapter(0, 13 + 3 * 10, lines, FONT_STANDARD);

      // scrollbar
      bar_heght = 40 - 2 * (data_rowcount - 5);
      if (bar_heght < 6) bar_heght = 6;
      for (i = bar_start; i < bar_end; i += 2) {  // 40 pixel
        oledDrawPixel(OLED_WIDTH - 1, i);
      }
      if (sub_index <= 18) {
        for (i = bar_start + 2 * ((int)sub_index);
             i < (bar_start + bar_heght + 2 * ((int)sub_index - 1)) - 1; i++) {
          oledDrawPixel(OLED_WIDTH - 1, i);
          oledDrawPixel(OLED_WIDTH - 2, i);
        }
      } else {
        for (i = bar_start + 2 * 18;
             i < (bar_start + bar_heght + 2 * (18 - 1)) - 1; i++) {
          oledDrawPixel(OLED_WIDTH - 1, i);
          oledDrawPixel(OLED_WIDTH - 2, i);
        }
      }

      if (sub_index == 0) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else if (sub_index == data_rowcount - 4) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      }
    } else {
      char buf[90] = {0};
      data2hexaddr(data, len, buf);
      oledDrawStringAdapter(0, 13, buf, FONT_STANDARD);
    }

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index - 1 == index) {
    is_details_page = false;
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else {
    sub_index = 0;
    is_details_page = true;
    layoutHeader(_(T__TRANSACTION_DETAILS));
    if (0 == detail_index) {
      oledDrawStringAdapter(0, 13, key1, FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, value1, FONT_STANDARD);
    } else if (1 == detail_index) {
      oledDrawStringAdapter(0, 13, key2, FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, value2, FONT_STANDARD);
    } else if (2 == detail_index) {
      oledDrawStringAdapter(0, 13, key3, FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, value3, FONT_STANDARD);
    }
    // scrollbar
    drawScrollbar(detail_total_index, detail_index);
    if (detail_total_index - 1 == detail_index) {
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    } else {
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    }
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);

    // index
    layout_index_count(detail_index + 1, detail_total_index);

    if (detail_index == 0) {
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                     &bmp_bottom_middle_arrow_down);
    } else if (detail_index == detail_total_index - 1) {
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                     &bmp_bottom_middle_arrow_up);
    } else {
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 7,
                     &bmp_bottom_middle_arrow_down);
      oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 7,
                     &bmp_bottom_middle_arrow_up);
    }
  }
  oledRefresh();

  WAIT_KEY_OR_ABORT(0, 0, key);
#if !EMULATOR
  if (isLongPress(KEY_UP_OR_DOWN) && getLongPressStatus()) {
    if (isLongPress(KEY_UP)) {
      key = KEY_UP;
    } else if (isLongPress(KEY_DOWN)) {
      key = KEY_DOWN;
    }
    delay_ms(75);
  }
#endif
  switch (key) {
    case KEY_UP:
      if (sub_index > 0) {
        sub_index--;
      }
      if (is_details_page && (detail_index > 0)) {
        detail_index--;
      }
      goto refresh_layout;
    case KEY_DOWN:
      if (index == 2 && sub_index < address_rowcount - 3) {
        sub_index++;
      }
      if (index == 3 && sub_index < data_rowcount - 4) {
        sub_index++;
      }
      if (is_details_page && (detail_index < (detail_total_index - 1))) {
        detail_index++;
      }
      goto refresh_layout;
    case KEY_CONFIRM:
      sub_index = 0;
      if (index == max_index - 1) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      goto refresh_layout;
    case KEY_CANCEL:
      sub_index = 0;
      if (0 == index || index == max_index - 1) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_layout;
    default:
      break;
  }

#if !EMULATOR
  enableLongPress(false);
#endif
  return result;
}

bool layoutSignMessage(const char *chain_name, bool verify, const char *signer,
                       const uint8_t *data, uint16_t len, bool is_printable,
                       const char *item_name, const char *item_value,
                       bool is_unsafe) {
  bool result = false;
  int index = 0;
  uint8_t max_index = 2;
  if (item_name != NULL) {
    max_index++;
  }
  uint8_t bubble_key;
  char title[64] = {0};
  char warning_content[64] = {0};

  if (verify) {
    strcat(title, _(T__VERIFY_MESSAGE));
    strcat(warning_content, _(C__DO_YOU_WANT_TO_VERIFY_THIS_MESSAGE_QUES));
  } else {
    snprintf(title, 64, "%s", _(T__CHAIN_STR_MESSAGE));
    bracket_replace(title, chain_name);
    snprintf(warning_content, 64, "%s",
             _(C__DO_YOU_WANT_TO_SIGN_THIS_CHAIN_STR_MESSAGE_QUES));
    bracket_replace(warning_content, chain_name);
  }
  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_ProtectCall;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_menu:
  layoutSwipe();
  oledClear();
  uint8_t y = 13;
  layoutHeader(title);
  bubble_key = KEY_NULL;
  if (is_unsafe && index == 0) {
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                                NULL, NULL,
                                _(SECURITY__SOLANA_RAW_SIGNING_TX_WARNING));
    while (1) {
      uint8_t key = KEY_NULL;
      WAIT_KEY_OR_ABORT(0, 0, key);
      if (key == KEY_CANCEL) {
        return false;
      } else if (key == KEY_CONFIRM) {
        oledClear();
        layoutHeader(title);
        break;
      }
      delay_ms(10);
    }
  }
  if (0 == index) {
    oledDrawStringAdapter(0, y, _(I__SIGNER_COLON), FONT_STANDARD);
    if (strlen(signer) > 63) {
      bubble_key = oledDrawPageableStringAdapter(
          0, y + 10, signer, FONT_STANDARD, &bmp_bottom_left_close,
          &bmp_bottom_right_arrow);
    } else {
      oledDrawStringAdapter(0, y + 10, signer, FONT_STANDARD);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      oledRefresh();
      while (1) {
        uint8_t key = KEY_NULL;
        WAIT_KEY_OR_ABORT(0, 0, key);
        if (key == KEY_CANCEL || key == KEY_CONFIRM) {
          bubble_key = key;
          break;
        }
        delay_ms(10);
      }
    }
  } else if (index == max_index - 1) {
    char message_colon[16] = {0};
    strcat(message_colon, _(MESSAGE));
    strcat(message_colon, ":");
    oledDrawStringAdapter(0, y, message_colon, FONT_STANDARD);
    size_t message_len = (is_printable ? len : len * 2) + 1;
    char message[message_len];
    if (is_printable) {
      memcpy(message, data, len);
      message[len] = 0;
    } else {
      data2hex(data, len, message);
    }
    if (strlen(message) > 63) {
      bubble_key = oledDrawPageableStringAdapter(
          0, y + 10, message, FONT_STANDARD, &bmp_bottom_left_arrow,
          &bmp_bottom_right_arrow);
    } else {
      oledDrawStringAdapter(0, y + 10, message, FONT_STANDARD);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    }
  } else if (index == max_index - 2 && item_name != NULL) {
    oledDrawStringAdapter(0, y, item_name, FONT_STANDARD);
    if (strlen(item_value) > 63) {
      bubble_key = oledDrawPageableStringAdapter(
          0, y + 10, item_value, FONT_STANDARD, &bmp_bottom_left_arrow,
          &bmp_bottom_right_arrow);
    } else {
      oledDrawStringAdapter(0, y + 10, item_value, FONT_STANDARD);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    }
  } else {
    oledDrawStringAdapter(0, y, warning_content, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();
  HANDLE_KEY(bubble_key);
}

bool layoutNostrEncryptMessage(const char *chain_name, bool en,
                               const char *signer, const uint8_t *data,
                               uint16_t len, bool is_ascii) {
  (void)chain_name;
  bool result = false;
  int index = 0, sub_index = 0, data_rowcount;
  int i, bar_heght, bar_start = 12, bar_end = 52;
  uint8_t max_index = 3;
  uint8_t key = KEY_NULL;
  char title[64] = {0};
  char title_tx[128] = {0};
  char lines[21] = {0};
  uint32_t rowlen = 21;
  const char **str;
  uint32_t addrlen = strlen(signer);
  int address_rowcount = addrlen / rowlen + 1;
  if (!is_ascii) {
    data_rowcount = len % 10 ? len / 10 + 1 : len / 10;
  } else {
    data_rowcount = len % 20 ? len / 20 + 1 : len / 20;
  }

#if !EMULATOR
  enableLongPress(true);
#endif

  // todo
  if (en) {
    snprintf(title, 64, "%s", "Encrypt Nostr Message");
    snprintf(title_tx, 128, "%s", "Do you want to encrypt\nNostr message?");
  } else {
    snprintf(title, 64, "%s", "Decrypt Nostr Message");
    snprintf(title_tx, 128, "%s", "Do you want to decrypt\nNostr message?");
  }

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_layout:
  layoutSwipe();
  oledClear();

  if (0 == index) {
    layoutHeader(title);
    if (address_rowcount > 4) {
      str = split_message((const uint8_t *)signer, addrlen, rowlen);
      if (0 == sub_index) {
        oledDrawStringAdapter(0, 13, "Signed by:", FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[0], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[2], FONT_STANDARD);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else {
        oledDrawStringAdapter(0, 13, str[sub_index - 1], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 1 * 10, str[sub_index], FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 2 * 10, str[sub_index + 1],
                              FONT_STANDARD);
        oledDrawStringAdapter(0, 13 + 3 * 10, str[sub_index + 2],
                              FONT_STANDARD);
        if (sub_index == address_rowcount - 3) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }
      }

      // scrollbar
      drawScrollbar(2, sub_index);
    } else {
      oledDrawStringAdapter(0, 13, "Signer:", FONT_STANDARD);
      oledDrawStringAdapter(0, 13 + 10, signer, FONT_STANDARD);
    }

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (1 == index) {
    layoutHeader(title);
    if (data_rowcount > 4) {
      if (is_ascii) {
        memcpy(lines, data + 20 * (sub_index), 20);
        oledDrawStringAdapter(0, 13, lines, FONT_STANDARD);
        memcpy(lines, data + 20 * (sub_index + 1), 20);
        oledDrawStringAdapter(0, 13 + 1 * 10, lines, FONT_STANDARD);
        memcpy(lines, data + 20 * (sub_index + 2), 20);
        oledDrawStringAdapter(0, 13 + 2 * 10, lines, FONT_STANDARD);
        if (sub_index >= data_rowcount - 4) {
          if (len % 20) {
            memset(lines, 0, 21);
            memcpy(lines, data + 20 * (sub_index + 3), len % 20);
          } else {
            memcpy(lines, data + 20 * (sub_index + 3), 20);
          }
        } else {
          memcpy(lines, data + 20 * (sub_index + 3), 20);
        }
        oledDrawStringAdapter(0, 13 + 3 * 10, lines, FONT_STANDARD);
      } else {
        data2hexaddr(data + 10 * (sub_index), 10, lines);
        oledDrawStringAdapter(0, 13, lines, FONT_STANDARD);
        data2hexaddr(data + 10 * (sub_index + 1), 10, lines);
        oledDrawStringAdapter(0, 13 + 1 * 10, lines, FONT_STANDARD);
        data2hexaddr(data + 10 * (sub_index + 2), 10, lines);
        oledDrawStringAdapter(0, 13 + 2 * 10, lines, FONT_STANDARD);
        if (sub_index >= data_rowcount - 4) {
          if (len % 10) {
            data2hexaddr(data + 10 * (sub_index + 3), len % 10, lines);
          } else {
            data2hexaddr(data + 10 * (sub_index + 3), 10, lines);
          }
        } else {
          data2hexaddr(data + 10 * (sub_index + 3), 10, lines);
        }
        oledDrawStringAdapter(0, 13 + 3 * 10, lines, FONT_STANDARD);
      }

      // scrollbar
      bar_heght = 40 - 2 * (data_rowcount - 5);
      if (bar_heght < 6) bar_heght = 6;
      for (i = bar_start; i < bar_end; i += 2) {  // 40 pixel
        oledDrawPixel(OLED_WIDTH - 1, i);
      }
      if (sub_index <= 18) {
        for (i = bar_start + 2 * ((int)sub_index);
             i < (bar_start + bar_heght + 2 * ((int)sub_index - 1)) - 1; i++) {
          oledDrawPixel(OLED_WIDTH - 1, i);
          oledDrawPixel(OLED_WIDTH - 2, i);
        }
      } else {
        for (i = bar_start + 2 * 18;
             i < (bar_start + bar_heght + 2 * (18 - 1)) - 1; i++) {
          oledDrawPixel(OLED_WIDTH - 1, i);
          oledDrawPixel(OLED_WIDTH - 2, i);
        }
      }

      if (sub_index == 0) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else if (sub_index == data_rowcount - 4) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      }
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);
    } else {
      if (is_ascii) {
        oledDrawStringAdapter(0, 13, (char *)data, FONT_STANDARD);
      } else {
        char buf[90] = {0};
        data2hexaddr(data, len, buf);
        oledDrawStringAdapter(0, 13, buf, FONT_STANDARD);
      }
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    }
  } else {
    if (en) {
      layoutHeader("Encrypt Message");
    } else {
      layoutHeader("Decrypt Message");
    }
    oledDrawStringAdapter(0, 13, title_tx, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();

  WAIT_KEY_OR_ABORT(0, 0, key);
#if !EMULATOR
  if (isLongPress(KEY_UP_OR_DOWN) && getLongPressStatus()) {
    if (isLongPress(KEY_UP)) {
      key = KEY_UP;
    } else if (isLongPress(KEY_DOWN)) {
      key = KEY_DOWN;
    }
    delay_ms(75);
  }
#endif
  switch (key) {
    case KEY_UP:
      if (sub_index > 0) {
        sub_index--;
      }
      goto refresh_layout;
    case KEY_DOWN:
      if (index == 0 && sub_index < address_rowcount - 3) {
        sub_index++;
      }
      if (index == 1 && sub_index < data_rowcount - 4) {
        sub_index++;
      }
      goto refresh_layout;
    case KEY_CONFIRM:
      if (index == max_index - 1) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      sub_index = 0;
      goto refresh_layout;
    case KEY_CANCEL:
      if (0 == index || index == max_index - 1) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_layout;
    default:
      break;
  }

#if !EMULATOR
  enableLongPress(false);
#endif
  return result;
}

bool layoutSignHash(const char *chain_name, bool verify, const char *signer,
                    const char *domain_hash, const char *message_hash,
                    const char *warning) {
  (void)warning;
  bool result = false;
  int index = 0;
  uint8_t max_index = 5;
  uint8_t key = KEY_NULL;
  char title[64] = {0};
  char title_tx[64] = {0};
  char domain_desc[32] = {0};
  if (!message_hash) max_index--;

  strcat(domain_desc, _(T__DOMAIN_HASH));

  if (verify) {
    strcat(title, _(T__CONFIRM_ADDRESS));
    strcat(title_tx, _(C__DO_YOU_WANT_TO_VERIFY_THIS_MESSAGE_QUES));
  } else {
    snprintf(title, 64, "%s", _(T__CHAIN_STR_MESSAGE));
    bracket_replace(title, chain_name);
    snprintf(title_tx, 64, "%s",
             _(C__DO_YOU_WANT_TO_SIGN_THIS_CHAIN_STR_TRANSACTION_QUES));
    bracket_replace(title_tx, chain_name);
  }

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_layout:
  layoutSwipe();
  oledClear();

  if (0 == index) {
    // Unable to decode EIP-712 data. Sign at your own risk
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__UNBALE_TO_DECODE_TX_DATA_SIGN_AT_YOUR_OWN_RISK_EXCLAM));
  } else if (1 == index) {
    layoutHeader(title);
    oledDrawStringAdapter(0, 13, _(I__SIGNER_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, signer, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (2 == index) {
    layoutHeader(domain_desc);
    oledDrawStringAdapter(0, 13, domain_hash, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (3 == index && message_hash) {
    layoutHeader(_(T__MESSAGE_HASH));
    oledDrawStringAdapter(0, 13, message_hash, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else {
    layoutHeader(title);
    oledDrawStringAdapter(0, 13, title_tx, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();

  WAIT_KEY_OR_ABORT(0, 0, key);
  switch (key) {
    case KEY_UP:
      goto refresh_layout;
    case KEY_DOWN:
      goto refresh_layout;
    case KEY_CONFIRM:
      if (index == max_index - 1) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      goto refresh_layout;
    case KEY_CANCEL:
      if (0 == index || index == max_index - 1) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_layout;
    default:
      break;
  }

  return result;
}

bool layoutSignSchnorrHash(const char *chain_name, const char *signer,
                           const char *hash) {
  bool result = false;
  int index = 0;
  uint8_t max_index = 3;
  uint8_t key = KEY_NULL;
  char title[64] = {0};
  char title_tx[64] = {0};

  snprintf(title, 64, "%s %s", chain_name, "message");
  snprintf(title_tx, 64, "%s%s %s?", "Do you want to sign this\n", chain_name,
           "message");

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_layout:
  layoutSwipe();
  oledClear();

  if (0 == index) {
    layoutHeader(title);
    oledDrawStringAdapter(0, 13, "Signer:", FONT_STANDARD);
    oledDrawStringAdapter(0, 13 + 10, signer, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (1 == index) {
    layoutHeader(title);
    oledDrawStringAdapter(0, 13, hash, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else {
    layoutHeader(title);
    oledDrawStringAdapter(0, 13, title_tx, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();

  WAIT_KEY_OR_ABORT(0, 0, key);
  switch (key) {
    case KEY_UP:
      goto refresh_layout;
    case KEY_DOWN:
      goto refresh_layout;
    case KEY_CONFIRM:
      if (index == max_index - 1) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      goto refresh_layout;
    case KEY_CANCEL:
      if (0 == index || index == max_index - 1) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_layout;
    default:
      break;
  }

  return result;
}

void layout_fido2_resident_credential(int index, int count,
                                      const char *app_name,
                                      const char *user_name) {
  char app_name_buf[64] = {0};
  char user_name_buf[64] = {0};

  short_line_message(app_name, app_name_buf);
  short_line_message(user_name, user_name_buf);
  layoutDialogAdapter_ex(NULL, &bmp_bottom_left_arrow, NULL,
                         &bmp_bottom_right_arrow, NULL, NULL, NULL,
                         _(GLOBAL_APP_NAME), app_name_buf, _(GLOBAL_ACCOUNT),
                         user_name_buf, NULL);
  if (count > 1) {
    layout_index_count(index + 1, count);
  }

  if (count > 1) {
    // if (index < count - 1) {
    //   oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
    //                  &bmp_bottom_middle_arrow_down);
    // }
    // if (index > 0) {
    //   oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
    //                  &bmp_bottom_middle_arrow_up);
    // }
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  }

  oledRefresh();
}
