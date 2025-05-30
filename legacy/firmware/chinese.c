#include "chinese.h"
#include "buttons.h"
#include "common.h"
#include "font.h"
#include "font_ex.h"
#include "layout2.h"
#include "oled.h"
#include "protect.h"

extern void drawScrollbar(int pages, int index);
extern void drawScrollbar_ext(int pages, int index, int bar_start);

static int oledDrawStringX(int x, int y, const uint8_t *char_data) {
  uint8_t data_len = char_data[0];
  char_data = char_data + 1;
  y -= 2;
  for (int xo = 0; xo < data_len; xo++) {
    for (int yo = 0; yo < 8; yo++) {
      if (char_data[xo] & (1 << (8 - 1 - yo))) {
        oledDrawPixel(x + xo, y + yo);
      }
    }
    for (int yo = 0; yo < 3; yo++) {  // 11 pixel
      if (char_data[xo + data_len] & (1 << (8 - 1 - yo))) {
        oledDrawPixel(x + xo, y + 8 + yo);
      }
    }
  }

  return data_len + 1;
}
// use row-column scanning to draw characters
// static int oledDrawCharEx(int x, int y, const char *c, uint8_t font) {
//   if (x >= OLED_WIDTH || y >= OLED_HEIGHT || y <= -FONT_HEIGHT) {
//     return 0;
//   }

//   uint8_t empty[] = {0x00, 0x00, 0x00, 0x7E, 0x42, 0x42, 0x42, 0x7E};

//   int height = font_get_height();
//   int zoom = (font & FONT_DOUBLE) ? 2 : 1;
//   uint8_t char_width = 0;
//   uint8_t line_bytes = 0;
//   uint32_t unicode = 0;
//   const uint8_t *char_data = NULL;
//   utf8_to_unicode_char((uint8_t *)c, &unicode);
//   char_data = get_fontx_data(unicode);
//   if (char_data) {
//     return oledDrawStringX(x, y, char_data);
//   }
//   char_data = font_get_data((uint8_t *)c, &char_width);
//   if (!char_data) {
//     char_data = empty;
//     height = char_width = 8;
//   }
//   line_bytes = (char_width + 7) / 8;

//   if (x <= -char_width) {
//     return 0;
//   }

//   for (int yo = 0; yo < height; yo++) {
//     for (int xo = 0; xo < char_width; xo++) {
//       if (char_data[yo * line_bytes + xo / 8] & (1 << (7 - xo % 8))) {
//         if (zoom <= 1) {
//           oledDrawPixel(x + xo, y + yo);
//         } else {
//           oledBox(x + xo, y + yo * zoom, x + (xo + 1) - 1,
//                   y + (yo + 1) * zoom - 1, true);
//         }
//       }
//     }
//   }

//   return char_width;
// }
// use bit-packed dot matrix data to draw characters
static int oledDrawCharEx(int x, int y, const char *c, uint8_t font) {
  if (x >= OLED_WIDTH || y >= OLED_HEIGHT || y <= -FONT_HEIGHT) {
    return 0;
  }
  // ☒
  uint8_t empty[] = {0x01, 0xfe, 0x0d, 0x59, 0x35, 0x60, 0xff, 0x00, 0x00};

  int height = font_get_height();  // box_height
  int zoom = (font & FONT_DOUBLE) ? 2 : 1;
  uint8_t char_width = 0;
  uint32_t unicode = 0;
  const uint8_t *char_data = NULL;

  utf8_to_unicode_char((uint8_t *)c, &unicode);
  char_data = get_fontx_data(unicode);
  if (char_data) {
    return oledDrawStringX(x, y, char_data);
  }

  char_data = font_get_data((uint8_t *)c, &char_width);
  if (!char_data) {
    char_data = empty;
    char_width = 7;
  }

  if (x <= -char_width) {
    return 0;
  }

  for (int yo = 0; yo < height; yo++) {
    for (int xo = 0; xo < char_width; xo++) {
      int bit_offset = yo * char_width + xo;
      int byte_index = bit_offset / 8;
      int bit_index = 7 - (bit_offset % 8);
      if ((char_data[byte_index] >> bit_index) & 0x01) {
        if (zoom <= 1) {
          oledDrawPixel(x + xo, y + yo);
        } else {
          oledBox(x + xo, y + yo * zoom, x + (xo + 1) - 1,
                  y + (yo + 1) * zoom - 1, true);
        }
      }
    }
  }

  return char_width + 1;
}

bool is_symbols(uint8_t *c, int steps) {
  // clang-format off
  const char *symbols[] = {"。", "，", "？", "！", "、", "：", "”", "“"};
  // clang-format on
  for (uint8_t i = 0; i < 8; i++) {
    if (memcmp(c, (uint8_t *)symbols[i], steps) == 0) {
      return true;
    }
  }

  return false;
}

int oledStringWidthEx(const char *text, uint8_t font) {
  if (!text) return 0;
  int steps = 0;
  int zoom = (font & FONT_DOUBLE) ? 2 : 1;
  int l = 0;
  while (*text) {
    if (((uint8_t)*text < 0x80)) {
      if (*text != '\n') {
        if (zoom == 2) {
          l += (fontCharWidth(font & 0x7f, (uint8_t)*text) + 1) * zoom + 1;
        } else {
          l += fontCharWidth(font & 0x7f, (uint8_t)*text) + 1;
        }
      }
      text++;
    } else {
      steps = utf8_get_size(*text);
      uint32_t unicode = 0;
      const uint8_t *char_data = NULL;
      utf8_to_unicode_char((uint8_t *)text, &unicode);
      char_data = get_fontx_data(unicode);
      if (char_data) {
        l += char_data[0] + 1;
      } else {
        l += font_get_width((uint8_t *)text) + 1;
      }
      text += steps;
    }
  }
  return l;
}

int oledCharWidthEx(const char text, uint8_t font) {
  char text_array[2] = {0};
  text_array[0] = text;
  return oledStringWidthEx(text_array, font);
}

void oledDrawStringEx(int x, int y, const char *text, uint8_t font) {
  int steps = 0;
  int l = 0;
  // bool mixed = false;
  int space = (font & FONT_DOUBLE) ? 2 : 1;
  uint8_t char_width = 0;
  uint8_t height = font_get_height();
  const uint8_t *char_data = font_get_data((uint8_t *)text, &char_width);
  if (!char_data) {
    height = char_width = 8;
  }
  int CLASSIC2_ADJUST = 0;

  while (*text) {
    if (((uint8_t)*text < 0x80)) {
      if (*text == '\n') {
        l = 0;
      } else {
        l = fontCharWidth(font & 0x7f, *text) + space;
      }
      if (x + l > (OLED_WIDTH - CLASSIC2_ADJUST) || (*text == '\n')) {
        x = CLASSIC2_ADJUST;
        y += 10;
      }
      if (y > OLED_HEIGHT) y = 0;
      if (*text != '\n') {
        oledDrawChar(x, y + 1, *text, font);
      }
      if (font & FONT_DOUBLE)
        x += l * space - 1;
      else
        x += l;
      text++;
    } else {
      // mixed = true;
      steps = utf8_get_size(*text);
      if (x + char_width > (OLED_WIDTH - CLASSIC2_ADJUST) || (*text == '\n')) {
        x = CLASSIC2_ADJUST;
        y += height + 1;
      }
      if (y > OLED_HEIGHT) y = 0;
      l = oledDrawCharEx(x, y, text, font);
      text += steps;
      x += l;
    }
  }
}

int oledStringWidthAdapter(const char *text, uint8_t font) {
  if (!text) return 0;
  return oledStringWidthEx(text, font);
}

void oledDrawStringAdapter(int x, int y, const char *text, uint8_t font) {
  if (!text) return;
  oledDrawStringEx(x, y, text, font);
  return;
}

void oledDrawStringCenterAdapter(int x, int y, const char *text, uint8_t font) {
  if (!text) return;
  x = x - oledStringWidthAdapter(text, font) / 2;
  if (x < 0) x = 0;
  oledDrawStringAdapter(x, y, text, font);
}

int oledDrawStringCenterAdapterX(int x, int y, const char *text, uint8_t font) {
  (void)y;
  if (!text) return 0;
  x = x - oledStringWidthAdapter(text, font) / 2;
  if (x < 0) x = 0;
  return x;
}

void oledDrawStringRightAdapter(int x, int y, const char *text, uint8_t font) {
  if (!text) return;
  x -= oledStringWidthAdapter(text, font);
  oledDrawStringAdapter(x, y, text, font);
}
#include "memzero.h"
#include "util.h"

uint8_t oledDrawPageableStringAdapter(int x, int y, const char *text,
                                      uint8_t font, const BITMAP *btn_no_icon,
                                      const BITMAP *btn_yes_icon) {
  // NOTE: 21 is the max width of a line. CAUTION: This function uses VLA
  // (Variable Length Array). Be aware of potential stack overflow risks.
  size_t rowlen = 21;
  size_t rowcount = 0, index = 0;

  uint8_t key = KEY_NULL;

  const char *p = text;

  size_t ascii_count = 0;
  size_t cjk_count = 0;

  while (*p) {
    if ((*p & 0x80) == 0) {
      ascii_count++;
      p++;
    } else if ((*p & 0xE0) == 0xC0) {
      ascii_count++;
      cjk_count++;
      p += 2;
    } else if ((*p & 0xF0) == 0xE0) {
      ascii_count++;
      cjk_count++;
      p += 3;
    } else if ((*p & 0xF8) == 0xF0) {
      ascii_count++;
      cjk_count++;
      p += 4;
    } else {
      p++;
    }

    if (*p == '\n' || cjk_count >= 13 || ascii_count >= rowlen) {
      rowcount++;
      ascii_count = 0;
      cjk_count = 0;
      if (*p == '\n') p++;
    }
  }
  if (ascii_count > 0) rowcount++;

  if (rowcount > 3) {
    char str[rowcount][rowlen + 1];
    memzero(str, sizeof(str));
    p = text;
    for (size_t i = 0; i < rowcount && *p; i++) {
      const char *next = memchr(p, '\n', MIN(rowlen, strlen(p)));
      size_t line_len = next ? (size_t)(next - p) : MIN(rowlen, strlen(p));
      memcpy(str[i], p, line_len);
      str[i][line_len] = '\0';
      p = next ? (next + 1) : (p + line_len);
    }
#if !EMULATOR
    enableLongPress(true);
#endif
  refresh_text:
    oledClear_ext(x, y);
    int y1 = y;
    y1++;
    if (0 == index) {
      oledDrawStringAdapter(x, y1, str[0], font);
      oledDrawStringAdapter(x, y1 + 1 * 10, str[1], font);
      oledDrawStringAdapter(x, y1 + 2 * 10, str[2], font);
      oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                     &bmp_bottom_middle_arrow_down);
    } else {
      oledDrawStringAdapter(x, y1, str[index], font);
      oledDrawStringAdapter(x, y1 + 1 * 10, str[index + 1], font);
      oledDrawStringAdapter(x, y1 + 2 * 10, str[index + 2], font);
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
    drawScrollbar_ext(rowcount - 2, index, y1);
    // bottom button
    layoutButtonNoAdapter(NULL, btn_no_icon);
    layoutButtonYesAdapter(NULL, btn_yes_icon);
    oledRefresh();
    key = protectWaitKey(0, 0);

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
        if (index > 0) {
          index--;
        }
        goto refresh_text;
      case KEY_DOWN:
        if (index < rowcount - 3) {
          index++;
        }
        goto refresh_text;
      default:
#if !EMULATOR
        enableLongPress(false);
#endif
        return key;
    }
  } else {
    oledDrawStringAdapter(0, y, text, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, btn_no_icon);
    layoutButtonYesAdapter(NULL, btn_yes_icon);
    oledRefresh();
    while (1) {
      key = protectWaitKey(0, 0);
      if (key == KEY_CONFIRM || key == KEY_CANCEL) {
        break;
      }
      delay_ms(10);
    }
    return key;
  }
}
