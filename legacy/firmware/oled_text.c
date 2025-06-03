#include "oled_text.h"
#include "buttons.h"
#include "common.h"
#include "font.h"
#include "font_ex.h"
#include "layout2.h"
#include "oled.h"
#include "protect.h"

#define LETTER_SPACE 1

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

  return data_len + LETTER_SPACE;
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

int get_char_width(const char *c, uint8_t font) {
  if (*c == '\r' || *c == '\n') {
    return 0;
  }

  int zoom = (font & FONT_DOUBLE) ? 2 : 1;
  if (((uint8_t)*c < 0x80)) {
    return fontCharWidth(font & 0x7f, (uint8_t)*c) * zoom + zoom * LETTER_SPACE;
  }

  const uint8_t *char_data = NULL;
  uint32_t unicode = 0;

  utf8_to_unicode_char((uint8_t *)c, &unicode);
  char_data = get_fontx_data(unicode);
  if (char_data) {
    return char_data[0] + LETTER_SPACE;
  }

  return font_get_width((const uint8_t *)c) + LETTER_SPACE;
}

int get_string_width(const char *str, const char *end, uint8_t font) {
  int width = 0;
  while (str < end) {
    width += get_char_width(str, font);
    str = utf8_next(str);
  }
  return width;
}
int draw_char(int x, int y, const char *c, uint8_t font) {
  int zoom = (font & FONT_DOUBLE) ? 2 : 1;

  if (((uint8_t)*c < 0x80)) {
    if (0 == ui_language) {
      oledDrawChar(x, y, *c, font);
    } else {
      oledDrawChar(x, y + 1, *c, font);
    }
    return fontCharWidth(font & 0x7f, (uint8_t)*c) * zoom + zoom * LETTER_SPACE;
  }

  uint32_t unicode = 0;
  const uint8_t *char_data = NULL;
  int height = font_get_height();

  utf8_to_unicode_char((uint8_t *)c, &unicode);
  char_data = get_fontx_data(unicode);
  if (char_data) {
    return oledDrawStringX(x, y, char_data);
  }
  uint8_t char_width = 0;
  char_data = font_get_data((uint8_t *)c, &char_width);
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

  return char_width + LETTER_SPACE;
}

const char *get_next_word(const char *text) {
  const char *p = text;
  uint32_t unicode = 0;

  while (*p) {
    const char *next = utf8_next(p);
    utf8_to_unicode_char((const uint8_t *)p, &unicode);

    bool is_break = (unicode <= 0x20) || (unicode == ':') || (unicode == '.') ||
                    (unicode == ',') || (unicode == '!') ||
                    (unicode == '?') ||  // space, \n, \r, \t, etc.
                    (unicode >= 0x4E00 && unicode <= 0x9FFF) ||
                    (unicode >= 0x3040 && unicode <= 0x30FF) ||
                    (unicode >= 0xAC00 && unicode <= 0xD7A3);

    if (is_break) {
      return next;
    }
    p = next;
  }
  return p;
}

const char *get_next_line(const char *text, int max_width, int *width,
                          uint8_t font) {
  const char *p = text, *word_end = NULL, *break_point1 = NULL,
             *break_point2 = NULL;
  int line_width = 0, word_width = 0, char_width = 0, break_width = 0;
  *width = 0;
  while (*p) {
    word_end = get_next_word(p);
    word_width = 0;
    break_point1 = p;
    *width = line_width;
    while (p < word_end) {
      char_width = get_char_width(p, font);
      word_width += char_width;
      line_width += char_width;

      if (word_width > max_width) {
        if (break_point2 == NULL) {
          *width = line_width - char_width;
          return p;
        } else {
          *width = break_width;
          return break_point2;
        }
      }

      if (line_width > max_width && break_point2 == NULL) {
        break_point2 = p;
        break_width = line_width - char_width;
      }
      if (*p == '\n' || *p == '\r') {
        if (line_width > max_width) {
          *width = line_width - word_width;
          return break_point1;
        } else {
          *width = line_width;
          p = utf8_next(p);
          return p;
        }
      }
      p = utf8_next(p);
    }
    if (line_width > max_width) {
      *width = line_width - word_width;
      return break_point1;
    }
  }
  *width = line_width;
  return p;
}

string_lines_t split_string_to_lines(const char *text, int max_width,
                                     uint8_t font) {
  string_lines_t lines = {0};
  int line_width = 0;
  const char *p = text;
  while (*p && lines.line_count < MAX_SPLIT_LINES) {
    const char *next = get_next_line(p, max_width, &line_width, font);
    lines.line_start[lines.line_count++] = p;
    p = next;
  }
  // add the end of the string
  lines.line_start[lines.line_count] = text + strlen(text);
  return lines;
}

void draw_string_wrap(int x, int y, const char *text, uint8_t font) {
  const char *p = text;
  uint8_t height = font_get_height();
  int cursor_x = x;
  int cursor_y = y;
  int char_width = 0, line_width = 0;

  while (*p) {
    if (*p == '\r' || *p == '\n') {
      cursor_x = 0;
      cursor_y += height;
      p++;
      continue;
    }
    const char *next_line =
        get_next_line(p, OLED_WIDTH - cursor_x, &line_width, font);
    while (p < next_line) {
      char_width = get_char_width(p, font);
      draw_char(cursor_x, cursor_y, p, font);
      cursor_x += char_width;
      p = utf8_next(p);
    }
    cursor_y += height;
    cursor_x = 0;
  }
}

void draw_string_center(int x, int y, const char *text, uint8_t font) {
  if (x > OLED_WIDTH || y > OLED_HEIGHT) {
    return;
  }
  const char *p = text;
  uint8_t height = font_get_height();
  int cursor_x = x;
  int cursor_y = y;
  int line_width = 0;
  int char_width = 0;
  int max_width = (x < OLED_WIDTH / 2) ? x * 2 : (OLED_WIDTH - x) * 2;
  if (max_width == 0) {
    return;
  }

  while (*p) {
    if (*p == '\r' || *p == '\n') {
      cursor_y += height;
      p++;
      continue;
    }
    const char *next_line = get_next_line(p, max_width, &line_width, font);
    cursor_x = x - line_width / 2;
    while (p < next_line) {
      char_width = get_char_width(p, font);
      draw_char(cursor_x, cursor_y, p, font);
      cursor_x += char_width;

      p = utf8_next(p);
    }
    cursor_y += height;
  }
}

int oledStringWidthEx(const char *text, uint8_t font) {
  int width = 0;
  while (*text) {
    width += get_char_width(text, font);
    text = utf8_next(text);
  }
  return width;
}

int oledCharWidthEx(const char text, uint8_t font) {
  char text_array[2] = {0};
  text_array[0] = text;
  return oledStringWidthEx(text_array, font);
}

int oledStringWidthAdapter(const char *text, uint8_t font) {
  if (!text) return 0;
  return oledStringWidthEx(text, font);
}

void oledDrawStringAdapter(int x, int y, const char *text, uint8_t font) {
  if (!text) return;
  draw_string_wrap(x, y, text, font);
  return;
}

void oledDrawStringCenterAdapter(int x, int y, const char *text, uint8_t font) {
  if (!text) return;
  draw_string_center(x, y, text, font);
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
