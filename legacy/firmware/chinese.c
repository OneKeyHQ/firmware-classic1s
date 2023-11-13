#include "chinese.h"
#include "common.h"
#include "font.h"
#include "font_ex.h"
#include "oled.h"

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

static int oledDrawCharEx(int x, int y, const char *c, uint8_t font) {
  if (x >= OLED_WIDTH || y >= OLED_HEIGHT || y <= -FONT_HEIGHT) {
    return 0;
  }

  uint8_t empty[] = {0x00, 0x00, 0x00, 0x7E, 0x42, 0x42, 0x42, 0x7E};

  int height = font_get_height();
  int zoom = (font & FONT_DOUBLE) ? 2 : 1;
  uint8_t char_width = 0;
  uint8_t line_bytes = 0;
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
    height = char_width = 8;
  }
  line_bytes = (char_width + 7) / 8;

  if (x <= -char_width) {
    return 0;
  }

  for (int yo = 0; yo < height; yo++) {
    for (int xo = 0; xo < char_width; xo++) {
      if (char_data[yo * line_bytes + xo / 8] & (1 << (7 - xo % 8))) {
        if (zoom <= 1) {
          oledDrawPixel(x + xo, y + yo);
        } else {
          oledBox(x + xo, y + yo * zoom, x + (xo + 1) - 1,
                  y + (yo + 1) * zoom - 1, true);
        }
      }
    }
  }

  return char_width;
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
        l += font_get_width((uint8_t *)text) + ((font & FONT_DOUBLE) ? 1 : 0);
      }
      text += steps;
    }
  }
  return l;
}

static bool is_symbols(uint8_t *c, int steps) {
  const char *symbols[] = {"。", "，", "？", "！", "、", "：", "”", "“"};
  for (uint8_t i = 0; i < 8; i++) {
    if (memcmp(c, (uint8_t *)symbols[i], steps) == 0) {
      return true;
    }
  }

  return false;
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
      if (is_symbols((uint8_t *)text, steps)) x += 1 + 3;
      text += steps;
      x += l;
    }
  }
}

int oledStringWidthAdapter(const char *text, uint8_t font) {
  if (!text) return 0;
  if (font_imported() && (ui_language != 0)) {
    return oledStringWidthEx(text, font);
  }

  const struct font_desc *font_dese = find_cur_font();
  int l = 0;
  int zoom = (font & FONT_DOUBLE) ? 2 : 1;

  while (*text) {
    if ((uint8_t)*text < 0x80) {
      if (zoom == 2) {
        l += (fontCharWidth(font & 0x7f, (uint8_t)*text) + 1) * zoom + 1;
      } else {
        l += fontCharWidth(font & 0x7f, (uint8_t)*text) + 1;
      }
      text++;
    } else {
      if (font_dese->idx == DEFAULT_IDX) {
        font_dese = find_font("dingmao_9x9");
      }
      // l += font_dese->width + ((font & FONT_DOUBLE) ? 2 : 1);
      l += font_dese->width + ((font & FONT_DOUBLE) ? 1 : 0);
      text += HZ_CODE_LEN;
    }
  }
  return l;
}

static void oledDrawChar_zh(int x, int y, const char *zh, uint8_t font,
                            const struct font_desc *font_dc) {
  if (x >= OLED_WIDTH || y >= OLED_HEIGHT || x <= -12 || y <= -12) {
    return;
  }
  int zoom = (font & FONT_DOUBLE) ? 2 : 1;
  const uint8_t *char_data = get_font_data(zh);

  if (!char_data) return;

  for (int xo = 0; xo < font_dc->pixel; xo++) {
    for (int yo = 0; yo < 8; yo++) {
      if (char_data[xo] & (1 << (8 - 1 - yo))) {
        if (zoom <= 1) {
          oledDrawPixel(x + xo, y + yo);
        } else {
          oledBox(x + xo, y + yo * zoom, x + (xo + 1) - 1,
                  y + (yo + 1) * zoom - 1, true);
        }
      }
    }
    for (int yo = 0; yo < font_dc->pixel - 8; yo++) {
      if (char_data[xo + font_dc->pixel] & (1 << (8 - 1 - yo))) {
        if (zoom <= 1) {
          oledDrawPixel(x + xo, y + 8 + yo);
        } else {
          oledBox(x + xo * zoom, y + (font_dc->pixel + yo) * zoom,
                  x + (xo + 1) * zoom - 1, y + (yo + 8 + 1) * zoom - 1, true);
        }
      }
    }
  }
}

void oledDrawStringAdapter(int x, int y, const char *text, uint8_t font) {
  if (!text) return;
  if (font_imported() && (ui_language != 0)) {
    oledDrawStringEx(x, y, text, font);
    return;
  }
  const char *p = text;
  while (*p) {
    if ((uint8_t)*p >= 0x80) {
      return oledDrawStringEx(x, y, text, font);
    }
    p++;
  }

  const struct font_desc *font_desc, *font_desc_bak;
  font_desc = font_desc_bak = find_cur_font();
  int space = (font & FONT_DOUBLE) ? 2 : 1;
  int l = 0;
  while (*text) {
    if ((uint8_t)*text < 0x80) {
      if (*text == '\n') {
        x = 0;
        if (font_desc->pixel <= 8)
          y += font_desc->pixel + 2;
        else
          y += font_desc->pixel + 1;
        text++;
        continue;
      }
      l = fontCharWidth(font & 0x7f, *text) + space;
      if (x + l > OLED_WIDTH) {
        x = 0;
        y += font_desc->pixel + 1;
      }
      if (y > OLED_HEIGHT) y = 0;
      oledDrawChar(x, y + font_desc->pixel - 8, *text, font);
      if (font & FONT_DOUBLE)
        x += l * space - 1;
      else
        x += l;
      text++;
    } else {
      if (font_desc_bak->idx == DEFAULT_IDX) {
        font_desc_bak = find_font("dingmao_9x9");
      }
      if (x + font_desc_bak->width > OLED_WIDTH) {
        x = 0;
        y += font_desc_bak->pixel + 1;
      }
      if (y > OLED_HEIGHT) y = 0;
      oledDrawChar_zh(x, y, text, font, font_desc_bak);
      // x += font_desc_bak->width + ((font & FONT_DOUBLE) ? 2 : 1);
      x += font_desc_bak->width +
           ((font & FONT_DOUBLE)
                ? 1
                : 0);  // dingmao_9x9: .width = 10 include 1 space
      text += HZ_CODE_LEN;
    }
  }
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
