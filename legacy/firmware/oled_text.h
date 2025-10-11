#ifndef __OLED_TEXT_H__
#define __OLED_TEXT_H__

#include <stdint.h>
#include <string.h>
#include "bitmaps.h"
// #define HZ_CODE_LEN 2  // GBK
#define HZ_CODE_LEN 3  // UTF-8

#define MAX_SPLIT_LINES 16

typedef struct {
  const char *line_start[MAX_SPLIT_LINES];
  int line_count;
} string_lines_t;

string_lines_t split_string_to_lines(const char *text, int max_width,
                                     uint8_t font);
int oledCharWidthEx(const char text, uint8_t font);
int oledStringWidthAdapter(const char *text, uint8_t font);
void oledDrawNumber_zh(int x, int y, const char font);
uint8_t oledDrawStringAdapter(int x, int y, const char *text, uint8_t font);
void oledDrawStringCenterAdapter(int x, int y, const char *text, uint8_t font);
int oledDrawStringCenterAdapterX(int x, int y, const char *text, uint8_t font);
void oledDrawStringRightAdapter(int x, int y, const char *text, uint8_t font);
uint8_t oledDrawPageableStringAdapter(int x, int y, const char *text,
                                      uint8_t font, const BITMAP *btn_no_icon,
                                      const BITMAP *btn_yes_icon);
#endif
