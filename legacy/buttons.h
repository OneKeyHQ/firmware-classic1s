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

#ifndef __BUTTONS_H__
#define __BUTTONS_H__

#include <libopencm3/stm32/gpio.h>
#include <stdbool.h>

#include "sys.h"
#include "timer.h"

#include "compatible.h"

struct buttonState {
  volatile bool YesUp;
  volatile int YesDown;
  volatile bool NoUp;
  volatile int NoDown;
  volatile bool UpUp;
  volatile int UpDown;
  volatile bool DownUp;
  volatile int DownDown;
};

extern struct buttonState button;

enum {
  KEY_UP_OR_DOWN,
  KEY_UP,
  KEY_DOWN,
};

uint16_t buttonRead(void);
void buttonUpdate(void);
bool hasbutton(void);
void clearButtonState(void);
void buttonsIrqInit(void);
void buttonsTimer(void);
void longPressTimer(void);
bool checkButtonOrTimeout(uint8_t btn, TimerOut type);
bool waitButtonResponse(uint8_t btn, uint32_t time_out);
uint8_t keyScan(void);
uint8_t waitKey(uint32_t time_out, uint8_t mode);
void enableLongPress(bool on);
bool getLongPressStatus(void);
bool isLongPress(uint8_t key);

#define KEY_NULL 0
#define KEY_UP 'U'
#define KEY_DOWN 'D'
#define KEY_CONFIRM 'O'
#define KEY_CANCEL 'C'
#define KEY_UP_LONG 'V'
#define KEY_DOWN_LONG 'E'
#define KEY_COMBO_UP_DOWN 'A'

#define HANDLE_KEY(bubble_key)                                  \
  do {                                                          \
    uint8_t key = KEY_NULL;                                     \
    key = bubble_key ? bubble_key : protectWaitKey(0, 0);       \
    if (protectAbortedByInitialize || protectAbortedByCancel) { \
      return false;                                             \
    }                                                           \
    switch (key) {                                              \
      case KEY_UP:                                              \
      case KEY_DOWN:                                            \
        goto refresh_menu;                                      \
      case KEY_CONFIRM:                                         \
        if (max_index == index) {                               \
          result = true;                                        \
          break;                                                \
        }                                                       \
        if (index < max_index) {                                \
          index++;                                              \
        }                                                       \
        goto refresh_menu;                                      \
      case KEY_CANCEL:                                          \
        if (0 == index || max_index == index) {                 \
          result = false;                                       \
          break;                                                \
        }                                                       \
        if (index > 0) {                                        \
          index--;                                              \
        }                                                       \
        goto refresh_menu;                                      \
      default:                                                  \
        break;                                                  \
    }                                                           \
    return result;                                              \
  } while (0)

#endif
