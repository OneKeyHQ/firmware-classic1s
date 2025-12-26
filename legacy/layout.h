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

#ifndef __LAYOUT_H__
#define __LAYOUT_H__

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "bitmaps.h"

#define BATTERY_LOGO_WIDTH 16
// USB/BLE/BATTERY/CHARGE
#define STATUS_LOGO_WIDTH_MAX 5 * LOGO_WIDTH

extern void *layoutLast, *layoutLastBackup;

#if !EMULATOR
void chargeDisTimer(void);
#endif
bool layoutNeedRefresh(void);
void layoutRefreshSet(bool refresh);
void layoutButtonNo(const char *btnNo, const BITMAP *icon);
void layoutButtonYes(const char *btnYes, const BITMAP *icon);
void layoutinfoCenter(const char *line1, const char *line2, const char *line3,
                      const char *line4, const char *line5, const char *line6);
void layoutDialog(const BITMAP *icon, const char *btnNo, const char *btnYes,
                  const char *desc, const char *line1, const char *line2,
                  const char *line3, const char *line4, const char *line5,
                  const char *line6);
void layoutDialogEx(const BITMAP *icon, const char *btnNo, const char *btnYes,
                    const char *desc, const char *line1, const char *line2,
                    const char *line3, const char *line4, const char *line5,
                    const char *line6, uint8_t font);
void layoutDialogCenterAdapterEx(const BITMAP *icon, const BITMAP *bmp_no,
                                 const BITMAP *bmp_yes, const char *title,
                                 const char *line1, const char *line2,
                                 const char *line3, const char *line4);
void layoutProgressUpdate(bool refresh);
void layoutProgressPercent(int permil);
void layoutProgress(const char *desc, int permil);
void layoutStatusLogo(void);
void disBatteryLevel(int offset_x, uint8_t cur_level);
void layoutBlePasskey(uint8_t *passkey);
void layoutBlePairSuccess(void);
void layoutBlePairFailed(void);
bool layoutBlePairResultShowing(void);
void layoutBlePairResultDismiss(void);
void layoutBlePasskeyDismiss(void);
void layoutFillBleName(uint8_t line);
void layoutFillBleVersion(uint8_t line);
void layoutError(const char *line1, const char *line2);

#endif
