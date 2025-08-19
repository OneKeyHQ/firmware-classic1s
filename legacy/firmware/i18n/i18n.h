#ifndef I18N_H
#define I18N_H

#include <stdint.h>
#include <stdio.h>
#include "keys.h"

#define I18N_ITEMS_COUNT 391
#define I18N_LANGUAGE_ITEMS 8

typedef enum {
  I18N_LANG_EN = 0,
  I18N_LANG_ZH_CN = 1,
  I18N_LANG_ZH_TW = 2,
  I18N_LANG_JA = 3,
  I18N_LANG_ES = 4,
  I18N_LANG_PT_BR = 5,
  I18N_LANG_DE = 6,
  I18N_LANG_KO_KR = 7,
} i18n_lang_t;

extern const char *const i18n_lang_keys[];
extern const char *const i18n_langs[];

extern const char *const languages_en[];
extern const char *const languages_zh_cn[];
extern const char *const languages_zh_tw[];
extern const char *const languages_ja[];
extern const char *const languages_es[];
extern const char *const languages_pt_br[];
extern const char *const languages_de[];
extern const char *const languages_ko_kr[];

extern const char *const *const languages_table[];

#endif
