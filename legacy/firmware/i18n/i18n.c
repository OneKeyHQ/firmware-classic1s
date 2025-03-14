#include "i18n.h"

uint8_t langs_len = 7;

// clang-format off
const char* const i18n_lang_keys[] = {"en", "zh_CN", "zh_TW", "ja", "es", "pt", "de"};
const char* const i18n_langs[] = {"English", "中文 (简体)", "中文 (繁體)", "日本語", "Español", "Português", "Deutsch"};
// clang-format on

#include "locales/de.inc"
#include "locales/en.inc"
#include "locales/es.inc"
#include "locales/ja.inc"
#include "locales/pt_br.inc"
#include "locales/zh_cn.inc"
#include "locales/zh_tw.inc"

int I18N_LANGUAGE_ITEMS = sizeof(languages_en) / sizeof(languages_en[0]);
