#include "i18n.h"

// clang-format off

const char *const i18n_lang_keys[] = {
    "en",
    "zh_CN",
    "zh_TW",
    "ja",
    "es",
    "pt",
    "de",
    "ko_KR",
};

const char *const i18n_langs[] = {
    "English",
    "中文 (简体)",
    "中文 (繁體)",
    "日本語",
    "Español",
    "Português",
    "Deutsch",
    "한국어",
};

#include "locales/de.inc"
#include "locales/en.inc"
#include "locales/es.inc"
#include "locales/ja.inc"
#include "locales/ko_kr.inc"
#include "locales/pt_br.inc"
#include "locales/zh_cn.inc"
#include "locales/zh_tw.inc"

const char *const *const languages_table[] = {
    languages_en,
    languages_zh_cn,
    languages_zh_tw,
    languages_ja,
    languages_es,
    languages_pt_br,
    languages_de,
    languages_ko_kr,
};

// clang-format on
