import os

import lokalise

LOKALISE_PROJECT_ID = "372193756406ee669eacc1.76289155"
BASE_PATH = os.path.join(os.path.dirname(__file__), "..", "firmware/i18n/")
SUPPORTED_LANGS = ("en", "zh_CN", "zh_TW", "ja", "es", "pt_BR", "de", "ko_KR")
CHARS_NORMAL = set()
CHARS_TITLE = set()
CHARS_SUBTITLE = set()


def write_keys(parsed):
    content = []
    for key in parsed:
        en_text = key["translations"]["en"].replace("\\n", " ")
        content += [
            f"// {wrapped}"
            for wrapped in [
                en_text[i : i + 76].strip() for i in range(0, len(en_text), 76)
            ]
        ]
        for key_name in key["key_names"]:
            text = key_name.upper().replace(":", "_")
            content.append(f"#define {text} {key['position']}")
    with open(f"{BASE_PATH}/keys.h", "w") as f:
        f.write("// clang-format off\n")
        f.write("#ifndef I18N_KEY_H\n")
        f.write("#define I18N_KEY_H\n")
        f.write("\n".join(content) + "\n")
        f.write("#endif\n")
        f.write("// clang-format on\n")


def write_lang(parsed, lang_iso):
    content = f"const char *const languages_{lang_iso.lower()}[] = " + "{"
    content = [content]
    for key in parsed:
        text = key["translations"][lang_iso]
        text = text.replace('"', '\\"')
        text = f'    "{text}",'
        content.append(text)
    content.append("};")
    with open(f"{BASE_PATH}/locales/{lang_iso.lower()}.inc", "w") as f:
        f.write("\n".join(content) + "\n")


def write_i18n_header(languages_map, items_count):
    content = [
        "#ifndef I18N_H",
        "#define I18N_H",
        "",
        "#include <stdint.h>",
        "#include <stdio.h>",
        '#include "keys.h"',
        "",
        f"#define I18N_ITEMS_COUNT {items_count}",
        f"#define I18N_LANGUAGE_ITEMS {len(SUPPORTED_LANGS)}",
        "",
        "typedef enum {",
    ]

    for i, lang_iso in enumerate(SUPPORTED_LANGS):
        lang_name = lang_iso.upper().replace("-", "_")
        content.append(f"  I18N_LANG_{lang_name} = {i},")

    content.extend(
        [
            "} i18n_lang_t;",
            "",
            "extern const char *const i18n_lang_keys[];",
            "extern const char *const i18n_langs[];",
            "",
        ]
    )

    for lang_iso in SUPPORTED_LANGS:
        content.append(f"extern const char *const languages_{lang_iso.lower()}[];")

    content.extend(
        [
            "",
            "extern const char *const *const languages_table[];",
            "",
            "#endif",
        ]
    )

    with open(f"{BASE_PATH}/i18n.h", "w") as f:
        f.write("\n".join(content) + "\n")


def write_i18n_source(languages_map):
    LANG_NAMES = {
        "en": "English",
        "zh_CN": "中文 (简体)",
        "zh_TW": "中文 (繁體)",
        "ja": "日本語",
        "es": "Español",
        "pt_BR": "Português",
        "de": "Deutsch",
        "ko_KR": "한국어",
    }

    LANG_KEY_DISPLAY = {
        "pt_BR": "pt",
    }

    content = [
        '#include "i18n.h"',
        "",
        "// clang-format off",
        "",
        "const char *const i18n_lang_keys[] = {",
    ]

    for lang_iso in SUPPORTED_LANGS:
        display_key = LANG_KEY_DISPLAY.get(lang_iso, lang_iso)
        content.append(f'    "{display_key}",')

    content.extend(
        [
            "};",
            "",
            "const char *const i18n_langs[] = {",
        ]
    )

    for lang_iso in SUPPORTED_LANGS:
        lang_name = LANG_NAMES[lang_iso]
        content.append(f'    "{lang_name}",')

    content.extend(
        [
            "};",
            "",
        ]
    )

    sorted_langs = sorted(SUPPORTED_LANGS)
    for lang_iso in sorted_langs:
        content.append(f'#include "locales/{lang_iso.lower()}.inc"')

    content.extend(
        [
            "",
            "const char *const *const languages_table[] = {",
        ]
    )

    for lang_iso in SUPPORTED_LANGS:
        content.append(f"    languages_{lang_iso.lower()},")

    content.extend(
        [
            "};",
            "",
            "// clang-format on",
        ]
    )

    with open(f"{BASE_PATH}/i18n.c", "w") as f:
        f.write("\n".join(content) + "\n")


def main():
    client = lokalise.Client(os.environ.get("LOKALISE_API_TOKEN"))
    languages_map = {
        lang.lang_iso: lang.lang_name
        for lang in client.project_languages(LOKALISE_PROJECT_ID).items
        if lang.lang_iso in SUPPORTED_LANGS
    }

    for lang_display_text in languages_map.values():
        CHARS_NORMAL.update(c for c in lang_display_text if len(c.encode("UTF-8")) > 1)

    all_keys = client.keys(
        LOKALISE_PROJECT_ID, {"include_translations": 1, "limit": 1000}
    ).items
    all_keys.sort(key=lambda k: k.key_id)

    index = 0
    en_text_to_index = {}  # to avoid duplicate strings
    parsed = []

    for key in all_keys:
        key_name = key.key_name["other"]
        translations = {
            translation["language_iso"]: translation["translation"]
            for translation in key.translations
            if translation["language_iso"] in SUPPORTED_LANGS
        }
        if key_name.startswith("title"):
            CHARS_TITLE.update(
                c for c in "".join(translations.values()) if len(c.encode("UTF-8")) > 1
            )
        elif key_name.startswith("form"):
            CHARS_NORMAL.update(
                c for c in "".join(translations.values()) if len(c.encode("UTF-8")) > 1
            )
        else:
            CHARS_SUBTITLE.update(
                c for c in "".join(translations.values()) if len(c.encode("UTF-8")) > 1
            )

        en_text = translations["en"]
        curr = en_text_to_index.get(en_text)

        if curr is not None:
            parsed[curr]["key_names"].append(key_name)
        else:
            parsed.append(
                {
                    "key_names": [key_name],
                    "translations": translations,
                    "position": index,
                }
            )
            en_text_to_index[en_text] = index
            index += 1

    write_keys(parsed)
    write_i18n_header(languages_map, len(parsed))
    write_i18n_source(languages_map)

    for lang in languages_map.keys():
        write_lang(parsed, lang)

    for chars in ((CHARS_TITLE, 36), (CHARS_SUBTITLE, 24), (CHARS_NORMAL, 20)):
        chars_list = list(chars[0])
        chars_list.sort()


if __name__ == "__main__":
    main()
