import os

import lokalise

LOKALISE_PROJECT_ID = "372193756406ee669eacc1.76289155"
BASE_PATH = os.path.join(os.path.dirname(__file__), "..", "firmware/i18n/")
SUPPORTED_LANGS = ("en", "zh_CN", "zh_TW", "ja", "es", "pt_BR", "de", "ko_KR")
CHARS_NORMAL = set()
CHARS_TITLE = set()
CHARS_SUBTITLE = set()
"""
LANG_MAP = {
    'zh_CN': 'Chinese Simplified',
    'zh_HK': 'Chinese Traditional',
    'en': 'English',
    'ja': 'Japanese',
    'es': 'Spanish',
    'pt_BR': 'Portuguese',
    'de': 'Deutsch',
    'ko_KR': 'Korean',
}
"""


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

    for lang in languages_map.keys():
        write_lang(parsed, lang)

    for chars in ((CHARS_TITLE, 36), (CHARS_SUBTITLE, 24), (CHARS_NORMAL, 20)):
        chars_list = list(chars[0])
        chars_list.sort()


if __name__ == "__main__":
    main()
