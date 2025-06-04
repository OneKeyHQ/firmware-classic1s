#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "gettext.h"
#include "language.h"

extern uint8_t ui_language;

char *gettext(const char *msgid) { return (char *)msgid; }

char *gettextX(int msgid) {
  switch (ui_language) {
    case 1:
      return (char *)languages_zh_cn[msgid];
    case 2:
      return (char *)languages_zh_tw[msgid];
    case 3:
      return (char *)languages_ja[msgid];
    case 4:
      return (char *)languages_es[msgid];
    case 5:
      return (char *)languages_pt_br[msgid];
    case 6:
      return (char *)languages_de[msgid];
    case 7:
      return (char *)languages_ko_kr[msgid];
    default:
      break;
  }

  return (char *)languages_en[msgid];
}

extern bool is_valid_ascii(const uint8_t *data, uint32_t size);
const char *gettext_from_en(char *en_str) {
  int msgid = -1;
  size_t len = strlen(en_str);
  if (!is_valid_ascii((uint8_t *)en_str, len)) {
    return en_str;
  }
  for (int i = 0; i < I18N_LANGUAGE_ITEMS; i++) {
    if ((0 == strncmp(en_str, languages_en[i], len)) &&
        (len == strlen(languages_en[i]))) {
      msgid = i;
      break;
    }
  }
  if (msgid < 0) return en_str;
  return _(msgid);
}
