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
    default:
      break;
  }

  return (char *)languages_en[msgid];
}