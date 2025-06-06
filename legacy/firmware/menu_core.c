#include "menu_core.h"
#include "bitmaps.h"
#include "buttons.h"
#include "config.h"
#include "gettext.h"
#include "layout2.h"
#include "util.h"

static struct menu *currentMenu;
static bool refresh_menu = true;

void menu_refresh(void) { refresh_menu = true; }

void menu_init(struct menu *menu) {
  currentMenu = menu;
  currentMenu->current = currentMenu->start;
  refresh_menu = true;
}

static const char *_gettext(char *en_str) {
  int msgid = -1;
  size_t len = strlen(en_str);
  if (!is_valid_ascii((uint8_t *)en_str, len)) {
    return en_str;
  }
  for (int i = 0; i < I18N_ITEMS_COUNT; i++) {
    if ((0 == strncmp(en_str, languages_en[i], len)) &&
        (len == strlen(languages_en[i]))) {
      msgid = i;
      break;
    }
  }
  if (msgid < 0) return en_str;
  return _(msgid);
}

void menu_display(struct menu *menu) {
  char descriptions[7][64] = {0};
  const BITMAP *bmp_yes = NULL;
  char *text_yes = NULL;

  for (int i = -3; i <= 3; i++) {
    int index = menu->current + i;
    if (index < 0 || index >= menu->counts) {
      continue;
    }
    strlcpy(descriptions[i + 3], _gettext(menu->items[index].name), 64);
    if (menu->items[index].name2) {
      if (0 == memcmp(menu->items[index].name2, "minutes", 7)) {
        strlcpy(descriptions[i + 3], _(O__STR_MINUTES), 64);
        bracket_replace(descriptions[i + 3], menu->items[index].name);
      } else {
        strcat(descriptions[i + 3], " ");
        strcat(descriptions[i + 3], _gettext(menu->items[index].name2));
      }
    }
  }

  switch (menu->button_type) {
    case BTN_TYPE_NEXT:
      bmp_yes = &bmp_bottom_right_arrow;
      text_yes = "Next";
      break;
    case BTN_TYPE_YES:
    default:
      bmp_yes = &bmp_bottom_right_confirm;
      text_yes = "Okay";
      break;
  }

  layoutMenuItemsEx(text_yes, bmp_yes, menu->current + 1, menu->counts,
                    menu->title ? _gettext(menu->title) : NULL, descriptions[3],
                    _gettext(menu->items[menu->current].name),
                    menu->items[menu->current].name2
                        ? _gettext(menu->items[menu->current].name2)
                        : NULL,
                    menu->items[menu->current].para
                        ? menu->items[menu->current].para()
                        : NULL,
                    menu->current > 0 ? descriptions[2] : NULL,
                    menu->current > 1 ? descriptions[1] : NULL,
                    menu->current > 2 ? descriptions[0] : NULL,
                    menu->current < menu->counts - 1 ? descriptions[4] : NULL,
                    menu->current < menu->counts - 2 ? descriptions[5] : NULL,
                    menu->current < menu->counts - 3 ? descriptions[6] : NULL);
}

void menu_up(void) {
  if (currentMenu->current > 0) {
    currentMenu->current--;
  }
}

void menu_down(void) {
  if (currentMenu->current < currentMenu->counts - 1) {
    currentMenu->current++;
  }
}

void menu_enter(void) {
  if (!currentMenu->items[currentMenu->current].is_function &&
      currentMenu->items[currentMenu->current].sub_menu) {
    if ((currentMenu->items[currentMenu->current].para != NULL) &&
        (currentMenu->items[currentMenu->current].index != NULL)) {
      int index = currentMenu->items[currentMenu->current].index();
      currentMenu = currentMenu->items[currentMenu->current].sub_menu;
      currentMenu->current = index;
    } else {
      currentMenu = currentMenu->items[currentMenu->current].sub_menu;
      currentMenu->current = currentMenu->start;
    }
  } else if (currentMenu->items[currentMenu->current].func != NULL) {
    currentMenu->items[currentMenu->current].func(currentMenu->current);
    if (layoutLast != layoutHome) layoutLast = menu_run;
    if (currentMenu->previous &&
        currentMenu->items[currentMenu->current].go_prev) {
      currentMenu = currentMenu->previous;
    }
  }
}

void menu_exit(void) {
  currentMenu->current = currentMenu->start;
  if (currentMenu->previous == NULL) {
    layoutHome();
  } else {
    currentMenu = currentMenu->previous;
  }
}

void menu_run(uint8_t key, uint32_t time) {
  static uint32_t wait_time = 0;

  if (layoutLast != menu_run) {
    refresh_menu = true;
    layoutLast = menu_run;
  }

  if (refresh_menu) {
    refresh_menu = false;
    menu_display(currentMenu);
    wait_time = time;
  }
  if (wait_time + timer1s * 30 < time) {
    if (key == KEY_NULL) key = KEY_CANCEL;
  }
  switch (key) {
    case KEY_UP:
      menu_up();
      break;
    case KEY_DOWN:
      menu_down();
      break;
    case KEY_CANCEL:
      menu_exit();
      break;
    case KEY_CONFIRM:
      menu_enter();
      break;
    default:
      break;
  }
  if (key != KEY_NULL) {
    refresh_menu = true;
  }
#if EMULATOR
  if (!config_isInitialized()) {
    layoutLast = onboarding;
  }
#endif
}
