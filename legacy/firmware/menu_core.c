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
  char descriptions[4][64] = {0};
  const BITMAP *bmp_yes = NULL;
  char *text_yes = NULL;

  int max_item_count = 4;
  int start_index = 0, end_index = 0;

  if (menu->title) {
    max_item_count = 3;
  }

  if (menu->counts <= max_item_count) {
    start_index = 0;
    end_index = menu->counts - 1;
  } else {
    int half = max_item_count / 2;

    if (max_item_count % 2 == 0) {
      start_index = menu->current - half + 1;
    } else {
      start_index = menu->current - half;
    }

    if (start_index < 0) {
      start_index = 0;
    }

    end_index = start_index + max_item_count - 1;
    if (end_index >= menu->counts) {
      end_index = menu->counts - 1;
      start_index = end_index - max_item_count + 1;
    }
  }

  layout_item_t items[4] = {0};

  for (int i = start_index; i <= end_index; i++) {
    strlcpy(descriptions[i - start_index], _gettext(menu->items[i].name), 64);
    if (menu->items[i].name2) {
      if (0 == memcmp(menu->items[i].name2, "minutes", 7)) {
        strlcpy(descriptions[i - start_index], _(O__STR_MINUTES), 64);
        bracket_replace(descriptions[i - start_index], menu->items[i].name);
      } else {
        strcat(descriptions[i - start_index], " ");
        strcat(descriptions[i - start_index], _gettext(menu->items[i].name2));
      }
    }

    items[i - start_index].label = descriptions[i - start_index];
    if (i == menu->current) {
      items[i - start_index].value = menu->items[menu->current].para
                                         ? menu->items[menu->current].para()
                                         : NULL;
    } else {
      items[i - start_index].value = NULL;
    }
    items[i - start_index].center = menu->title ? true : false;
  }

  switch (menu->button_type) {
    case BTN_TYPE_NEXT:
      bmp_yes = &bmp_bottom_right_arrow;
      break;
    case BTN_TYPE_YES:
    default:
      bmp_yes = &bmp_bottom_right_confirm;
      break;
  }

  layout_screen_t screen = {
      .bmp_up = &bmp_bottom_middle_arrow_up,
      .bmp_down = &bmp_bottom_middle_arrow_down,
      .bmp_no = &bmp_bottom_left_arrow,
      .bmp_yes = bmp_yes,
      .btn_no = NULL,
      .btn_yes = text_yes,
      .title = menu->title ? _gettext(menu->title) : NULL,
      .title_space = false,
      .items = items,
      .item_count = menu->counts,
      .item_index = menu->current,
      .item_offset = start_index,
      .show_index = true,
      .show_scroll_bar = true,
      .loop = currentMenu->loop,
  };

  layout_screen(screen);
}

void menu_up(void) {
  if (currentMenu->current > 0) {
    currentMenu->current--;
  } else if (currentMenu->loop) {
    currentMenu->current = currentMenu->counts - 1;
  }
}

void menu_down(void) {
  if (currentMenu->current < currentMenu->counts - 1) {
    currentMenu->current++;
  } else if (currentMenu->loop) {
    currentMenu->current = 0;
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
