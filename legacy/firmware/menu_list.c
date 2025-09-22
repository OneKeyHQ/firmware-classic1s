#include "menu_list.h"
#include "menu_core.h"
#include "menu_para.h"

#include "ble.h"
#include "buttons.h"
#include "common.h"
#include "config.h"
#include "gettext.h"
#include "layout2.h"
#include "oled.h"
#include "oled_text.h"
#include "protect.h"
#include "recovery.h"
#include "reset.h"
#include "se_chip.h"
#include "supervise.h"
#include "timer.h"
#include "usb.h"
#include "util.h"

#if !BITCOIN_ONLY
#include "fido2/resident_credential.h"
static bool resident_credential_refresh = true;
#endif

void security_menu_update_items(void);
static struct menu passphrase_manage_menu;
static void passphrase_menu_update_items(void);
static uint8_t menu_attach_to_pin_pagination(void);
static uint8_t menu_attach_passphrase_warning_pagination(
    const char *main_pin, const char *hidden_pin);
static int menu_countlines(char *text);
static int menu_line_index(char *text, int lines);
static void menu_pin_input_for_attach(void);
static uint8_t menu_attach_pin_options(const char *passphrase_pin);
static void menu_remove_pin_option(int index);
static void menu_set_new_passphrase_option(int index);
static void clear_temp_pin_data(void);
static void menu_remove_pin_from_limit_warning(void);
static void menu_remove_pin_input(void);
static void menu_remove_pin_confirmation(const char *pin_to_remove);
static bool require_standard_pin(bool cancel_allowed);

extern void drawScrollbar(int pages, int index);

static struct menu settings_menu, main_menu, security_set_menu, about_menu;

static char g_temp_passphrase_pin[MAX_PIN_LEN + 1] = "";
static char g_temp_main_pin[MAX_PIN_LEN + 1] = "";

void menu_erase_device(int index) {
  (void)index;
  uint8_t key = KEY_NULL;

  if (!layoutEraseDevice()) {
    return;
  }
  if (!require_standard_pin(true)) {
    return;
  }
  layoutDialogCenterAdapterV2(
      _(T__ERASE_DEVICE), NULL, NULL, &bmp_bottom_right_confirm, NULL, NULL,
      NULL, NULL, NULL, NULL,
      _(C__ARE_YOU_SURE_TO_RESET_THIS_DEVICE_THIS_ACTION_CANNOT_BE_UNDO));
  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return;
  }

  uint8_t ui_language_bak = ui_language;
  config_wipe();
  if (ui_language_bak) {
    ui_language = ui_language_bak;
  }
  layoutDialogCenterAdapterV2(
      NULL, &bmp_icon_ok, NULL, &bmp_bottom_right_confirm, NULL, NULL, NULL,
      NULL, NULL, NULL, _(C__DEVICE_RESET_COMPLETE_RESTART_NOW_EXCLAM));
  while (1) {
    key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      break;
    }
  }
#if !EMULATOR
  usbDisconnect();
  svc_system_reset();
#endif
}

void menu_changePin(int index) {
  (void)index;
  uint8_t key = KEY_NULL;

  layoutDialogCenterAdapterV2(_(M__CHANGE_PIN), NULL, &bmp_bottom_left_arrow,
                              &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL,
                              NULL, NULL,
                              _(C__BEFORE_START_VERIFY_YOUR_CURRENT_PIN));
  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return;
  }
  protectChangePinOnDevice(true, false, true);
}

void menu_set_passphrase(int index) {
  (void)index;

  uint8_t key = KEY_NULL;
  char title[32] = {0};
  if (index) {
    snprintf(title, 32, "%s %s", _(O__DISABLE), _(M__PASSPHRASE));

    uint8_t space_available = 0;
    bool attach_to_pin_used = false;
    if (se_get_pin_passphrase_space(&space_available)) {
      attach_to_pin_used = (space_available < 30);
    }

    if (attach_to_pin_used) {
      layoutDialogCenterAdapterV2(
          title, NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm, NULL,
          NULL, NULL, NULL, NULL, NULL,
          _(C__DISABLE_PASSPHRASE_HIDDEN_WALLET_PIN_WILL_NOT_UNLOCK_YOUR_DEVICE));
    } else {
      layoutDialogCenterAdapterV2(
          title, NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm, NULL,
          NULL, NULL, NULL, NULL, NULL,
          _(C__DO_YOU_WANT_TO_DISABLE_PASSPHRASE_ENCRYPTION));
    }
  } else {
    snprintf(title, 32, "%s %s", _(O__ENABLE), _(M__PASSPHRASE));
    layoutDialogCenterAdapterV2(
        title, NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm, NULL,
        NULL, NULL, NULL, NULL, NULL,
        _(C__DO_YOU_WANT_TO_ENABLE_PASSPHRASE_ENCRYPTION));
  }

  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return;
  }
  bool new_passphrase_state = index ? false : true;
  config_setPassphraseProtection(new_passphrase_state);

  if (!new_passphrase_state && is_passphrase_pin_enabled) {
    session_clear(true);
    menu_default();
    layoutHome();
    return;
  }

  bool current_state = false;
  (void)config_getPassphraseProtection(&current_state);
  security_menu_update_items();
  passphrase_menu_update_items();
}

void menu_attach_to_pin_desc(int index) {
  (void)index;

  uint8_t key = KEY_NULL;

  key = menu_attach_to_pin_pagination();
  if (key == KEY_CONFIRM) {
    menu_pin_input_for_attach();
  }
}

static int menu_countlines(char *text) {
  string_lines_t lines = split_string_to_lines(text, OLED_WIDTH, FONT_STANDARD);
  return lines.line_count;
}

static int menu_line_index(char *text, int lines) {
  string_lines_t split_lines =
      split_string_to_lines(text, OLED_WIDTH, FONT_STANDARD);
  int line_index =
      lines > split_lines.line_count ? split_lines.line_count : lines;
  return split_lines.line_start[line_index] - text;
}

static uint8_t menu_attach_to_pin_pagination(void) {
  uint8_t key = KEY_NULL;
  int rows = 0, pages = 0, page = 0;
  int p1 = 0, p2 = 0;
  char text[256] = {0};
  char *content = _(C__ATTACH_TO_PIN_DESC);

  rows = menu_countlines(content);
  pages = (rows + 4 - 1) / 4;
  if (pages <= 0) pages = 1;

  BITMAP *bmp_no = (BITMAP *)&bmp_bottom_left_close;
  BITMAP *bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  BITMAP *bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
  BITMAP *bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;

_layout:
  oledClear_ex();

  int start_line = page * 4;
  p1 = menu_line_index(content, start_line);
  p2 = menu_line_index(content, start_line + 4);
  memset(text, 0, sizeof(text));
  memcpy(text, content + p1, p2 - p1);

  if (pages == 1) {
    bmp_up = NULL;
    bmp_down = NULL;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow;
  } else if (page == 0) {
    bmp_up = NULL;
    bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow;
  } else if (page == pages - 1) {
    bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;
    bmp_down = NULL;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow;
  } else {
    bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;
    bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  }

  layoutDialogCenterAdapterV2(_(T__ATTACH_TO_PIN), NULL, (const BITMAP *)bmp_no,
                              (const BITMAP *)bmp_yes, (const BITMAP *)bmp_up,
                              (const BITMAP *)bmp_down, NULL, NULL, NULL, NULL,
                              text);
  if (pages > 1) drawScrollbar(pages, page);
  oledRefresh();

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (page > 0) {
        page--;
      }
      goto _layout;
    case KEY_DOWN:
      if (page < pages - 1) {
        page++;
      }
      goto _layout;
    case KEY_CONFIRM:
      if (page == 0) {
        return KEY_CONFIRM;
      }
      if (page == pages - 1) {
        return KEY_CONFIRM;
      }
      page++;
      goto _layout;
    default:
      return KEY_CANCEL;
  }

  return key;
}

void menu_set_usb_lock(int index) {
  uint8_t key = KEY_NULL;
  if (index) {
    layoutDialogCenterAdapterV2(
        _(T__DISABLE_USB_LOCK), NULL, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__DEVICE_WILL_REMAIN_UNLOCKED_WHEN_USB_PLUG_OR_UNPLUG));
    key = protectWaitKey(0, 1);
    if (key != KEY_CONFIRM) {
      return;
    }
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_confirm, NULL, NULL, NULL,
                                NULL, NULL, NULL,
                                _(C__DO_YOU_WANT_TO_DISABLE_USB_LOCK_QUES));
    key = protectWaitKey(0, 1);
    if (key != KEY_CONFIRM) {
      return;
    }
  } else {
    layoutDialogCenterAdapterV2(
        _(T__ENABLE_USB_LOCK), NULL, &bmp_bottom_left_arrow,
        &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__DEVICE_WILL_AUTO_LOCK_WHEN_USB_PLUG_OR_UNPLUG));
    key = protectWaitKey(0, 1);
    if (key != KEY_CONFIRM) {
      return;
    }
    layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_close,
                                &bmp_bottom_right_confirm, NULL, NULL, NULL,
                                NULL, NULL, NULL,
                                _(C__DO_YOU_WANT_TO_ENABLE_USB_LOCK_QUES));
    key = protectWaitKey(0, 1);
    if (key != KEY_CONFIRM) {
      return;
    }
  }

  config_setUsblock(index ? false : true);
}

void menu_set_input_direction(int index) {
  uint8_t key = KEY_NULL;
  if (!layoutInputDirection(index)) {
    return;
  }
  if (index) {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__DO_YOU_WANT_TO_REVERSE_THE_INPUT_DIRECTION_QUES));
  } else {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__DO_YOU_WANT_TO_RESTORE_THE_INPUT_DIRECTION_TO_DEFAULT_QUES));
  }
  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return;
  }

  config_setInputDirection(index ? true : false);
}

static const struct menu_item ble_set_menu_items[] = {
    {"Enable", NULL, true, menu_para_set_ble, NULL, true, NULL},
    {"Disable", NULL, true, menu_para_set_ble, NULL, true, NULL}};

static struct menu ble_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(ble_set_menu_items),
    .title = "Bluetooth",
    .items = (struct menu_item *)ble_set_menu_items,
    .previous = &settings_menu,
};

static const struct menu_item language_set_menu_items[] = {
    {"English", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"中文 (简体)", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"中文 (繁體)", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"日本語", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"Español", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"Português", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"Deutsch", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"한국어", NULL, true, menu_para_set_language, NULL, true, NULL}};

static struct menu language_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(language_set_menu_items),
    .title = "Language",
    .items = (struct menu_item *)language_set_menu_items,
    .previous = &settings_menu,
};

static const struct menu_item autolock_set_menu_items[] = {
    {"1", "minute", true, menu_para_set_sleep, NULL, true, NULL},
    {"2", "minutes", true, menu_para_set_sleep, NULL, true, NULL},
    {"5", "minutes", true, menu_para_set_sleep, NULL, true, NULL},
    {"10", "minutes", true, menu_para_set_sleep, NULL, true, NULL},
    {"Never", NULL, true, menu_para_set_sleep, NULL, true, NULL}};

static struct menu_item autolock_set_menu_items_added_custom[] = {
    {"1", "minute", true, menu_para_set_sleep, NULL, true, NULL},
    {"2", "minutes", true, menu_para_set_sleep, NULL, true, NULL},
    {"5", "minutes", true, menu_para_set_sleep, NULL, true, NULL},
    {"10", "minutes", true, menu_para_set_sleep, NULL, true, NULL},
    {"Never", NULL, true, menu_para_set_sleep, NULL, true, NULL},
    {"Custom", NULL, false, NULL, NULL, true, NULL}};

static struct menu autolock_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(autolock_set_menu_items),
    .title = "Auto-Lock",
    .items = (struct menu_item *)autolock_set_menu_items,
    .previous = &settings_menu,
};

static const struct menu_item shutdown_set_menu_items[] = {
    {"1", "minute", true, menu_para_set_shutdown, NULL, true, NULL},
    {"3", "minutes", true, menu_para_set_shutdown, NULL, true, NULL},
    {"5", "minutes", true, menu_para_set_shutdown, NULL, true, NULL},
    {"10", "minutes", true, menu_para_set_shutdown, NULL, true, NULL},
    {"Never", NULL, true, menu_para_set_shutdown, NULL, true, NULL}};

static struct menu shutdown_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(shutdown_set_menu_items),
    .title = "Shutdown",
    .items = (struct menu_item *)shutdown_set_menu_items,
    .previous = &settings_menu,
};

static const struct menu_item usb_lock_set_menu_items[] = {
    {"Enable", NULL, true, menu_set_usb_lock, NULL, true, NULL},
    {"Disable", NULL, true, menu_set_usb_lock, NULL, true, NULL}};

static struct menu usb_lock_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(usb_lock_set_menu_items),
    .title = "USB Lock",
    .items = (struct menu_item *)usb_lock_set_menu_items,
    .previous = &settings_menu,
};

static const struct menu_item input_direction_set_menu_items[] = {
    {"Default", NULL, true, menu_set_input_direction, NULL, true, NULL},
    {"Reverse", NULL, true, menu_set_input_direction, NULL, true, NULL}};

static struct menu input_direction_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(input_direction_set_menu_items),
    .title = "Input Direction",
    .items = (struct menu_item *)input_direction_set_menu_items,
    .previous = &settings_menu,
};

static const struct menu_item passphrase_set_menu_items[] = {
    {"Enable", NULL, true, menu_set_passphrase, NULL, true, NULL},
    {"Disable", NULL, true, menu_set_passphrase, NULL, true, NULL}};

static struct menu passphrase_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(passphrase_set_menu_items),
    .title = "Passphrase",
    .items = (struct menu_item *)passphrase_set_menu_items,
    .previous = &passphrase_manage_menu,
};

static const struct menu_item passphrase_manage_menu_items_base[] = {
    {"Passphrase", NULL, false, .sub_menu = &passphrase_set_menu,
     menu_para_passphrase, true, menu_para_passphrase_index},
};

static struct menu_item passphrase_manage_menu_items_dynamic[] = {
    {"Passphrase", NULL, false, .sub_menu = &passphrase_set_menu,
     menu_para_passphrase, true, menu_para_passphrase_index},
    {"Attach to PIN", NULL, true, menu_attach_to_pin_desc, NULL, false, NULL},
};

static struct menu passphrase_manage_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(passphrase_manage_menu_items_base),
    .title = NULL,
    .items = (struct menu_item *)passphrase_manage_menu_items_base,
    .previous = &security_set_menu,
    .button_type = BTN_TYPE_NEXT,
};

static const struct menu_item settings_menu_items[] = {
    {"Bluetooth", NULL, false, .sub_menu = &ble_set_menu, menu_para_ble_state,
     false, menu_para_ble_index},
    {"Language", NULL, false, .sub_menu = &language_set_menu,
     menu_para_language, false, menu_para_language_index},
    {"Auto-Lock", NULL, false, .sub_menu = &autolock_set_menu,
     menu_para_autolock, false, menu_para_autolock_index},
    {"Shutdown", NULL, false, .sub_menu = &shutdown_set_menu,
     menu_para_shutdown, false, menu_para_shutdown_index},
    {"USB Lock", NULL, false, .sub_menu = &usb_lock_set_menu,
     menu_para_usb_lock, false, menu_para_usb_lock_index},
    {"Input Direction", NULL, false, .sub_menu = &input_direction_set_menu,
     menu_para_input_direction, false, menu_para_input_direction_index}};

static const struct menu_item settings_menu_items_pure[] = {
    {"Bluetooth", NULL, false, .sub_menu = &ble_set_menu, menu_para_ble_state,
     false, menu_para_ble_index},
    {"Language", NULL, false, .sub_menu = &language_set_menu,
     menu_para_language, false, menu_para_language_index},
    {"Auto-Lock", NULL, false, .sub_menu = &autolock_set_menu,
     menu_para_autolock, false, menu_para_autolock_index},
    {"Input Direction", NULL, false, .sub_menu = &input_direction_set_menu,
     menu_para_input_direction, false, menu_para_input_direction_index}};

static struct menu settings_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(settings_menu_items),
    .title = NULL,
    .items = (struct menu_item *)settings_menu_items,
    .previous = &main_menu,
    .button_type = BTN_TYPE_NEXT,
};

void menu_init_settings_menu(void) {
  if (ble_hw_ver_is_pure()) {
    settings_menu.items = (struct menu_item *)settings_menu_items_pure;
    settings_menu.counts = COUNT_OF(settings_menu_items_pure);
  } else {
    settings_menu.items = (struct menu_item *)settings_menu_items;
    settings_menu.counts = COUNT_OF(settings_menu_items);
  }
}

void menu_check_all_words(int index) {
  (void)index;
  char desc[128] = "";
  uint8_t key = KEY_NULL;
  uint32_t word_count = 0;

refresh_menu:
  layoutDialogCenterAdapterV2(
      _(T__CHECK_RECOVERY_PHRASE), NULL, &bmp_bottom_left_arrow,
      &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__CHECK_YOUR_RECOVERY_PHRASE_BACKUP_MAKE_SURE_IT_IS_EXACTLY_THE_SAME_AS_THE_ONE_STORED_ON_DEVICE));
  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return;
  }

  if (require_standard_pin(true)) {
    memset(desc, 0, sizeof(desc));
    if (!protectSelectMnemonicNumber(&word_count, true)) {
      goto refresh_menu;
    }
    strlcpy(desc, _(C__ENTER_YOUR_STR_WORDS_RECOVERY_PHRASE_IN_ORDER),
            sizeof(desc) - 1);
    if (word_count == 12) {
      bracket_replace(desc, "12");
    } else if (word_count == 18) {
      bracket_replace(desc, "18");
    } else if (word_count == 24) {
      bracket_replace(desc, "24");
    } else {
      return;
    }

    layoutDialogCenterAdapterV2(_(T__ENTER_RECOVERY_PHRASE), NULL,
                                &bmp_bottom_left_arrow, &bmp_bottom_right_arrow,
                                NULL, NULL, NULL, NULL, NULL, NULL, desc);
    key = protectWaitKey(0, 1);
    if (key != KEY_CONFIRM) {
      return;
    }

    if (!verify_words(word_count)) {
      return;
    }
  }
}

#if !BITCOIN_ONLY
void menu_fido2_resident_credential(int index);

static CTAP_UserInfo user_info[FIDO2_RESIDENT_CREDENTIALS_COUNT]
    __attribute__((section(".secMessageSection"))) = {0};

static struct menu_item
    fido_resident_credential_menu_items[FIDO2_RESIDENT_CREDENTIALS_COUNT + 1] =
        {0};

static struct menu fido_resident_credential_menu = {
    .start = 0,
    .current = 0,
    .counts = 0,
    .title = NULL,
    .items = fido_resident_credential_menu_items,
    .previous = &main_menu,
    .button_type = BTN_TYPE_NEXT,
};

bool menu_fido2_remove_credential(const char *title, int index) {
  uint8_t key = KEY_NULL;

  layout_item_t items = {
      .label = _(ACTION__REMOVE),
      .value = NULL,
      .center = true,
  };

  layout_screen_t screen = {
      .bmp_up = NULL,
      .bmp_down = NULL,
      .bmp_no = &bmp_bottom_left_arrow,
      .bmp_yes = &bmp_bottom_right_arrow,
      .btn_no = NULL,
      .btn_yes = NULL,
      .title = title,
      .title_space = true,
      .items = &items,
      .item_count = 1,
      .item_index = 0,
      .item_offset = 0,
      .show_index = false,
      .show_scroll_bar = false,
  };

  layout_screen(screen);

  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return false;
  }
  layoutDialogCenterAdapterV2(NULL, &bmp_icon_warning, &bmp_bottom_left_arrow,
                              &bmp_bottom_right_arrow, NULL, NULL, NULL,
                              _(FIDO_REMOVE_KEY_DESC), NULL, NULL, NULL);
  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return false;
  }
  resident_credential_delete(index);
  layoutDialogCenterAdapterV2(NULL, NULL, NULL, &bmp_bottom_right_confirm, NULL,
                              NULL, NULL, NULL,
                              _(FIDO_REMOVE_KEY_SUCCESS_TITLE), NULL, NULL);
  protectWaitKey(timer1s * 2, 0);
  return true;
}

void menu_fido2_resident_credential_display(int index) {
  uint8_t key = KEY_NULL;
  layout_fido2_resident_credential(0, 0, user_info[index].rp_id,
                                   user_info[index].user_name);
  key = protectWaitKey(0, 1);
  if (key == KEY_CONFIRM) {
    if (menu_fido2_remove_credential(user_info[index].rp_id,
                                     user_info[index].index)) {
      if (fido_resident_credential_menu.counts > 1) {
        if (index < fido_resident_credential_menu.counts - 1) {
          memset(&user_info[index], 0, sizeof(CTAP_UserInfo));
          memmove(&user_info[index], &user_info[index + 1],
                  (fido_resident_credential_menu.counts - index - 1) *
                      sizeof(CTAP_UserInfo));
        }
        fido_resident_credential_menu.counts--;
        if (fido_resident_credential_menu.current) {
          fido_resident_credential_menu.current--;
        }
        menu_refresh();
      } else {
        fido_resident_credential_menu.counts = 0;
        resident_credential_refresh = false;
        menu_fido2_resident_credential(0);
        // fido_resident_credential_menu_items[0].go_prev = true;
      }
    }
    return;
  }
}

static int cred_cmp_func(const void *_a, const void *_b) {
  CTAP_UserInfo *a = (CTAP_UserInfo *)_a;
  CTAP_UserInfo *b = (CTAP_UserInfo *)_b;
  return a->creation_time - b->creation_time;
}

void menu_set_fido_switch(int index) {
  uint8_t key = KEY_NULL;
  if (index == 0) {
  } else {
    layoutDialogCenterAdapterV2(_(FIDO_DISABLE_PROMPT_TITLE), NULL,
                                &bmp_bottom_left_arrow, &bmp_bottom_right_arrow,
                                NULL, NULL, NULL, NULL, NULL, NULL,
                                _(FIDO_DISABLE_PROMPT_DESC));
    key = protectWaitKey(0, 1);
    if (key != KEY_CONFIRM) {
      return;
    }
  }
  layoutDialogCenterAdapterV2(_(FIDO_DISABLE_PROMPT_TITLE), NULL,
                              &bmp_bottom_left_close, &bmp_bottom_right_confirm,
                              NULL, NULL, NULL, NULL, NULL, NULL,
                              _(C__IT_WILL_TAKE_EFFECT_AFTER_DEVICE_RESTART));

  key = protectWaitKey(0, 0);
  if (key == KEY_CONFIRM) {
    config_setFidoSwitch(index ? false : true);
    usbDisconnect();
    svc_system_reset();
  }
}

static const struct menu_item fido_switch_set_menu_items[] = {
    {"Enable", NULL, true, menu_set_fido_switch, NULL, true, NULL},
    {"Disable", NULL, true, menu_set_fido_switch, NULL, true, NULL}};

static struct menu fido_switch_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(fido_switch_set_menu_items),
    .title = "Enable Security Keys",
    .items = (struct menu_item *)fido_switch_set_menu_items,
    .previous = &main_menu,
};

void menu_fido2_resident_credential(int index) {
  (void)index;

  uint8_t indexs[FIDO2_RESIDENT_CREDENTIALS_COUNT] = {0};
  uint8_t count = 0;
  if (resident_credential_refresh) {
    count = resident_credential_info(indexs, 30);
  } else {
    resident_credential_refresh = true;
    count = fido_resident_credential_menu.counts;
    menu_init(&main_menu);
  }

  if (count == 0) {
    layoutDialogCenterAdapterV2(NULL, NULL, &bmp_bottom_left_arrow, NULL, NULL,
                                NULL, NULL, NULL, _(FIDO_LIST_EMPTY_TEXT), NULL,
                                NULL);
    protectWaitKey(timer1s * 2, 0);
    return;
  }
  CTAP_credentialDescriptor cred_desc = {0};

  uint8_t percent = 0;
  for (int i = 0; i < count; i++) {
    percent = 30 + ((i + 1) * 100 / count) * 70 / 100;
    layoutProgressAdapter(_(C__PROCESSING_ETC), percent * 10);
    memset(&cred_desc, 0, sizeof(CTAP_credentialDescriptor));
    resident_credential_get_desc(indexs[i], &cred_desc);
    char *account_name = get_account_name(&cred_desc.credential.user);

    strlcpy(user_info[i].rp_id, cred_desc.credential.rp.id,
            sizeof(user_info[i].rp_id));
    strlcpy(user_info[i].user_name, account_name,
            sizeof(user_info[i].user_name));
    user_info[i].creation_time = cred_desc.credential.creation_time;
    user_info[i].index = indexs[i];

    fido_resident_credential_menu_items[i].name = user_info[i].rp_id;
    fido_resident_credential_menu_items[i].is_function = true;
    fido_resident_credential_menu_items[i].func =
        menu_fido2_resident_credential_display;
    fido_resident_credential_menu_items[i].go_prev = false;
  }
  qsort(user_info, count, sizeof(CTAP_UserInfo), cred_cmp_func);
  fido_resident_credential_menu.counts = count;
  fido_resident_credential_menu.current = 0;
  fido_resident_credential_menu.start = 0;
  fido_resident_credential_menu.items = fido_resident_credential_menu_items;
  fido_resident_credential_menu.previous = &main_menu;
  fido_resident_credential_menu.loop = true;

  menu_init(&fido_resident_credential_menu);
}
#endif

static const struct menu_item security_set_menu_items_base[] = {
    {"Change PIN", NULL, true, menu_changePin, NULL, false, NULL},
    {"Check Recovery Phrase", NULL, true, menu_check_all_words, NULL, false,
     NULL},
    {"Passphrase", NULL, false, .sub_menu = &passphrase_manage_menu, NULL, true,
     NULL},
#if !BITCOIN_ONLY
    {"FIDO Keys", NULL, true, menu_fido2_resident_credential, NULL, false,
     NULL},
#endif
    {"Reset Device", NULL, true, menu_erase_device, NULL, false, NULL},
};

static struct menu security_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(security_set_menu_items_base),
    .title = NULL,
    .items = (struct menu_item *)security_set_menu_items_base,
    .previous = &main_menu,
    .button_type = BTN_TYPE_NEXT,
};

void menu_set_trezor_compatibility(int index) {
  (void)index;

  uint8_t key = KEY_NULL;

  if (0 == index) {
    layoutDialogCenterAdapterV2(
        _(T__RESTORE_TREZOR_COMPAT), NULL, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__IT_WILL_TAKE_EFFECT_AFTER_DEVICE_RESTART));
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        break;
      }
      if (key == KEY_CANCEL) {
        return;
      }
    }
  } else {
  _layout_disable:
    layoutDialogCenterAdapterV2(
        _(T__DISABLE_TREZOR_COMPAT), NULL, &bmp_bottom_left_close,
        &bmp_bottom_right_arrow, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__THIS_WILL_PREVENT_YOU_FROM_USING_THIRD_PARTY_WALLET_CLIENT_AND_WEBSITES_WHICH_ONLY_SUPPORT_TREZOR));
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        break;
      }
      if (key == KEY_CANCEL) {
        return;
      }
    }

    layoutDialogCenterAdapterV2(
        _(T__DISABLE_TREZOR_COMPAT), NULL, &bmp_bottom_left_arrow,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__IT_WILL_TAKE_EFFECT_AFTER_DEVICE_RESTART));
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        break;
      }
      if (key == KEY_CANCEL) {
        goto _layout_disable;
      }
    }

    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, &bmp_bottom_left_close,
        &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__WARNING_EXCLAM_DONOT_CHANGE_THIS_SETTING_IF_YOU_NOT_SURE));
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        break;
      }
      if (key == KEY_CANCEL) {
        return;
      }
    }
  }

  bool trezor_comp_mode = false;
  config_getTrezorCompMode(&trezor_comp_mode);
  config_setTrezorCompMode(index ? false : true);
#if !EMULATOR
  if ((index && trezor_comp_mode) || (!index && !trezor_comp_mode)) {
    svc_system_reset();
  }
#endif
}

static const struct menu_item trezor_compatibility_set_menu_items[] = {
    {"Enable", NULL, true, menu_set_trezor_compatibility, NULL, true, NULL},
    {"Disable", NULL, true, menu_set_trezor_compatibility, NULL, true, NULL}};

static struct menu trezor_compatibility_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(trezor_compatibility_set_menu_items),
    .title = "Trezor Mode",
    .items = (struct menu_item *)trezor_compatibility_set_menu_items,
    .previous = &about_menu,
};

void menu_set_safety_checks(int index) {
  bool confirmed = false;
  if (index == 0) {
    confirmed = layoutConfirmSafetyChecks(SafetyCheckLevel_Strict, false);
  } else {
    confirmed =
        layoutConfirmSafetyChecks(SafetyCheckLevel_PromptTemporarily, false);
  }
  if (!confirmed) {
    return;
  }
  config_setSafetyCheckLevel(index ? SafetyCheckLevel_PromptTemporarily
                                   : SafetyCheckLevel_Strict);
}

static const struct menu_item safety_checks_set_menu_items[] = {
    {"On", NULL, true, menu_set_safety_checks, NULL, true, NULL},
    {"Off", NULL, true, menu_set_safety_checks, NULL, true, NULL}};

static struct menu safety_checks_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(safety_checks_set_menu_items),
    .title = "Safety Checks",
    .items = (struct menu_item *)safety_checks_set_menu_items,
    .previous = &about_menu,
};

static const struct menu_item about_menu_items[] = {
    {"Device Info", NULL, true, layoutDeviceParameters, NULL, false, NULL},
    {"Certification", NULL, true, layoutAboutCertifications, NULL, false, NULL},
    {"Trezor Compat", NULL, false, .sub_menu = &trezor_compatibility_set_menu,
     menu_para_trezor_comp_mode_state, true, menu_para_trezor_comp_mode_index},
    {"Safety Checks", NULL, false, .sub_menu = &safety_checks_set_menu,
     menu_para_safety_checks_state, true, menu_para_safety_checks_index},
};

static struct menu about_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(about_menu_items),
    .title = NULL,
    .items = (struct menu_item *)about_menu_items,
    .previous = &main_menu,
    .button_type = BTN_TYPE_NEXT,
};

static const struct menu_item main_menu_items[] = {
    {"General", NULL, false, .sub_menu = &settings_menu, NULL, false},
    {"Security", NULL, false, .sub_menu = &security_set_menu, NULL, false},
    {"About Device", NULL, false, .sub_menu = &about_menu, NULL, false},
#if !BITCOIN_ONLY
    {"Security Key", NULL, false, .sub_menu = &fido_switch_set_menu,
     menu_para_fido_switch, false, menu_para_fido_switch_index},
    {"Management Security Key", NULL, true, menu_fido2_resident_credential,
     NULL, false, NULL},
#endif
};

static struct menu main_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(main_menu_items),
    .title = NULL,
    .items = (struct menu_item *)main_menu_items,
    .previous = NULL,
    .button_type = BTN_TYPE_NEXT,
};

void menu_autolock_added_custom(void) {
  static char autolock_custom_name[32] = {0};
  uint32_t ms = config_getSleepDelayMs();
  if ((ms != 1 * 60 * 1000) && (ms != 2 * 60 * 1000) && (ms != 5 * 60 * 1000) &&
      (ms != 10 * 60 * 1000) && (ms != 0)) {
    autolock_set_menu.counts = COUNT_OF(autolock_set_menu_items_added_custom);
    autolock_set_menu.items = autolock_set_menu_items_added_custom;
    char *value = format_time(ms);
    memset(autolock_custom_name, 0, 32);
    strcat(autolock_custom_name, value);
    strcat(autolock_custom_name, _(O_BRACKET_CUSTOM_BRACKET));
    autolock_set_menu_items_added_custom[5].name = autolock_custom_name;
  } else {
    autolock_set_menu.counts = COUNT_OF(autolock_set_menu_items);
    autolock_set_menu.items = (struct menu_item *)autolock_set_menu_items;
  }
}

void security_menu_update_items(void) {
  security_set_menu.counts = COUNT_OF(security_set_menu_items_base);
  security_set_menu.items = (struct menu_item *)security_set_menu_items_base;
}

static void passphrase_menu_update_items(void) {
  bool passphrase_protection = false;
  config_getPassphraseProtection(&passphrase_protection);
  if (passphrase_protection) {
    passphrase_manage_menu.counts =
        COUNT_OF(passphrase_manage_menu_items_dynamic);
    passphrase_manage_menu.items = passphrase_manage_menu_items_dynamic;
  } else {
    passphrase_manage_menu.counts = COUNT_OF(passphrase_manage_menu_items_base);
    passphrase_manage_menu.items =
        (struct menu_item *)passphrase_manage_menu_items_base;
  }
}

void main_menu_init(bool state) {
  menu_autolock_added_custom();
  security_menu_update_items();
  passphrase_menu_update_items();
  if (state) {
    menu_init(&main_menu);
    menu_update(&settings_menu, previous, &main_menu);
  }
}

void menu_default(void) {
  menu_init_settings_menu();
  bool fido_switch = false;
  config_getFidoSwitch(&fido_switch);
  menu_update(&main_menu, counts, fido_switch ? 5 : 4);
  menu_init(&main_menu);
}

static void menu_pin_input_for_attach(void) {
  uint8_t available_space = 0;
  (void)se_get_pin_passphrase_space(&available_space);
  const char *main_pin = NULL;
  const char *hidden_pin1 = NULL;
  const char *hidden_pin2 = NULL;
  static char main_pin_copy[MAX_PIN_LEN + 1] = "";
  static char pin1_copy[MAX_PIN_LEN + 1] = "";
  static char pin2_copy[MAX_PIN_LEN + 1] = "";

get_main_pin : {
  if (session_isUnlocked() && is_passphrase_pin_enabled) {
    layoutDialogCenterAdapterV2(
        _(T__ENTER_PIN), NULL, &bmp_bottom_left_close, &bmp_bottom_right_arrow,
        NULL, NULL, NULL, NULL, NULL, NULL,
        _(C__NEXT_PLEASE_ENTER_THE_STANDARD_WALLET_PIN));
    uint8_t guide_key = protectWaitKey(0, 0);
    if (guide_key != KEY_CONFIRM) {
      clear_temp_pin_data();
      return;
    }
  }

  const char *pin_title;
  if (session_isUnlocked() && is_passphrase_pin_enabled) {
    pin_title = _(T__STANDARD_PIN);
  } else {
    pin_title = _(T__ENTER_PIN);
  }
  main_pin = protectInputPin(pin_title, 4, MAX_PIN_LEN, true);
  if (!main_pin) {
    clear_temp_pin_data();
    return;
  }
  strlcpy(main_pin_copy, main_pin, sizeof(main_pin_copy));
  strlcpy(g_temp_main_pin, main_pin, sizeof(g_temp_main_pin));

  bool main_ok = config_verifyPin(main_pin, PIN_TYPE_USER_CHECK);
  pin_result_t main_pin_result = se_get_pin_result_type();
  (void)main_pin_result;  // avoid -Werror when RTT logging is disabled
  if (!main_ok) {
    protectPinErrorTips(true);
    goto get_main_pin;
  }
}

retry_pin:
  hidden_pin1 = protectInputPin(_(T__SET_HIDDEN_PIN), 6, MAX_PIN_LEN, true);
  if (!hidden_pin1 || strlen(hidden_pin1) < 6) {
    clear_temp_pin_data();
    return;
  }
  strlcpy(pin1_copy, hidden_pin1, sizeof(pin1_copy));

  hidden_pin2 =
      protectInputPin(_(T__ENTER_NEW_PIN_AGAIN), 6, MAX_PIN_LEN, true);
  if (!hidden_pin2 || strlen(hidden_pin2) < 6) {
    clear_temp_pin_data();
    return;
  }
  strlcpy(pin2_copy, hidden_pin2, sizeof(pin2_copy));

  if (strcmp(pin1_copy, pin2_copy) != 0) {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, NULL, &bmp_bottom_right_retry, NULL, NULL,
        NULL, NULL, NULL, NULL, _(C__PIN_NOT_MATCH_EXCLAM_TRY_AGAIN));

    uint8_t key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      goto retry_pin;
    }
    return;
  }

  if (strcmp(main_pin_copy, pin1_copy) == 0) {
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, NULL, &bmp_bottom_right_retry, NULL, NULL,
        NULL, NULL, NULL, NULL,
        _(C__PIN_ALREADY_USED_PLEASE_TRY_A_DIFFERENT_ONE));

    uint8_t key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      goto retry_pin;
    }
    return;
  }

  bool passphrase_pin_exists =
      config_verifyPin(pin1_copy, PIN_TYPE_PASSPHRASE_PIN_CHECK);
  pin_result_t check_result = se_get_pin_result_type();
  (void)check_result;

  if (passphrase_pin_exists) {
  show_pin_exists_warning:
    layoutDialogCenterAdapterV2(_(T__ATTACH_PASSPHRASE), NULL,
                                &bmp_bottom_left_close, &bmp_bottom_right_arrow,
                                NULL, NULL, NULL, NULL, NULL, NULL,
                                _(C__PIN_HAS_ATTACHED_ONE_PASSPHRASE));
    {
      uint8_t key = protectWaitKey(0, 1);
      if (key == KEY_CANCEL) {
        return;
      } else if (key == KEY_CONFIRM) {
        uint8_t ret = menu_attach_pin_options(pin1_copy);
        if (ret == KEY_CANCEL) {
          goto show_pin_exists_warning;
        }
        return;
      }
    }
  } else {
    uint8_t space_available = 0;
    if (se_get_pin_passphrase_space(&space_available) == sectrue) {
      if (space_available <= 27) {
        layoutDialogCenterAdapterV2(
            NULL, &bmp_icon_warning, &bmp_bottom_left_close,
            &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
            _(C__HIT_THE_LIMIT_30_PINS_MAX));

        uint8_t key = protectWaitKey(0, 0);
        if (key == KEY_CONFIRM) {
          menu_remove_pin_from_limit_warning();
        }
        clear_temp_pin_data();
        return;
      }
    }
  }

  layoutDialogCenterAdapterV2(_(T__ATTACH_PASSPHRASE), NULL,
                              &bmp_bottom_left_close, &bmp_bottom_right_arrow,
                              NULL, NULL, NULL, NULL, NULL, NULL,
                              _(C__YOU_CAN_ATTACH_A_PASSPHRASE_TO_THIS_PIN));

  uint8_t key = protectWaitKey(0, 1);
  if (key == KEY_CANCEL) {
    menu_init(&passphrase_manage_menu);
  } else if (key == KEY_CONFIRM) {
    menu_attach_passphrase_warning_pagination(main_pin_copy, pin1_copy);
  }
}

static uint8_t menu_attach_passphrase_warning_pagination(
    const char *main_pin, const char *hidden_pin) {
  uint8_t key = KEY_NULL;
  int index = 0;
  int pages = 2;
  char *page_contents[2] = {_(C__PASSPHRASE__ATTACH_ONE_PASSPHRASE_DESC1),
                            _(C__PASSPHRASE__ATTACH_ONE_PASSPHRASE_DESC2)};

  BITMAP *bmp_no = (BITMAP *)&bmp_bottom_left_close;
  BITMAP *bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  BITMAP *bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
  BITMAP *bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;

_layout:
  if (index == 0) {
    bmp_up = NULL;
    bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  } else if (index == pages - 1) {
    bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;
    bmp_down = NULL;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow;
  } else {
    bmp_up = (BITMAP *)&bmp_bottom_middle_arrow_up;
    bmp_down = (BITMAP *)&bmp_bottom_middle_arrow_down;
    bmp_yes = (BITMAP *)&bmp_bottom_right_arrow_off;
  }

  char title[64] = {0};
  char page_str[32] = {0};
  strlcpy(title, _(T__WARNING_EXCLAM_BRACKET_STR_BRACKET), sizeof(title));
  snprintf(page_str, sizeof(page_str), "%d/%d", index + 1, pages);
  bracket_replace(title, page_str);

  layoutDialogCenterAdapterV2(title, NULL, (const BITMAP *)bmp_no,
                              (const BITMAP *)bmp_yes, (const BITMAP *)bmp_up,
                              (const BITMAP *)bmp_down, NULL, NULL, NULL, NULL,
                              page_contents[index]);
  if (pages > 1) drawScrollbar(pages, index);
  oledRefresh();

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (index > 0) {
        index--;
      }
      goto _layout;
    case KEY_DOWN:
      if (index < pages - 1) {
        index++;
      }
      goto _layout;
    case KEY_CONFIRM:
      if (index == 0) {
        index++;
        goto _layout;
      } else {
        static char passphrase[MAX_PASSPHRASE_LEN + 1] = "";
        memset(passphrase, 0, sizeof(passphrase));
        bool result = inputPassphraseOnDeviceRequired(passphrase);
        if (result && strlen(passphrase) > 0) {
          layoutShowPassphrase(passphrase);
          uint8_t confirm_key = protectWaitKey(0, 0);
          if (confirm_key != KEY_CONFIRM) {
            index = 0;
            goto _layout;
          }

          layoutDialogCenterAdapterV2(
              _(T__SAVE_PASSPHRASE), NULL, NULL, &bmp_bottom_right_arrow, NULL,
              NULL, NULL, NULL, NULL, NULL, _(C__PASSPHRASE_SAVE_DESC));
          uint8_t save_key = protectWaitKey(0, 1);
          if (save_key == KEY_CONFIRM) {
            secbool pin_unlocked = se_getSecsta();

            if (pin_unlocked != sectrue) {
              secbool verify_result = se_verifyPin(main_pin, PIN_TYPE_USER);

              if (verify_result != sectrue) {
                layoutDialogCenterAdapterV2(NULL, &bmp_icon_error, NULL,
                                            &bmp_bottom_right_confirm, NULL,
                                            NULL, NULL, NULL, NULL, NULL,
                                            "Failed to verify PIN with SE");
                protectWaitKey(0, 1);
                menu_init(&passphrase_manage_menu);
                return KEY_CONFIRM;
              }

              pin_unlocked = se_getSecsta();
            } else {
            }

            bool override = false;
            secbool se_result = se_set_pin_passphrase(main_pin, hidden_pin,
                                                      passphrase, &override);

            (void)se_get_pin_result_type();

            if (se_result == sectrue) {
              layoutDialogCenterAdapterV2(
                  NULL, &bmp_icon_ok, NULL, &bmp_bottom_right_arrow, NULL, NULL,
                  NULL, NULL, NULL, NULL,
                  _(C__PASSPHRASE_SET_AND_ATTACHED_TO_PIN));
              protectWaitKey(0, 1);

              if (override) {
                session_clear(true);
                menu_default();
                layoutHome();
                return KEY_CONFIRM;
              }

              passphrase_menu_update_items();
              menu_init(&passphrase_manage_menu);
            } else {
              (void)se_lasterror();

              layoutDialogCenterAdapterV2(
                  NULL, &bmp_icon_error, NULL, &bmp_bottom_right_confirm, NULL,
                  NULL, NULL, NULL, NULL, NULL, "Failed to save passphrase");
              protectWaitKey(0, 1);
              menu_init(&passphrase_manage_menu);
            }
          } else {
            menu_init(&passphrase_manage_menu);
          }
        } else {
          index = 0;
          goto _layout;
        }
        return KEY_CONFIRM;
      }
      break;
    case KEY_CANCEL:
      clear_temp_pin_data();
      menu_init(&passphrase_manage_menu);
      return KEY_CANCEL;
    default:
      clear_temp_pin_data();
      return KEY_CANCEL;
  }

  clear_temp_pin_data();
  return key;
}

static void clear_temp_pin_data(void) {
  memset(g_temp_passphrase_pin, 0, sizeof(g_temp_passphrase_pin));
  memset(g_temp_main_pin, 0, sizeof(g_temp_main_pin));
}

static bool require_standard_pin(bool cancel_allowed) {
  while (1) {
    const char *pin_title;
    if (session_isUnlocked() && is_passphrase_pin_enabled) {
      pin_title = _(T__STANDARD_PIN);
    } else {
      pin_title = _(T__ENTER_PIN);
    }

    const char *pin = protectInputPin(pin_title, DEFAULT_PIN_LEN, MAX_PIN_LEN,
                                      cancel_allowed);
    if (!pin || pin == PIN_CANCELED_BY_BUTTON) {
      return false;
    }

    bool ok = config_unlock(pin, PIN_TYPE_USER_CHECK);
    if (!ok) {
      protectPinErrorTips(true);
      continue;
    }

    pin_result_t result = se_get_pin_result_type();
    if (result != USER_PIN_ENTERED && result != PIN_SUCCESS) {
      protectPinErrorTips(true);
      continue;
    }

    is_passphrase_pin_enabled = false;
    return true;
  }
}

static void menu_remove_pin_option(int index) {
  (void)index;

  layoutDialogCenterAdapterV2(
      NULL, &bmp_icon_warning, &bmp_bottom_left_close,
      &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__REMOVE_PIN_YOU_WILL_NOT_BE_ABLE_TO_USE_IT_TO_UNLOCK_THE_DEVICE));

  uint8_t key = protectWaitKey(0, 0);
  if (key == KEY_CONFIRM) {
    bool current = false;
    secbool result = se_delete_pin_passphrase(g_temp_passphrase_pin, &current);

    if (result == sectrue) {
      layoutDialogCenterAdapterV2(NULL, &bmp_icon_ok, NULL,
                                  &bmp_bottom_right_arrow, NULL, NULL, NULL,
                                  NULL, NULL, NULL, _(C__PIN_REMOVED));

      if (current) {
        protectWaitKey(timer1s * 2, 0);
        session_clear(true);
        clear_temp_pin_data();
        menu_default();
        layoutHome();
        return;
      } else {
        protectWaitKey(0, 0);  // Wait for user input
      }

      clear_temp_pin_data();
      passphrase_menu_update_items();
      menu_init(&passphrase_manage_menu);
    } else {
      (void)se_get_pin_result_type();
    }
  } else {
  }
}

static void menu_set_new_passphrase_option(int index) {
  (void)index;

  layoutDialogCenterAdapterV2(_(T__ATTACH_PASSPHRASE), NULL,
                              &bmp_bottom_left_close, &bmp_bottom_right_arrow,
                              NULL, NULL, NULL, NULL, NULL, NULL,
                              _(C__YOU_CAN_ATTACH_A_PASSPHRASE_TO_THIS_PIN));

  uint8_t key = protectWaitKey(0, 0);
  if (key == KEY_CANCEL) {
    return;
  } else if (key == KEY_CONFIRM) {
    (void)menu_attach_passphrase_warning_pagination(g_temp_main_pin,
                                                    g_temp_passphrase_pin);
    return;
  }
}

static void display_attach_pin_options(uint8_t selected) {
  oledClear();

  const char *option1 = _(O__REMOVE_THIS_PIN);
  const char *option2 = _(O__SET_A_NEW_PASSPHRASE);

  int y1 = 20;
  int y2 = 35;

  int text_width1 = oledStringWidthAdapter(option1, FONT_STANDARD);
  int text_width2 = oledStringWidthAdapter(option2, FONT_STANDARD);

  int x1 = (OLED_WIDTH - text_width1) / 2;
  int x2 = (OLED_WIDTH - text_width2) / 2;

  oledDrawStringCenterAdapter(OLED_WIDTH / 2, y1, option1, FONT_STANDARD);
  if (selected == 0) {
    oledInvert(x1 - 2, y1 - 2, x1 + text_width1 + 2, y1 + 10);
  }

  oledDrawStringCenterAdapter(OLED_WIDTH / 2, y2, option2, FONT_STANDARD);
  if (selected == 1) {
    oledInvert(x2 - 2, y2 - 2, x2 + text_width2 + 2, y2 + 10);
  }

  oledDrawBitmap(0, OLED_HEIGHT - 11, &bmp_bottom_left_arrow);

  oledDrawBitmap(OLED_WIDTH - 16, OLED_HEIGHT - 11, &bmp_bottom_right_arrow);

  if (selected == 0) {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
  } else {
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  }

  oledRefresh();
}

static uint8_t menu_attach_pin_options(const char *passphrase_pin) {
  strlcpy(g_temp_passphrase_pin, passphrase_pin, sizeof(g_temp_passphrase_pin));

  uint8_t selected = 0;
  uint8_t key = KEY_NULL;

  while (1) {
    display_attach_pin_options(selected);

    key = protectWaitKey(0, 0);

    switch (key) {
      case KEY_UP:
        if (selected > 0) {
          selected--;

        } else {
        }
        break;
      case KEY_DOWN:
        if (selected < 1) {
          selected++;

        } else {
        }
        break;
      case KEY_CANCEL:

        return KEY_CANCEL;
      case KEY_CONFIRM:

        if (selected == 0) {
          menu_remove_pin_option(0);
        } else {
          menu_set_new_passphrase_option(0);
        }
        return KEY_CONFIRM;
      default:

        break;
    }
  }
}

static void menu_remove_pin_from_limit_warning(void) {
  layoutDialogCenterAdapterV2(
      _(T__REMOVE_PIN), NULL, &bmp_bottom_left_close, &bmp_bottom_right_arrow,
      NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__NEXT_PLEASE_ENTER_THE_HIDDEN_WALLET_PIN_YOU_WANT_TO_REMOVE));

  uint8_t key = protectWaitKey(0, 0);
  if (key == KEY_CONFIRM) {
    menu_remove_pin_input();
  }
}

static void menu_remove_pin_input(void) {
  static char pin_to_remove[MAX_PIN_LEN + 1] = "";
  static int retry_count = 0;
  const int max_retries = 3;

  if (retry_count >= max_retries) {
    retry_count = 0;
    return;
  }

  const char *entered_pin =
      protectInputPin(_(T__ENTER_HIDDEN_PIN), 6, MAX_PIN_LEN, true);
  if (entered_pin == NULL) {
    return;
  }

  strncpy(pin_to_remove, entered_pin, MAX_PIN_LEN);
  pin_to_remove[MAX_PIN_LEN] = '\0';

  bool passphrase_pin_exists =
      config_verifyPin(pin_to_remove, PIN_TYPE_PASSPHRASE_PIN_CHECK);
  pin_result_t remove_check = se_get_pin_result_type();
  (void)remove_check;

  if (passphrase_pin_exists) {
    retry_count = 0;
    menu_remove_pin_confirmation(pin_to_remove);
  } else {
    retry_count++;
    layoutDialogCenterAdapterV2(
        NULL, &bmp_icon_warning, NULL, &bmp_bottom_right_retry, NULL, NULL,
        NULL, NULL, NULL, NULL,
        _(C__INCORRECT_PIN_THE_PIN_YOU_ENTERED_IS_INCORRECT));

    uint8_t key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      menu_remove_pin_input();
    }
  }
}

static void menu_remove_pin_confirmation(const char *pin_to_remove) {
  layoutDialogCenterAdapterV2(
      NULL, &bmp_icon_question, &bmp_bottom_left_close,
      &bmp_bottom_right_confirm, NULL, NULL, NULL, NULL, NULL, NULL,
      _(C__REMOVE_PIN_YOU_WILL_NOT_BE_ABLE_TO_USE_IT_TO_UNLOCK_THE_DEVICE));

  uint8_t key = protectWaitKey(0, 0);
  if (key == KEY_CONFIRM) {
    bool current = false;
    secbool result = se_delete_pin_passphrase(pin_to_remove, &current);

    if (result == sectrue) {
      layoutDialogCenterAdapterV2(NULL, &bmp_icon_ok, NULL,
                                  &bmp_bottom_right_arrow, NULL, NULL, NULL,
                                  NULL, NULL, NULL, _(C__PIN_REMOVED));

      if (current) {
        session_clear(true);
        menu_default();
        layoutHome();
        return;
      } else {
        protectWaitKey(0, 0);
      }
    } else {
      layoutDialog(&bmp_icon_error, NULL, "Continue", NULL, "Failed to",
                   "remove PIN.", NULL, "Please try again.", NULL, NULL);
      protectWaitKey(0, 0);
    }
  }
}
