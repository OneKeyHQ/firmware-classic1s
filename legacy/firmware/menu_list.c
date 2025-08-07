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
#include "protect.h"
#include "recovery.h"
#include "reset.h"
#include "supervise.h"
#include "timer.h"
#include "usb.h"
#include "util.h"

#if !BITCOIN_ONLY
#include "fido2/resident_credential.h"
static bool resident_credential_refresh = true;
#endif

static struct menu settings_menu, main_menu, security_set_menu, about_menu;

void menu_erase_device(int index) {
  (void)index;
  uint8_t key = KEY_NULL;

  if (!layoutEraseDevice()) {
    return;
  }
  if (!protectPinOnDevice(false, true)) {
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
    snprintf(title, 32, "%s %s", _(O__ENABLE), _(M__PASSPHRASE));
    layoutDialogCenterAdapterV2(
        title, NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm, NULL,
        NULL, NULL, NULL, NULL, NULL,
        _(C__DO_YOU_WANT_TO_DISABLE_PASSPHRASE_ENCRYPTION));
  } else {
    snprintf(title, 32, "%s %s", _(O__DISABLE), _(M__PASSPHRASE));
    layoutDialogCenterAdapterV2(
        title, NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm, NULL,
        NULL, NULL, NULL, NULL, NULL,
        _(C__DO_YOU_WANT_TO_ENABLE_PASSPHRASE_ENCRYPTION));
  }

  key = protectWaitKey(0, 1);
  if (key != KEY_CONFIRM) {
    return;
  }

  config_setPassphraseProtection(index ? false : true);
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
    .previous = &security_set_menu,
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

  if (protectPinOnDevice(false, true)) {
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
static const struct menu_item security_set_menu_items[] = {
    {"Change PIN", NULL, true, menu_changePin, NULL, false, NULL},
    {"Check Recovery Phrase", NULL, true, menu_check_all_words, NULL, false,
     NULL},
    {"Passphrase", NULL, false, .sub_menu = &passphrase_set_menu,
     menu_para_passphrase, true, menu_para_passphrase_index},
    {"Reset Device", NULL, true, menu_erase_device, NULL, false, NULL},
};

static struct menu security_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(security_set_menu_items),
    .title = NULL,
    .items = (struct menu_item *)security_set_menu_items,
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

void main_menu_init(bool state) {
  menu_autolock_added_custom();

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
