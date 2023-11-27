#include "menu_list.h"
#include "menu_core.h"
#include "menu_para.h"

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

bool exitBlindSignByInitialize;

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

static struct menu_item ble_set_menu_items[] = {
    {"Enable", NULL, true, menu_para_set_ble, NULL, true, NULL},
    {"Disable", NULL, true, menu_para_set_ble, NULL, true, NULL}};

static struct menu ble_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(ble_set_menu_items),
    .title = "Bluetooth",
    .items = ble_set_menu_items,
    .previous = &settings_menu,
};

static struct menu_item language_set_menu_items[] = {
    {"English", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"中文 (简体)", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"中文 (繁體)", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"日本語", NULL, true, menu_para_set_language, NULL, true, NULL},
    {"Español", NULL, true, menu_para_set_language, NULL, true, NULL}};

static struct menu language_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(language_set_menu_items),
    .title = "Language",
    .items = language_set_menu_items,
    .previous = &settings_menu,
};

static struct menu_item autolock_set_menu_items[] = {
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
    .items = autolock_set_menu_items,
    .previous = &settings_menu,
};

static struct menu_item shutdown_set_menu_items[] = {
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
    .items = shutdown_set_menu_items,
    .previous = &settings_menu,
};

static struct menu_item usb_lock_set_menu_items[] = {
    {"Enable", NULL, true, menu_set_usb_lock, NULL, true, NULL},
    {"Disable", NULL, true, menu_set_usb_lock, NULL, true, NULL}};

static struct menu usb_lock_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(usb_lock_set_menu_items),
    .title = "USB Lock",
    .items = usb_lock_set_menu_items,
    .previous = &settings_menu,
};

static struct menu_item input_direction_set_menu_items[] = {
    {"Default", NULL, true, menu_set_input_direction, NULL, true, NULL},
    {"Reverse", NULL, true, menu_set_input_direction, NULL, true, NULL}};

static struct menu input_direction_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(input_direction_set_menu_items),
    .title = "Input Direction",
    .items = input_direction_set_menu_items,
    .previous = &settings_menu,
};

static struct menu_item passphrase_set_menu_items[] = {
    {"Enable", NULL, true, menu_set_passphrase, NULL, true, NULL},
    {"Disable", NULL, true, menu_set_passphrase, NULL, true, NULL}};

static struct menu passphrase_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(passphrase_set_menu_items),
    .title = "Passphrase",
    .items = passphrase_set_menu_items,
    .previous = &security_set_menu,
};

static struct menu_item settings_menu_items[] = {
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

static struct menu settings_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(settings_menu_items),
    .title = NULL,
    .items = settings_menu_items,
    .previous = &main_menu,
    .button_type = BTN_TYPE_NEXT,
};

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

static struct menu_item security_set_menu_items[] = {
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
    .items = security_set_menu_items,
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

static struct menu_item trezor_compatibility_set_menu_items[] = {
    {"Enable", NULL, true, menu_set_trezor_compatibility, NULL, true, NULL},
    {"Disable", NULL, true, menu_set_trezor_compatibility, NULL, true, NULL}};

static struct menu trezor_compatibility_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(trezor_compatibility_set_menu_items),
    .title = "Trezor Compatibility",
    .items = trezor_compatibility_set_menu_items,
    .previous = &about_menu,
};

void menu_set_safety_checks(int index) {
  (void)index;
  if (index) {
    config_setSafetyCheckLevel(SafetyCheckLevel_PromptAlways);
  } else {
    config_setSafetyCheckLevel(SafetyCheckLevel_Strict);
  }
}

static struct menu_item safety_checks_set_menu_items[] = {
    {"On", NULL, true, menu_set_safety_checks, NULL, true, NULL},
    {"Off", NULL, true, menu_set_safety_checks, NULL, true, NULL}};

static struct menu safety_checks_set_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(safety_checks_set_menu_items),
    .title = "Safety Checks",
    .items = safety_checks_set_menu_items,
    .previous = &about_menu,
};

static struct menu_item about_menu_items[] = {
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
    .items = about_menu_items,
    .previous = &main_menu,
    .button_type = BTN_TYPE_NEXT,
};

static struct menu_item main_menu_items[] = {
    {"General", NULL, false, .sub_menu = &settings_menu, NULL, false},
    {"Security", NULL, false, .sub_menu = &security_set_menu, NULL, false},
    {"About Device", NULL, false, .sub_menu = &about_menu, NULL, false}};

static struct menu main_menu = {
    .start = 0,
    .current = 0,
    .counts = COUNT_OF(main_menu_items),
    .title = NULL,
    .items = main_menu_items,
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
    autolock_set_menu.items = autolock_set_menu_items;
  }
}

void main_menu_init(bool state) {
  menu_autolock_added_custom();
  if (state) {
    menu_init(&main_menu);
    menu_update(&settings_menu, previous, &main_menu);
  }
}

void menu_default(void) { menu_init(&main_menu); }