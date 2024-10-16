#include "alph_layout.h"

bool layoutFee(const char *fee) {
  uint8_t key = KEY_NULL;
  char desc[32] = {0};
  char fee_with_unit[128] = {0};

  const char **tx_msg = format_tx_message("Alephium");

  oledClear();
  layoutHeader(tx_msg[0]);
  strcat(desc, "Fee:");

  strlcpy(fee_with_unit, fee, sizeof(fee_with_unit));
  strlcat(fee_with_unit, " ALPH", sizeof(fee_with_unit));

  oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);
  oledDrawStringAdapter(0, 23, fee_with_unit, FONT_STANDARD);

  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  oledRefresh();
  while (1) {
    key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      break;
    }
    if (key == KEY_CANCEL || key == KEY_NULL) {
      return false;
    }
  }
  return true;
}

bool layoutFinal(void) {
  uint8_t key = KEY_NULL;
  const char **tx_msg = format_tx_message("Alephium");

  oledClear();
  layoutHeader(_(T__SIGN_TRANSACTION));
  layoutTxConfirmPage(tx_msg[1]);
  layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
  layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  oledRefresh();
  while (1) {
    key = protectWaitKey(0, 1);
    if (key == KEY_CONFIRM) {
      return true;
      break;
    }
    if (key == KEY_CANCEL || key == KEY_NULL) {
      return false;
    }
  }
}

void displayAddressPage(const char **str, int index, int rowcount,
                        const char *header) {
  oledClear_ex();
  layoutHeader(header);

  if (0 == index) {
    oledDrawStringAdapter(0, 13, _(I__SEND_TO_COLON), FONT_STANDARD);
    for (int i = 0; i < 3; i++) {
      oledDrawStringAdapter(0, 23 + i * 10, str[i], FONT_STANDARD);
    }
  } else {
    for (int i = 0; i < 4; i++) {
      oledDrawStringAdapter(0, 13 + i * 10, str[index + i - 1], FONT_STANDARD);
    }
  }

  if (index > 0) {
    oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_up);
  }
  if (index < rowcount - 3) {
    oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                   &bmp_bottom_middle_arrow_down);
  }
}

void drawScrollBar(int index, int rowcount) {
  int bar_start = 12, bar_end = 52;
  int bar_height = 40 - 2 * (rowcount - 4);
  for (int i = bar_start; i < bar_end; i += 2) {
    oledDrawPixel(OLED_WIDTH - 1, i);
  }
  for (int i = bar_start + 2 * index;
       i < (bar_start + bar_height + 2 * (index - 1)) - 1; i++) {
    oledDrawPixel(OLED_WIDTH - 1, i);
    oledDrawPixel(OLED_WIDTH - 2, i);
  }
}

bool displayAndNavigateAddress(const char *to_address, const char *header) {
  uint32_t rowlen = 21, addrlen = strlen(to_address);
  int index = 0, rowcount = addrlen / rowlen + 1;
  const char **str =
      split_message((const uint8_t *)to_address, addrlen, rowlen);

  while (1) {
    displayAddressPage(str, index, rowcount, header);
    drawScrollBar(index, rowcount);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    oledRefresh();

    uint8_t key = protectWaitKey(0, 0);
    switch (key) {
      case KEY_UP:
        if (index > 0) index--;
        break;
      case KEY_DOWN:
        if (index < rowcount - 3) index++;
        break;
      case KEY_CONFIRM:
        return true;
      case KEY_CANCEL:
      default:
        return false;
    }
  }
}

bool layoutOutput(const char *chain_name, const char *amount,
                  const char *to_address, const char *token_id,
                  const char *token_amount, const uint8_t *bytecode,
                  size_t bytecode_size) {
  bool ret = true;
  uint8_t key = KEY_NULL;
  char desc[256] = {0};
  const char **tx_msg = format_tx_message(chain_name);
  if (token_id) {
    oledClear();
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, 13, _(T__THE_FOLLOWING_TX_OUTPUT_CONTAINS_TOKEN),
                          FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    oledRefresh();
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        ret = true;
        break;
      }
      if (key == KEY_CANCEL || key == KEY_NULL) {
        return false;
      }
    }
  }

  if (bytecode && bytecode_size > 0) {
    oledClear();
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, 13, _(SIGN_TX_CONTAIN_CONTRACT_DATA_TEXT),
                          FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
    oledRefresh();
    while (1) {
      key = protectWaitKey(0, 1);
      if (key == KEY_CONFIRM) {
        break;
      }
      if (key == KEY_CANCEL || key == KEY_NULL) {
        return false;
      }
    }

    int index = 0;
    int chars_per_line = 20;
    int lines_per_page = 3;
    int chars_per_page = chars_per_line * lines_per_page;
    int total_chars = bytecode_size * 2;
    int total_pages = (total_chars + chars_per_page - 1) / chars_per_page;

    while (1) {
      oledClear();
      layoutHeader(tx_msg[0]);
      snprintf(desc, sizeof(desc), "Data (%d/%d):", index + 1, total_pages);
      oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);

      for (int i = 0; i < lines_per_page; i++) {
        int start = (index * chars_per_page) + (i * chars_per_line);
        if (start >= total_chars) break;

        char bytecode_part[22] = {0};  // 21 characters + null terminator
        int chars_to_copy = (start + chars_per_line > total_chars)
                                ? (total_chars - start)
                                : chars_per_line;
        for (int j = 0; j < chars_to_copy; j += 2) {
          if (start + j < total_chars) {
            snprintf(bytecode_part + j, sizeof(bytecode_part) - j, "%02x",
                     bytecode[(start + j) / 2]);
          }
        }
        oledDrawStringAdapter(0, 23 + i * 10, bytecode_part, FONT_STANDARD);
      }

      if (index > 0) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
      }
      if (index < total_pages - 1) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      }

      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      oledRefresh();

      key = protectWaitKey(0, 0);
      switch (key) {
        case KEY_UP:
          if (index > 0) index--;
          break;
        case KEY_DOWN:
          if (index < total_pages - 1) index++;
          break;
        case KEY_CONFIRM:
          ret = true;
          goto exit_bytecode_display;
        case KEY_CANCEL:
          return false;
      }
    }
  exit_bytecode_display:;
  } else {
    {
      int index = 0;
      int lines_per_page = 3;
      int total_lines = 0;
      char amount_lines[5][64] = {0};

      if (token_id) {
        snprintf(amount_lines[total_lines++], sizeof(amount_lines[0]), "%s",
                 _(I__TOKEN_AMOUNT_COLON));
        snprintf(amount_lines[total_lines++], sizeof(amount_lines[0]), "%s",
                 token_amount);
      } else {
        snprintf(amount_lines[total_lines++], sizeof(amount_lines[0]),
                 "ALPH %s", _(I__AMOUNT_COLON));
        snprintf(amount_lines[total_lines++], sizeof(amount_lines[0]),
                 "%s ALPH", amount);
      }

      int total_pages = (total_lines + lines_per_page - 1) / lines_per_page;

      while (1) {
        oledClear();
        layoutHeader(tx_msg[0]);

        for (int i = 0;
             i < lines_per_page && index * lines_per_page + i < total_lines;
             i++) {
          oledDrawStringAdapter(0, 13 + i * 10,
                                amount_lines[index * lines_per_page + i],
                                FONT_STANDARD);
        }
        if (index > 0) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        }
        if (index < total_pages - 1) {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }

        layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
        layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
        oledRefresh();

        key = protectWaitKey(0, 0);
        switch (key) {
          case KEY_UP:
            if (index > 0) index--;
            break;
          case KEY_DOWN:
            if (index < total_pages - 1) index++;
            break;
          case KEY_CONFIRM:
            ret = true;
            goto exit_amount_display;
          case KEY_CANCEL:
            return false;
        }
      }
    exit_amount_display:;
    }

    if (token_id) {
      int index = 0;
      int chars_per_line = 21;
      int lines_per_page = 3;
      int chars_per_page = chars_per_line * lines_per_page;
      int total_chars = strlen(token_id);
      int total_pages = (total_chars + chars_per_page - 1) / chars_per_page;

      while (1) {
        oledClear();
        layoutHeader(tx_msg[0]);
        snprintf(desc, sizeof(desc), "Token ID (%d/%d):", index + 1,
                 total_pages);
        oledDrawStringAdapter(0, 13, desc, FONT_STANDARD);

        for (int i = 0; i < lines_per_page; i++) {
          int start = (index * chars_per_page) + (i * chars_per_line);
          if (start >= total_chars) break;

          char token_id_part[22] = {0};
          strncpy(token_id_part, token_id + start, sizeof(token_id_part) - 1);
          token_id_part[sizeof(token_id_part) - 1] = '\0';
          oledDrawStringAdapter(0, 23 + i * 10, token_id_part, FONT_STANDARD);
        }

        if (index > 0) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        }
        if (index < total_pages - 1) {
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }

        layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
        layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
        oledRefresh();

        key = protectWaitKey(0, 0);
        switch (key) {
          case KEY_UP:
            if (index > 0) index--;
            break;
          case KEY_DOWN:
            if (index < total_pages - 1) index++;
            break;
          case KEY_CONFIRM:
            ret = true;
            goto exit_token_id_display;
          case KEY_CANCEL:
            return false;
        }
      }
    exit_token_id_display:;
    }
  }

  if (to_address) {
    if (strlen(to_address) > 63) {
      return displayAndNavigateAddress(to_address, tx_msg[0]);
    } else {
      oledClear();
      layoutHeader(tx_msg[0]);
      oledDrawStringAdapter(0, 13, _(I__SEND_TO_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, 23, to_address, FONT_STANDARD);
      layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
      layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
      oledRefresh();
      while (1) {
        key = protectWaitKey(0, 0);
        if (key == KEY_CONFIRM) {
          return true;
        }
        if (key == KEY_CANCEL || key == KEY_NULL) {
          return false;
        }
      }
    }
  }
  return ret;
}
