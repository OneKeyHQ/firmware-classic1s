#include "ton_layout.h"
#include "memzero.h"
#include "messages.h"
#include "util.h"

#include "SEGGER_RTT.h"
#include "rtt_log.h"

void drawTonScrollbar(int pages, int index) {
  int i, bar_start = 12, bar_end = 52;
  int bar_heght = 40 - 2 * (pages - 1);
  for (i = bar_start; i < bar_end; i += 2) {  // 40 pixel
    oledDrawPixel(OLED_WIDTH - 1, i);
  }
  for (i = bar_start + 2 * ((int)index);
       i < (bar_start + bar_heght + 2 * ((int)index)) - 1; i++) {
    oledDrawPixel(OLED_WIDTH - 1, i);
    oledDrawPixel(OLED_WIDTH - 2, i);
  }
}

bool confirmFinal(void) {
  uint8_t key = KEY_NULL;
  const char **tx_msg = format_tx_message("Ton");

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
    }
    if (key == KEY_CANCEL || key == KEY_NULL) {
      return false;
    }
  }
}

bool layoutTonSign(const char *chain_name, bool token_transfer,
                   const char *amount, const char *to_str, const char *signer,
                   const char *recipient, const char *token_id,
                   const uint8_t *data, uint16_t len, const char *memo) {
  bool result = false;
  int index = 0, sub_index = 0, tokenid_len = 0, token_id_rowcount = 0;
  int i, y = 0, bar_heght, bar_start = 12, bar_end = 52;
  uint8_t key = KEY_NULL;
  uint8_t max_index = 4;
  char desc[64] = {0};
  char title[64] = {0};
  char title_data[32] = {0}, bytes_buf[16] = {0};
  char lines[21] = {0};
  int data_rowcount = len % 10 ? len / 10 + 1 : len / 10;
  uint32_t rowlen = 21;
  const char **str;
  int to_str_rowcount = strlen(to_str) / rowlen;
  int signer_rowcount = strlen(signer) / rowlen;
  if (strlen(to_str) % rowlen) to_str_rowcount++;
  if (strlen(signer) % rowlen) signer_rowcount++;
  if (token_id) {
    tokenid_len = strlen(token_id);
    token_id_rowcount = tokenid_len / rowlen + 1;
  }

  if (token_transfer && (token_id == NULL)) {
    strcat(title, _(T__TOKEN_TRANSFER));
  } else if (token_transfer && (token_id != NULL)) {
    strcat(title, _(T__NFT_TRANSFER));
  } else {
    snprintf(title, 64, "%s", _(T__STR_CHAIN_TRANSACTION));
    bracket_replace(title, chain_name);
  }
  strcat(title_data, _(T__VIEW_DATA_BRACKET_STR));
  uint2str(len, bytes_buf);
  strcat(bytes_buf, " bytes");
  bracket_replace(title_data, bytes_buf);

  if (len > 0) max_index++;
  if (memo != NULL) max_index++;
  if (token_transfer) max_index += 1;  // token transfer

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;
  if (0 == index) {
    sub_index = 0;
    layoutHeader(title);
    memset(desc, 0, 64);
    strcat(desc, _(I__AMOUNT_COLON));
    oledDrawStringAdapter(0, y, desc, FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, amount, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (1 == index && token_transfer) {  // token contract address
    sub_index = 0;
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__TOKEN_CONTRACT_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, to_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (2 == index && token_transfer) {  // token recipient
    sub_index = 0;
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__SEND_TO_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, recipient, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (1 == index && !token_transfer) {  // To
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__SEND_TO_COLON), FONT_STANDARD);
    if (to_str_rowcount > 3) {
      str = split_message((const uint8_t *)to_str, strlen(to_str), rowlen);
      if (sub_index == 0) {
        oledDrawStringAdapter(0, y + 1 * 10, str[0], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 2 * 10, str[1], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 3 * 10, str[2], FONT_STANDARD);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else {
        oledDrawStringAdapter(0, y + 1 * 10, str[sub_index], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 2 * 10, str[sub_index + 1], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 3 * 10, str[sub_index + 2], FONT_STANDARD);
        if (sub_index == to_str_rowcount - 3) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }
      }
      drawTonScrollbar(to_str_rowcount - 2, sub_index);
    } else {
      sub_index = 0;
      oledDrawStringAdapter(0, y + 10, to_str, FONT_STANDARD);
    }

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if ((2 == index && !token_transfer) ||
             (3 == index && token_transfer)) {  // From
    layoutHeader(title);
    memset(desc, 0, 64);
    strcat(desc, _(I__FROM_COLON));
    oledDrawStringAdapter(0, y, desc, FONT_STANDARD);
    if (signer_rowcount > 3) {
      str = split_message((const uint8_t *)signer, strlen(signer), rowlen);
      if (sub_index == 0) {
        oledDrawStringAdapter(0, y + 1 * 10, str[0], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 2 * 10, str[1], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 3 * 10, str[2], FONT_STANDARD);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else {
        oledDrawStringAdapter(0, y + 1 * 10, str[sub_index], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 2 * 10, str[sub_index + 1], FONT_STANDARD);
        oledDrawStringAdapter(0, y + 3 * 10, str[sub_index + 2], FONT_STANDARD);
        if (sub_index == signer_rowcount - 3) {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
        } else {
          oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_up);
          oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                         &bmp_bottom_middle_arrow_down);
        }
      }
      drawTonScrollbar(signer_rowcount - 2, sub_index);
    } else {
      sub_index = 0;
      oledDrawStringAdapter(0, y + 10, signer, FONT_STANDARD);
    }

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if ((3 == index && len > 0 && !token_transfer) ||
             (4 == index && len > 0 && token_transfer)) {  // data
    layoutHeader(title_data);
    if (data_rowcount > 4) {
      data2hexaddr(data + 10 * (sub_index), 10, lines);
      oledDrawStringAdapter(0, 13, lines, FONT_STANDARD);
      data2hexaddr(data + 10 * (sub_index + 1), 10, lines);
      oledDrawStringAdapter(0, 13 + 1 * 10, lines, FONT_STANDARD);
      data2hexaddr(data + 10 * (sub_index + 2), 10, lines);
      oledDrawStringAdapter(0, 13 + 2 * 10, lines, FONT_STANDARD);
      if (sub_index == data_rowcount - 4) {
        if (len % 10) {
          data2hexaddr(data + 10 * (sub_index + 3), len % 10, lines);
        } else {
          data2hexaddr(data + 10 * (sub_index + 3), 10, lines);
        }
      } else {
        data2hexaddr(data + 10 * (sub_index + 3), 10, lines);
      }
      oledDrawStringAdapter(0, 13 + 3 * 10, lines, FONT_STANDARD);

      // scrollbar
      bar_heght = 40 - 2 * (data_rowcount - 5);
      if (bar_heght < 6) bar_heght = 6;
      for (i = bar_start; i < bar_end; i += 2) {  // 40 pixel
        oledDrawPixel(OLED_WIDTH - 1, i);
      }
      if (sub_index <= 18) {
        for (i = bar_start + 2 * ((int)sub_index);
             i < (bar_start + bar_heght + 2 * ((int)sub_index - 1)) - 1; i++) {
          oledDrawPixel(OLED_WIDTH - 1, i);
          oledDrawPixel(OLED_WIDTH - 2, i);
        }
      } else {
        for (i = bar_start + 2 * 18;
             i < (bar_start + bar_heght + 2 * (18 - 1)) - 1; i++) {
          oledDrawPixel(OLED_WIDTH - 1, i);
          oledDrawPixel(OLED_WIDTH - 2, i);
        }
      }

      if (sub_index == 0) {
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      } else if (sub_index == data_rowcount - 4) {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
      } else {
        oledDrawBitmap(OLED_WIDTH / 4, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_up);
        oledDrawBitmap(3 * OLED_WIDTH / 4 - 8, OLED_HEIGHT - 8,
                       &bmp_bottom_middle_arrow_down);
      }
    } else {
      char buf[90] = {0};
      data2hexaddr(data, len, buf);
      oledDrawStringAdapter(0, 13, buf, FONT_STANDARD);
    }

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_next);

  } else if ((3 == index && (memo != NULL) && !token_transfer) ||
             (4 == index && (memo != NULL) && token_transfer)) {
    sub_index = 0;
    layoutHeader(title);
    oledDrawStringAdapter(0, y, _(I__MEMO_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, memo, FONT_STANDARD);

    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }

  oledRefresh();

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      if (sub_index > 0) {
        sub_index--;
      }
      goto refresh_menu;
    case KEY_DOWN:
      if ((len > 0 && index == 3 && sub_index < data_rowcount - 4) ||
          (len > 0 && index == 4 && sub_index < data_rowcount - 4)) {
        sub_index++;
      }
      if (token_transfer && token_id && index == 2 &&
          sub_index < token_id_rowcount - 3) {  // token_id
        sub_index++;
      }
      if (1 == index && !token_transfer &&
          sub_index < to_str_rowcount - 3) {  // To
        sub_index++;
      }
      if (sub_index < signer_rowcount - 3 &&
          ((2 == index && !token_transfer) ||
           (4 == index && token_transfer))) {  // From
        sub_index++;
      }
      goto refresh_menu;
    case KEY_CONFIRM:
      if (index == max_index - 2) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      sub_index = 0;
      goto refresh_menu;
    case KEY_CANCEL:
      if ((0 == index) || (index == max_index - 1)) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      sub_index = 0;
      goto refresh_menu;
    default:
      break;
  }

  return result;
}
