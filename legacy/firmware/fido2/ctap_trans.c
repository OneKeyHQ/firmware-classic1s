/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2015 Mark Bryars <mbryars@google.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ecdsa.h>
#include <stdint.h>
#include <string.h>

#include "bip32.h"
#include "buttons.h"
#include "common.h"
#include "config.h"
#include "crypto.h"
#include "curves.h"
#include "debug.h"
#include "gettext.h"
#include "hmac.h"
#include "layout2.h"
#include "memzero.h"
#include "protect.h"
#include "secbool.h"
#if !EMULATOR
#include "thd89.h"
#endif
#include "ble.h"
#include "flash.h"
#include "nist256p1.h"
#include "oled.h"
#include "rng.h"
#include "si2c.h"
#include "sys.h"
#include "trezor.h"
#include "usb.h"
#include "util.h"

#include "ctap.h"
#include "ctap_trans.h"
#include "memory.h"
#include "se_chip.h"
#include "u2f.h"
#include "u2f_hid.h"
#include "u2f_keys.h"
#include "u2f_knownapps.h"

// About 1/2 Second according to values used in protect.c
#define CTAP_HID_TIMEOUT (timer1s / 2)

// Initialise without a cid
static uint32_t cid = 0;

// The channel ID of the last successful U2F_AUTHENTICATE check-only request.
static uint32_t last_good_auth_check_cid = 0;

// Circular Output buffer
static uint32_t u2f_out_start = 0;

uint32_t u2f_out_end = 0;
uint8_t u2f_out_packets[U2F_OUT_PKT_BUFFER_LEN][HID_RPT_SIZE];

#define U2F_PUBKEY_LEN 65
#define KEY_PATH_LEN 32
#define KEY_HANDLE_LEN (KEY_PATH_LEN + SHA256_DIGEST_LENGTH)

// Derivation path is m/U2F'/r'/r'/r'/r'/r'/r'/r'/r'
#define KEY_PATH_ENTRIES (KEY_PATH_LEN / sizeof(uint32_t))

// Defined as UsbSignHandler.BOGUS_APP_ID_HASH
// in
// https://github.com/google/u2f-ref-code/blob/master/u2f-chrome-extension/usbsignhandler.js#L118
#define BOGUS_APPID_CHROME "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define BOGUS_APPID_FIREFOX \
  "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

// Auth/Register request state machine
typedef enum {
  INIT = 0,
  AUTH = 10,
  AUTH_PASS = 11,
  REG = 20,
  REG_PASS = 21,
  REQUEST_PIN = 30
} U2F_STATE;

bool u2f_init_command = false;
static bool next_page = false;
static bool se_seed_cached = false;
static volatile bool usb_hid_tiny = false;
extern bool protectAbortedByFIDO;

typedef enum {
  TRANSPORT_NULL = 0,
  TRANSPORT_HID = 1,
  TRANSPORT_BLE = 2,
} TRANSPORT_TYPE;
static uint8_t transport_type = 0;
static uint8_t poll_nest = 0;

typedef struct {
  uint8_t reserved;
  uint8_t appId[U2F_APPID_SIZE];
  uint8_t chal[U2F_CHAL_SIZE];
  uint8_t keyHandle[KEY_HANDLE_LEN];
  uint8_t pubKey[U2F_PUBKEY_LEN];
} U2F_REGISTER_SIG_STR;

typedef struct {
  uint8_t appId[U2F_APPID_SIZE];
  uint8_t flags;
  uint8_t ctr[4];
  uint8_t chal[U2F_CHAL_SIZE];
} U2F_AUTHENTICATE_SIG_STR;

typedef struct {
  uint32_t dialog_timer_start;
  bool is_busy;
  U2F_STATE last_req_state;
} DIALOG_MANAGER;

static DIALOG_MANAGER dialog_manager = {
    .dialog_timer_start = 0, .is_busy = false, .last_req_state = INIT};

uint32_t next_cid(void) {
  // extremely unlikely but hey
  do {
    cid = random32();
  } while (cid == 0 || cid == CID_BROADCAST);
  return cid;
}

// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html#message--and-packet-structure
// states the following:
// With a packet size of 64 bytes (max for full-speed devices), this means that
// the maximum message payload length is 64 - 7 + 128 * (64 - 5) = 7609 bytes.
#define U2F_MAXIMUM_PAYLOAD_LENGTH 7609
typedef struct {
  uint8_t buf[U2F_MAXIMUM_PAYLOAD_LENGTH];
  uint8_t *buf_ptr;
  uint32_t len;
  uint8_t seq;
  uint8_t cmd;
} U2F_ReadBuffer;

U2F_ReadBuffer *reader;

bool dialog_is_busy(void) {
  // if (dialog_manager.is_busy) {
  //   if (timer_ms() - dialog_manager.dialog_timer_start >
  //   CTAP_HID_TIMEOUT) {
  //     dialog_update_state(false, 0);
  //     dialog_manager.is_busy = false;
  //     return false;
  //   }
  //   return true;
  // }
  return dialog_manager.is_busy;
}
uint32_t dialog_get_timer_start(void) {
  return dialog_manager.dialog_timer_start;
}

void dialog_update_state(bool busy, uint32_t timer_start) {
  dialog_manager.is_busy = busy;
  dialog_manager.dialog_timer_start = timer_start;
}

void u2fhid_read(char tiny, const U2FHID_FRAME *f) {
  (void)tiny;
  // Always handle init packets directly
  if (f->init.cmd == U2FHID_INIT) {
    u2f_init_command = true;
    u2fhid_init(f);
    if (usb_hid_tiny && reader && f->cid == cid) {
      // abort current channel
      reader->cmd = 0;
      reader->len = 0;
      reader->seq = 255;
    }
    return;
  }

  if (usb_hid_tiny || dialog_is_busy()) {
    // read continue packet
    if (reader == 0 || cid != f->cid) {
      send_u2fhid_error(f->cid, ERR_CHANNEL_BUSY);
      return;
    }

    if ((f->type & TYPE_INIT) && reader->seq == 255) {
      u2fhid_init_cmd(f);
      return;
    }

    if (reader->seq != f->cont.seq) {
      send_u2fhid_error(f->cid, ERR_INVALID_SEQ);
      reader->cmd = 0;
      reader->len = 0;
      reader->seq = 255;
      return;
    }

    // check out of bounds
    if ((reader->buf_ptr - reader->buf) >= (signed)reader->len ||
        (reader->buf_ptr + sizeof(f->cont.data) - reader->buf) >
            (signed)sizeof(reader->buf))
      return;
    reader->seq++;
    memcpy(reader->buf_ptr, f->cont.data, sizeof(f->cont.data));
    reader->buf_ptr += sizeof(f->cont.data);
    return;
  }

  u2fhid_read_start(f);
}

void u2fhid_init_cmd(const U2FHID_FRAME *f) {
  reader->seq = 0;
  reader->buf_ptr = reader->buf;
  reader->len = MSG_LEN(*f);
  reader->cmd = f->type;
  memcpy(reader->buf_ptr, f->init.data, sizeof(f->init.data));
  reader->buf_ptr += sizeof(f->init.data);
  cid = f->cid;
}

void u2fhid_read_start(const U2FHID_FRAME *f) {
  U2F_ReadBuffer readbuffer = {0};
  memzero(&readbuffer, sizeof(readbuffer));
  if (!(f->type & TYPE_INIT)) {
    return;
  }

  // Broadcast is reserved for init
  if (f->cid == CID_BROADCAST || f->cid == 0) {
    send_u2fhid_error(f->cid, ERR_INVALID_CID);
    return;
  }

  if ((unsigned)MSG_LEN(*f) > sizeof(reader->buf)) {
    send_u2fhid_error(f->cid, ERR_INVALID_LEN);
    return;
  }

  reader = &readbuffer;
  u2fhid_init_cmd(f);

  for (;;) {
    usb_hid_tiny = true;
    // Do we need to wait for more data
    while ((reader->buf_ptr - reader->buf) < (signed)reader->len) {
      uint8_t lastseq = reader->seq;
      uint8_t lastcmd = reader->cmd;
      uint32_t timer_start = timer_ms();
      while (reader->seq == lastseq && reader->cmd == lastcmd) {
        if (timer_ms() - timer_start > CTAP_HID_TIMEOUT) {
          // timeout
          send_u2fhid_error(cid, ERR_MSG_TIMEOUT);
          cid = 0;
          reader = 0;
          usb_hid_tiny = false;
          layoutHome();
          return;
        }
        usbPoll();
      }
    }

    if (transport_type == TRANSPORT_BLE) {
      send_u2fhid_error(cid, ERR_CHANNEL_BUSY);
      return;
    }
    transport_type = TRANSPORT_HID;
    poll_nest++;
    usb_hid_tiny = false;

    ctap_printf("ctap usb cmd\n");

    protectAbortedByFIDO = true;

    // We have all the data
    switch (reader->cmd) {
      case 0:
        // message was aborted by init
        break;
      case U2FHID_PING:
        u2fhid_ping(reader->buf, reader->len);
        break;
      case U2FHID_MSG:
        if (reader->len == 5) {
          // lc2 lc3 = 0
          reader->buf[5] = reader->buf[6] = 0;
        }
        u2fhid_msg((APDU *)reader->buf, reader->len);
        break;
      case U2FHID_WINK:
        u2fhid_wink(reader->buf, reader->len);
        break;
      case U2FHID_CBOR:
        ctap_cbor_cmd(reader->buf, reader->len);
        break;
      default:
        send_u2fhid_error(cid, ERR_INVALID_CMD);
        break;
    }

    poll_nest--;
    if (poll_nest == 0) {
      transport_type = TRANSPORT_NULL;
    }

    // wait for next command/button press
    reader->cmd = 0;
    reader->seq = 255;
    while (dialog_is_busy() && reader->cmd == 0) {
      if (timer_ms() - dialog_manager.dialog_timer_start > CTAP_HID_TIMEOUT) {
        break;
      }
      usbPoll();  // may trigger new request
      buttonUpdate();
      if (button.YesUp && (dialog_manager.last_req_state == AUTH ||
                           dialog_manager.last_req_state == REG)) {
        if (next_page == true) {
          // standard requires to remember button press for 10 seconds.
          if (dialog_manager.last_req_state == REG) {
            layoutDialogCenterAdapterV2(
                _(T__U2F_REGISTER), NULL, NULL, &bmp_bottom_right_confirm, NULL,
                NULL, NULL, NULL, NULL, NULL, _(T__U2F_AUTHENTICATE));
          } else {
            layoutDialogCenterAdapterV2(
                _(T__U2F_AUTHENTICATE), NULL, NULL, &bmp_bottom_right_confirm,
                NULL, NULL, NULL, NULL, NULL, NULL,
                _(C__AUTHENTICATE_U2F_SECURITY_KEY_QUES));
          }
          // delay_ms(100);
          next_page = false;
        } else {
          layoutHome();
          dialog_manager.last_req_state++;
        }
      }
      if (reader == 0) {
        layoutHome();
        return;
      }
    }

    dialog_update_state(false, 0);

    if (dialog_manager.last_req_state == REQUEST_PIN) {
      return;
    }

    if (reader->cmd == 0) {
      dialog_manager.last_req_state = INIT;
      next_page = false;
      cid = 0;
      reader = 0;
      layoutHome();
      return;
    }
  }
}

void u2fhid_ping(const uint8_t *buf, uint32_t len) {
  debugLog(0, "", "u2fhid_ping");
  send_u2fhid_msg(U2FHID_PING, buf, len);
}

void u2fhid_wink(const uint8_t *buf, uint32_t len) {
  debugLog(0, "", "u2fhid_wink");
  (void)buf;

  if (len > 0) return send_u2fhid_error(cid, ERR_INVALID_LEN);

  if (dialog_is_busy()) {
    dialog_update_state(true, timer_ms());
  }

  U2FHID_FRAME f = {0};
  memzero(&f, sizeof(f));
  f.cid = cid;
  f.init.cmd = U2FHID_WINK;
  f.init.bcntl = 0;
  queue_u2f_pkt(&f);
}

void u2fhid_init(const U2FHID_FRAME *in) {
  const U2FHID_INIT_REQ *init_req = (const U2FHID_INIT_REQ *)&in->init.data;
  U2FHID_FRAME f = {0};
  U2FHID_INIT_RESP resp = {0};
  memzero(&resp, sizeof(resp));

  debugLog(0, "", "u2fhid_init");

  if (in->cid == 0) {
    send_u2fhid_error(in->cid, ERR_INVALID_CID);
    return;
  }

  memzero(&f, sizeof(f));
  f.cid = in->cid;
  f.init.cmd = U2FHID_INIT;
  f.init.bcnth = 0;
  f.init.bcntl = sizeof(resp);

  memcpy(resp.nonce, init_req->nonce, sizeof(init_req->nonce));
  resp.cid = in->cid == CID_BROADCAST ? next_cid() : in->cid;
  resp.versionInterface = U2FHID_IF_VERSION;
  resp.versionMajor = VERSION_MAJOR;
  resp.versionMinor = VERSION_MINOR;
  resp.versionBuild = VERSION_PATCH;
  resp.capFlags = CAPFLAG_WINK;
  memcpy(&f.init.data, &resp, sizeof(resp));

  queue_u2f_pkt(&f);
}

void queue_u2f_pkt(const U2FHID_FRAME *u2f_pkt) {
  // debugLog(0, "", "u2f_write_pkt");
  uint32_t next = (u2f_out_end + 1) % U2F_OUT_PKT_BUFFER_LEN;
  if (u2f_out_start == next) {
    debugLog(0, "", "u2f_write_pkt full");
    return;  // Buffer full :(
  }
  memcpy(u2f_out_packets[u2f_out_end], u2f_pkt, HID_RPT_SIZE);
  u2f_out_end = next;
}

uint8_t *u2f_out_data(void) {
  if (u2f_out_start == u2f_out_end) return NULL;  // No data
  // debugLog(0, "", "u2f_out_data");
  uint32_t t = u2f_out_start;
  u2f_out_start = (u2f_out_start + 1) % U2F_OUT_PKT_BUFFER_LEN;
  return u2f_out_packets[t];
}

void layoutKeyCheckInfo(void) {
  oledClear_ex();
  oledDrawStringCenter(60, 32, "Press any key... ", FONT_STANDARD);
  oledRefresh();
}

void vButton_Lcd_Test(void) {
  uint8_t ucStatus;
  uint32_t uiTimeout;

  oledClear_ex();
  oledRefresh();
  layoutKeyCheckInfo();
  ucStatus = 0;
  uiTimeout = 0;
  while (1) {
    buttonUpdate();
    if (button.YesUp) {
      oledClear_ex();
      oledDrawStringCenter(60, 32, "Ok Button is OK ", FONT_STANDARD);
      oledRefresh();
      if (0x00 == (ucStatus & 0x01)) {
        ucStatus |= 0x01;
      }
    }
    if (button.NoUp) {
      oledClear_ex();
      oledDrawStringCenter(60, 32, "Cancel Button is OK ", FONT_STANDARD);
      oledRefresh();
      if (0x00 == (ucStatus & 0x02)) {
        ucStatus |= 0x02;
      }
    }
    if (button.DownUp) {
      oledClear_ex();
      oledDrawStringCenter(60, 32, "Down Button is OK ", FONT_STANDARD);
      oledRefresh();
      if (0x00 == (ucStatus & 0x04)) {
        ucStatus |= 0x04;
      }
    }
    if (button.UpUp) {
      oledClear_ex();
      oledDrawStringCenter(60, 32, "UP Button is OK ", FONT_STANDARD);
      oledRefresh();
      if (0x00 == (ucStatus & 0x08)) {
        ucStatus |= 0x08;
      }
    }
    if (ucStatus >= 0x0F) {
      send_u2f_error(U2F_SW_NO_ERROR);
      break;
    }
    uiTimeout++;
    if (uiTimeout > 10000000) {
      send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
      break;
    }
  }
}

void st_version(void) {
  uint8_t ucBuf[4];

  ucBuf[0] = ONEKEY_VERSION_HEX >> 8 & 0xFF;
  ucBuf[1] = ONEKEY_VERSION_HEX & 0xFF;
  ucBuf[2] = U2F_SW_NO_ERROR >> 8 & 0xFF;
  ucBuf[3] = U2F_SW_NO_ERROR & 0xFF;
  send_u2f_msg(ucBuf, 4);
}

void gd32_protect(void) {
  // memory protect later
  // memory_protect();
  send_u2f_error(U2F_SW_NO_ERROR);
}

void gd32_checkEleConnection(void) {
  if (!se_isFactoryMode()) {  // se need at factory stage
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    return;
  }
  vButton_Lcd_Test();
}

void get_device_state(void) {
  uint8_t resp[4];
  resp[0] = memory_protect_state() == 0xCC ? 1 : 0;
  resp[1] = se_isFactoryMode() ? 0 : 1;
  resp[2] = U2F_SW_NO_ERROR >> 8 & 0xFF;
  resp[3] = U2F_SW_NO_ERROR & 0xFF;
  send_u2f_msg(resp, 4);
}

void u2fhid_msg(const APDU *a, uint32_t len) {
  if (a->cla != 0 && a->cla != 0x80) {
    send_u2f_error(U2F_SW_CLA_NOT_SUPPORTED);
    return;
  }

#if !EMULATOR
  uint8_t buffer[1024 + 64];
  uint16_t resp_len = sizeof(buffer);
#endif

  switch (a->ins) {
    case U2F_REGISTER:
      u2f_register(a);
      break;
    case U2F_AUTHENTICATE:
      u2f_authenticate(a);
      break;
    case U2F_VERSION:
      u2f_version(a);
      break;
    case GET_ST_VERSION:
      st_version();
      break;
    case Buttton_Lcd_Test:
      vButton_Lcd_Test();
      break;
    case MEMORY_LOCK:  // it would disable swd and boot from system bootloader
                       // and sram
      gd32_protect();
      break;
    case CHECK_ELECONNECT:  // smt factory check device connection
      gd32_checkEleConnection();
      break;
    case DEVICE_STATE:
      get_device_state();
      break;
    default:
#if !EMULATOR

      if (!thd89_transmit((uint8_t *)&(a->cla), len, buffer, &resp_len)) {
        send_u2f_error(thd89_last_error());
      } else {
        buffer[resp_len] = U2F_SW_NO_ERROR >> 8 & 0xFF;
        buffer[resp_len + 1] = U2F_SW_NO_ERROR & 0xFF;
        send_u2f_msg(buffer, resp_len + 2);
      }
#endif
      break;
  }
}

void send_u2fhid_msg(const uint8_t cmd, const uint8_t *data,
                     const uint32_t len) {
  if (len > U2F_MAXIMUM_PAYLOAD_LENGTH) {
    debugLog(0, "", "send_u2fhid_msg failed");
    return;
  }

  U2FHID_FRAME f = {0};
  uint8_t *p = (uint8_t *)data;
  uint32_t l = len;
  uint32_t psz = 0;
  uint8_t seq = 0;

  // debugLog(0, "", "send_u2fhid_msg");

  memzero(&f, sizeof(f));
  f.cid = cid;
  f.init.cmd = cmd;
  f.init.bcnth = len >> 8;
  f.init.bcntl = len & 0xff;

  // Init packet
  psz = MIN(sizeof(f.init.data), l);
  memcpy(f.init.data, p, psz);
  queue_u2f_pkt(&f);
  l -= psz;
  p += psz;

  // Cont packet(s)
  for (; l > 0; l -= psz, p += psz) {
    // debugLog(0, "", "send_u2fhid_msg con");
    memzero(&f.cont.data, sizeof(f.cont.data));
    f.cont.seq = seq++;
    psz = MIN(sizeof(f.cont.data), l);
    memcpy(f.cont.data, p, psz);
    queue_u2f_pkt(&f);
  }

  if (data + len != p) {
    debugLog(0, "", "send_u2fhid_msg is bad");
    debugInt(data + len - p);
  }
  usb_u2f_data_send();
}

void send_u2fhid_error(uint32_t fcid, uint8_t err) {
  U2FHID_FRAME f = {0};

  memzero(&f, sizeof(f));
  f.cid = fcid;
  f.init.cmd = U2FHID_ERROR;
  f.init.bcntl = 1;
  f.init.data[0] = err;
  queue_u2f_pkt(&f);
}

void u2f_version(const APDU *a) {
  if (APDU_LEN(*a) != 0) {
    debugLog(0, "", "u2f version - badlen");
    send_u2f_error(U2F_SW_WRONG_LENGTH);
    return;
  }

  // INCLUDES SW_NO_ERROR
  static const uint8_t version_response[] = {'U', '2', 'F',  '_',
                                             'V', '2', 0x90, 0x00};
  debugLog(0, "", "u2f version");
  send_u2f_msg(version_response, sizeof(version_response));
}

void getReadableAppId(const uint8_t appid[U2F_APPID_SIZE],
                      const char **appname) {
  static char buf[8 + 2 + 8 + 1];

  for (unsigned int i = 0; i < sizeof(u2f_well_known) / sizeof(U2FWellKnown);
       i++) {
    if (memcmp(appid, u2f_well_known[i].appid, U2F_APPID_SIZE) == 0) {
      *appname = u2f_well_known[i].appname;
      return;
    }
  }

  data2hex(appid, 4, &buf[0]);
  buf[8] = buf[9] = '.';
  data2hex(appid + (U2F_APPID_SIZE - 4), 4, &buf[10]);
  *appname = buf;
}
#if EMULATOR
static const HDNode *getDerivedNode(uint32_t *address_n,
                                    size_t address_n_count) {
  static CONFIDENTIAL HDNode node;
  if (!config_getU2FRoot(&node)) {
    layoutHome();
    debugLog(0, "", "ERR: Device not init");
    return 0;
  }

  if (!address_n || address_n_count == 0) {
    return &node;
  }
  for (size_t i = 0; i < address_n_count; i++) {
    if (hdnode_private_ckd(&node, address_n[i]) == 0) {
      layoutHome();
      debugLog(0, "", "ERR: Derive private failed");
      return 0;
    }
  }

  return &node;
}

static const HDNode *generateKeyHandle(const uint8_t app_id[],
                                       uint8_t key_handle[]) {
  uint8_t keybase[U2F_APPID_SIZE + KEY_PATH_LEN] = {0};
  uint8_t path_len = KEY_PATH_ENTRIES;

  // Derivation path is m/U2F'/r'/r'/r'/r'/r'/r'/r'/r'
  uint32_t key_path[KEY_PATH_ENTRIES + 1] = {0};

  for (uint32_t i = 0; i < KEY_PATH_ENTRIES; i++) {
    // high bit for hardened keys
    key_path[i] = PATH_HARDENED | random32();
  }
  // First half of keyhandle is key_path
  memcpy(key_handle, key_path, KEY_PATH_LEN);

  // prepare keypair from /random data
  const HDNode *node = getDerivedNode(key_path, path_len);
  if (!node) return NULL;

  // For second half of keyhandle
  // Signature of app_id and random data
  memcpy(&keybase[0], app_id, U2F_APPID_SIZE);
  memcpy(&keybase[U2F_APPID_SIZE], key_handle, KEY_PATH_LEN);
  hmac_sha256(node->private_key, sizeof(node->private_key), keybase,
              sizeof(keybase), &key_handle[KEY_PATH_LEN]);
  // Done!
  return node;
}

static const HDNode *validateKeyHandle(const uint8_t app_id[],
                                       const uint8_t key_handle[]) {
  uint32_t key_path[KEY_PATH_ENTRIES + 1] = {0};
  uint8_t path_len = KEY_PATH_ENTRIES;
  memcpy(key_path, key_handle, KEY_PATH_LEN);
  for (unsigned int i = 0; i < KEY_PATH_ENTRIES; i++) {
    // check high bit for hardened keys
    if (!(key_path[i] & PATH_HARDENED)) {
      return NULL;
    }
  }

  const HDNode *node = getDerivedNode(key_path, path_len);
  if (!node) return NULL;

  uint8_t keybase[U2F_APPID_SIZE + KEY_PATH_LEN] = {0};
  memcpy(&keybase[0], app_id, U2F_APPID_SIZE);
  memcpy(&keybase[U2F_APPID_SIZE], key_handle, KEY_PATH_LEN);

  uint8_t hmac[SHA256_DIGEST_LENGTH] = {0};
  hmac_sha256(node->private_key, sizeof(node->private_key), keybase,
              sizeof(keybase), hmac);

  if (memcmp(&key_handle[KEY_PATH_LEN], hmac, SHA256_DIGEST_LENGTH) != 0)
    return NULL;

  // Done!
  return node;
}
#endif

void u2f_register(const APDU *a) {
  static U2F_REGISTER_REQ last_req;
  const U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)a->data;
  uint8_t percent = 0;

  if (!config_isInitialized()) {
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    return;
  }

  if (!session_isUnlocked()) {
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    if (dialog_manager.last_req_state == REQUEST_PIN) {
      return;
    }
    dialog_manager.last_req_state = REQUEST_PIN;
    protectPinOnDevice(true, true);
    layoutHome();
    return;
  }

  if (!se_seed_cached) {
    UI_WAIT_CALLBACK ui_callback = se_get_ui_callback();
    secbool ret = se_gen_root_node(&percent);
    if (ret) {
      if (percent == 100) {
        se_seed_cached = true;
        return;
      } else if (ui_callback) {
        ui_callback(_(C__PROCESSING_ETC), percent * 10);
        send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
        return;
      }
    } else {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }
  }

  // If this request is different from last request, reset state machine
  if (memcmp(&last_req, req, sizeof(last_req)) != 0) {
    memcpy(&last_req, req, sizeof(last_req));
    dialog_manager.last_req_state = INIT;
  }

  // Validate basic request parameters
  debugLog(0, "", "u2f register");
  if (APDU_LEN(*a) != sizeof(U2F_REGISTER_REQ)) {
    debugLog(0, "", "u2f register - badlen");
    send_u2f_error(U2F_SW_WRONG_LENGTH);
    return;
  }

  // First Time request, return not present and display request dialog
  if (dialog_manager.last_req_state == INIT) {
    // error: testof-user-presence is required
    buttonUpdate();  // Clear button state
    if (0 == memcmp(req->appId, BOGUS_APPID_CHROME, U2F_APPID_SIZE) ||
        0 == memcmp(req->appId, BOGUS_APPID_FIREFOX, U2F_APPID_SIZE)) {
      if (cid == last_good_auth_check_cid) {
        layoutDialogCenterAdapterV2(
            _(T__U2F_ALREADY_REGISTER), NULL, NULL, &bmp_bottom_right_confirm,
            NULL, NULL, NULL, NULL, NULL, NULL,
            _(C__THIS_U2F_DEVICE_IS_ALREADY_REGISTERED_IN_THIS_APP));
      } else {
        layoutDialogCenterAdapterV2(
            _(T__U2F_NOT_REGISTER), NULL, NULL, &bmp_bottom_right_confirm, NULL,
            NULL, NULL, NULL, NULL, NULL,
            _(C__THIS_U2F_DEVICE_IS_NOT_REGISTERED_IN_THIS_APP));
      }
    } else {
      const char *appname = NULL;
      getReadableAppId(req->appId, &appname);
      layoutDialogAdapterEx(_(T__U2F_REGISTER), NULL, NULL,
                            &bmp_bottom_right_arrow, NULL, NULL,
                            _(I__APP_NAME_COLON), appname, NULL, NULL);
      next_page = true;
    }
    dialog_manager.last_req_state = REG;
  }

  // Still awaiting Keypress
  if (dialog_manager.last_req_state == REG) {
    // error: testof-user-presence is required
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    dialog_update_state(true, timer_ms());
    return;
  }

  // Buttons said yes
  if (dialog_manager.last_req_state == REG_PASS) {
    uint8_t data[sizeof(U2F_REGISTER_RESP) + 2] = {0};
    U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)&data;
    memzero(data, sizeof(data));

    resp->registerId = U2F_REGISTER_ID;
    resp->keyHandleLen = KEY_HANDLE_LEN;

#if EMULATOR
    // Generate keypair for this appId
    const HDNode *node =
        generateKeyHandle(req->appId, (uint8_t *)&resp->keyHandleCertSig);

    if (!node) {
      debugLog(0, "", "getDerivedNode Fail");
      send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
      return;
    }

    if (ecdsa_get_public_key65(node->curve->params, node->private_key,
                               (uint8_t *)&resp->pubKey) != 0) {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }
#endif

    memcpy(resp->keyHandleCertSig + resp->keyHandleLen, U2F_ATT_CERT,
           sizeof(U2F_ATT_CERT));

    uint8_t sig[64] = {0};
#if EMULATOR
    U2F_REGISTER_SIG_STR sig_base = {0};
    sig_base.reserved = 0;
    memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
    memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);
    memcpy(sig_base.keyHandle, &resp->keyHandleCertSig, KEY_HANDLE_LEN);
    memcpy(sig_base.pubKey, &resp->pubKey, U2F_PUBKEY_LEN);
    if (ecdsa_sign(&nist256p1, HASHER_SHA2, U2F_ATT_PRIV_KEY,
                   (uint8_t *)&sig_base, sizeof(sig_base), sig, NULL,
                   NULL) != 0) {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }
#else
    if (!se_u2f_register(req->appId, req->chal, resp->keyHandleCertSig,
                         (uint8_t *)&resp->pubKey, sig)) {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }
#endif
    // Where to write the signature in the response
    uint8_t *resp_sig =
        resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT);
    // Convert to der for the response
    const uint8_t sig_len = ecdsa_sig_to_der(sig, resp_sig);

    // Append success bytes
    memcpy(resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT) +
               sig_len,
           "\x90\x00", 2);

    int l = 1 /* registerId */ + U2F_PUBKEY_LEN + 1 /* keyhandleLen */ +
            resp->keyHandleLen + sizeof(U2F_ATT_CERT) + sig_len + 2;

    dialog_manager.last_req_state = INIT;
    dialog_update_state(false, 0);
    send_u2f_msg(data, l);
    return;
  }

  // Didn't expect to get here
  dialog_update_state(false, 0);
}

void u2f_authenticate(const APDU *a) {
  const U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)a->data;
  static U2F_AUTHENTICATE_REQ last_req;
  uint8_t percent = 0;

  if (!config_isInitialized()) {
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    return;
  }

  if (APDU_LEN(*a) < 64) {  /// FIXME: decent value
    debugLog(0, "", "u2f authenticate - badlen");
    send_u2f_error(U2F_SW_WRONG_LENGTH);
    return;
  }

  if (req->keyHandleLen != KEY_HANDLE_LEN) {
    debugLog(0, "", "u2f auth - bad keyhandle len");
    send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
    return;
  }

  if (!session_isUnlocked()) {
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    if (dialog_manager.last_req_state == REQUEST_PIN) {
      return;
    }
    dialog_manager.last_req_state = REQUEST_PIN;
    protectPinOnDevice(true, true);
    dialog_manager.last_req_state = INIT;
    layoutHome();
    return;
  }

  if (!se_seed_cached) {
    UI_WAIT_CALLBACK ui_callback = se_get_ui_callback();
    secbool ret = se_gen_root_node(&percent);
    if (ret) {
      if (percent == 100) {
        se_seed_cached = true;
        return;
      } else if (ui_callback) {
        ui_callback(_(C__PROCESSING_ETC), percent * 10);
        send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
        return;
      }
    } else {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }
  }

#if EMULATOR
  const HDNode *node = validateKeyHandle(req->appId, req->keyHandle);

  if (!node) {
    debugLog(0, "", "u2f auth - bad keyhandle len");
    send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
    return;
  }
#else
  if (!se_u2f_validate_handle(req->appId, req->keyHandle)) {
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }
#endif

  if (a->p1 == U2F_AUTH_CHECK_ONLY) {
    debugLog(0, "", "u2f authenticate check");
    // This is a success for a good keyhandle
    // A failed check would have happened earlier
    // error: testof-user-presence is required
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    last_good_auth_check_cid = cid;
    return;
  }

  if (a->p1 != U2F_AUTH_ENFORCE && a->p1 != U2F_NOT_AUTH_ENFORCE) {
    debugLog(0, "", "u2f authenticate unknown");
    // error:bad key handle
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }

  debugLog(0, "", "u2f authenticate enforce");

  if (memcmp(&last_req, req, sizeof(last_req)) != 0) {
    memcpy(&last_req, req, sizeof(last_req));
    dialog_manager.last_req_state = INIT;
  }

  if (dialog_manager.last_req_state == INIT) {
    // error: testof-user-presence is required
    buttonUpdate();  // Clear button state
    const char *appname = NULL;
    getReadableAppId(req->appId, &appname);
    layoutDialogAdapterEx(_(T__U2F_AUTHENTICATE), NULL, NULL,
                          &bmp_bottom_right_arrow, NULL, NULL,
                          _(I__APP_NAME_COLON), appname, NULL, NULL);
    next_page = true;
    dialog_manager.last_req_state = AUTH;
  }

  // Awaiting Keypress
  if (dialog_manager.last_req_state == AUTH) {
    // error: testof-user-presence is required
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    dialog_update_state(true, timer_ms());
    return;
  }

  // Buttons said yes
  if (dialog_manager.last_req_state == AUTH_PASS) {
    uint8_t buf[(sizeof(U2F_AUTHENTICATE_RESP)) + 2] = {0};
    U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)&buf;

    uint8_t sig[64] = {0};
    resp->flags = a->p1 == U2F_AUTH_ENFORCE ? U2F_AUTH_FLAG_TUP : 0;
#if EMULATOR
    const uint32_t ctr = config_nextU2FCounter();
    resp->ctr[0] = ctr >> 24 & 0xff;
    resp->ctr[1] = ctr >> 16 & 0xff;
    resp->ctr[2] = ctr >> 8 & 0xff;
    resp->ctr[3] = ctr & 0xff;

    // Build and sign response
    U2F_AUTHENTICATE_SIG_STR sig_base = {0};

    memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
    sig_base.flags = resp->flags;
    memcpy(sig_base.ctr, resp->ctr, 4);
    memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);
    if (ecdsa_sign(&nist256p1, HASHER_SHA2, node->private_key,
                   (uint8_t *)&sig_base, sizeof(sig_base), sig, NULL,
                   NULL) != 0) {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }
#else
    if (!se_u2f_authenticate(req->appId, req->keyHandle, req->chal, resp->ctr,
                             sig)) {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }

#endif
    // Copy DER encoded signature into response
    const uint8_t sig_len = ecdsa_sig_to_der(sig, resp->sig);

    // Append OK
    memcpy(buf + sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len,
           "\x90\x00", 2);
    dialog_manager.last_req_state = INIT;
    dialog_update_state(false, 0);
    send_u2f_msg(
        buf, sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len + 2);
  }
}

void send_u2f_error(const uint16_t err) {
  uint8_t data[2] = {0};
  data[0] = err >> 8 & 0xFF;
  data[1] = err & 0xFF;
  if (transport_type == TRANSPORT_BLE) {
    if (err == U2F_SW_CONDITIONS_NOT_SATISFIED) {
      return;
    }
    ctap_ble_u2f_send(U2FHID_MSG, data, 2);
  } else {
    send_u2f_msg(data, 2);
  }
}

void send_u2f_msg(const uint8_t *data, const uint32_t len) {
  if (transport_type == TRANSPORT_BLE) {
    ctap_ble_u2f_send(U2FHID_MSG, (uint8_t *)data, len);
  } else {
    send_u2fhid_msg(U2FHID_MSG, data, len);
  }
}

// FIDO2
#include "ctap.h"
#include "ctap_errors.h"
#include "usart.h"

void send_cbor_error(const uint8_t err) {
  send_u2fhid_msg(U2FHID_CBOR, (uint8_t *)&err, 1);
}

void ctap_hid_keepalive_status(void) {
  uint8_t status = CTAPHID_STATUS_UPNEEDED;
  if (transport_type == TRANSPORT_BLE) {
    ctap_ble_u2f_send(U2FHID_KEEPALIVE, &status, 1);
  } else {
    send_u2fhid_msg(CTAPHID_KEEPALIVE, &status, 1);
  }
}

void ctap_hid_keepalive_process(void) {
  uint8_t status = CTAPHID_STATUS_PROCESSING;
  if (transport_type == TRANSPORT_BLE) {
    ctap_ble_u2f_send(U2FHID_KEEPALIVE, &status, 1);
  } else {
    send_u2fhid_msg(CTAPHID_KEEPALIVE, &status, 1);
  }
}

void ctap_hid_keepalive_register(void) {
  if (transport_type == TRANSPORT_BLE) {
    register_loop_callback(ctap_hid_keepalive_status, timer_ms(), timer1s / 12);
  } else {
    register_timer("ctap_keepalive", timer1s / 12, ctap_hid_keepalive_status);
  }
}

void ctap_hid_keepalive_unregister(void) {
  if (transport_type == TRANSPORT_BLE) {
    unregister_loop_callback();
  } else {
    unregister_timer("ctap_keepalive");
  }
}

uint8_t ctap_check_device_status(void) {
  uint8_t status = CTAP1_ERR_SUCCESS;
  if (!config_isInitialized()) {
    return CTAP1_ERR_OTHER;
  }
  if (!session_isUnlocked()) {
    // Keepalive should be sent every 100ms
    ctap_hid_keepalive_register();

    if (protectPinOnDevice(true, true)) {
    } else {
      status = CTAP2_ERR_OPERATION_DENIED;
    }
    ctap_hid_keepalive_unregister();
  }

  if (status == CTAP1_ERR_SUCCESS) {
    if (check_se_fido_seed(ctap_hid_keepalive_status)) {
      status = CTAP1_ERR_SUCCESS;
    } else {
      status = CTAP2_ERR_OPERATION_DENIED;
    }
  }
  layoutHome();
  return status;
}

uint8_t ctap_cbor_cmd(const uint8_t *data, const uint32_t len) {
  char *se_version = se_get_version();
  if (len == 0) {
    ctap_error(ERR_INVALID_LEN);
    return 0;
  }

  if (compare_str_version(se_version, "1.1.5") < 0) {
    ctap_error(CTAP2_ERR_NOT_ALLOWED);
    return 0;
  }

  CTAP_RESPONSE resp;
  memset(&resp, 0, sizeof(resp));

  CborEncoder encoder;
  memset(&encoder, 0, sizeof(CborEncoder));

  uint8_t *ctap_status = resp.data;
  uint8_t *ctap_data = resp.data + 1;
  uint32_t ctap_data_len = sizeof(resp.data) - 1;

  cbor_encoder_init(&encoder, ctap_data, ctap_data_len, 0);

  uint8_t cmd = data[0];
  uint8_t status = CTAP1_ERR_SUCCESS;

  if (dialog_manager.is_busy) {
    ctap_error(CTAP1_ERR_CHANNEL_BUSY);
    return 0;
  }

  dialog_manager.is_busy = true;

  switch (cmd) {
    case CTAP_MAKE_CREDENTIAL:
    case CTAP_GET_ASSERTION:
      status = ctap_check_device_status();
      break;
    default:
      break;
  }

  if (status != CTAP1_ERR_SUCCESS) {
    dialog_manager.is_busy = false;
    send_cbor_error(status);
    return 0;
  }

  switch (cmd) {
    case CTAP_MAKE_CREDENTIAL:
      ctap_hid_keepalive_register();
      status = ctap_make_credential(&encoder, (uint8_t *)(data + 1), len - 1);
      ctap_hid_keepalive_unregister();
      ctap_hid_keepalive_process();
      if (status == CTAP1_ERR_SUCCESS) {
        *ctap_status = CTAP1_ERR_SUCCESS;
        resp.length = cbor_encoder_get_buffer_size(&encoder, ctap_data) + 1;
      } else {
        *ctap_status = status;
        resp.length = 1;
      }
      break;
    case CTAP_GET_ASSERTION:
      ctap_hid_keepalive_register();
      status = ctap_get_assertion(&encoder, (uint8_t *)(data + 1), len - 1);
      ctap_hid_keepalive_unregister();
      ctap_hid_keepalive_process();
      if (status == CTAP1_ERR_SUCCESS) {
        *ctap_status = CTAP1_ERR_SUCCESS;
        resp.length = cbor_encoder_get_buffer_size(&encoder, ctap_data) + 1;
      } else {
        *ctap_status = status;
        resp.length = 1;
      }
      break;
    case CTAP_GET_INFO:
      ctap_get_info(&encoder);
      *ctap_status = CTAP1_ERR_SUCCESS;
      resp.length = cbor_encoder_get_buffer_size(&encoder, ctap_data) + 1;
      break;
    case CTAP_CLIENT_PIN:
      status = ctap_client_pin(&encoder, (uint8_t *)(data + 1), len - 1);
      *ctap_status = status;
      resp.length = cbor_encoder_get_buffer_size(&encoder, ctap_data) + 1;
      break;
    case CTAP_RESET:
      *ctap_status = CTAP1_ERR_SUCCESS;
      resp.length = 1;
      break;
    case GET_NEXT_ASSERTION:
      *ctap_status = CTAP2_ERR_NOT_ALLOWED;
      resp.length = 1;
      break;
    default:
      *ctap_status = CTAP1_ERR_INVALID_COMMAND;
      resp.length = 1;
      break;
  }
  dialog_manager.is_busy = false;
  ctap_printf("ctap response:");
  dump_hex1(NULL, resp.data, resp.length);
  if (transport_type == TRANSPORT_BLE) {
    ctap_printf("ble send response\n");
    ctap_ble_u2f_send(U2FHID_MSG, resp.data, resp.length);
  } else {
    ctap_printf("hid send response\n");
    send_u2fhid_msg(U2FHID_CBOR, resp.data, resp.length);
  }
  return 0;
}

// ble transport
#define BLE_TRANSPORT_WAIT_TIME 10000  // 10 seconds

static uint8_t ble_fido_data[1024 * 3];
static uint16_t ble_fido_data_len = 0;
static uint8_t ble_fido_response[1024];
static uint8_t ble_cmd_nest = 0;
static uint8_t *ble_response_buffer = ble_fido_response;

void set_ble_fido_data(const uint8_t *data, const uint16_t len) {
  memcpy(ble_fido_data, data, len);
  ble_fido_data_len = len;
}

void set_ble_fido_data_len(const uint16_t len) { ble_fido_data_len = len; }

uint8_t *get_ble_fido_data_ptr(void) { return ble_fido_data; }

bool check_ble_timeout(void) {
  if (timer_ms() - dialog_manager.dialog_timer_start >
      BLE_TRANSPORT_WAIT_TIME) {
    layoutHome();
    return false;
  }
  layoutHome();
  return true;
}

bool ble_u2f_check_device_status(void) {
  static bool processing = false;
  uint8_t percent;
  if (processing) {
    return false;
  }

  if (!session_isUnlocked()) {
    processing = true;
    bool pin_ret = protectPinOnDevice(true, true);
    if (!pin_ret) {
      layoutHome();
      processing = false;
      return false;
    }
  }

  if (!se_seed_cached) {
    processing = true;
    UI_WAIT_CALLBACK ui_callback = se_get_ui_callback();
    while (1) {
      usbPoll();
      secbool ret = se_gen_root_node(&percent);
      if (ret) {
        if (percent == 100) {
          se_seed_cached = true;
          break;
        } else if (ui_callback) {
          ui_callback(_(C__PROCESSING_ETC), percent * 10);
        }
      } else {
        send_u2f_error(U2F_SW_WRONG_DATA);
        processing = false;
        return false;
      }
    }
  }
  processing = false;
  return true;
}

void u2f_register_ble(const APDU *a) {
  static U2F_REGISTER_REQ last_req;
  const U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)a->data;

  // If this request is different from last request, reset state machine
  if (memcmp(&last_req, req, sizeof(last_req)) != 0) {
    memcpy(&last_req, req, sizeof(last_req));
    dialog_manager.last_req_state = INIT;
  }

  // Validate basic request parameters
  debugLog(0, "", "u2f register");
  if (APDU_LEN(*a) != sizeof(U2F_REGISTER_REQ)) {
    debugLog(0, "", "u2f register - badlen");
    send_u2f_error(U2F_SW_WRONG_LENGTH);
    return;
  }

  if (dialog_manager.last_req_state == INIT) {
    const char *appname = NULL;
    getReadableAppId(last_req.appId, &appname);
    layoutDialogAdapterEx(_(T__U2F_REGISTER), NULL, NULL,
                          &bmp_bottom_right_arrow, NULL, NULL,
                          _(I__APP_NAME_COLON), appname, NULL, NULL);

    dialog_manager.last_req_state = REG;
  }

  if (dialog_manager.last_req_state == REG && ble_cmd_nest != 0) {
    return;
  }

  uint32_t timer_start = timer_ms();
  bool button_ret = false;

  ble_cmd_nest++;
  while (1) {
    usbPoll();
    buttonUpdate();
    if (button.YesUp) {
      button_ret = true;
      break;
    } else if (button.NoUp) {
      break;
    }
    if (timer_ms() - timer_start > USER_PRESENCE_TIMEOUT) {
      break;
    }
  }
  layoutHome();
  ble_cmd_nest--;
  if (!button_ret) {
    return;
  }

  // Buttons said yes
  uint8_t data[sizeof(U2F_REGISTER_RESP) + 2] = {0};
  U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)&data;
  memzero(data, sizeof(data));

  resp->registerId = U2F_REGISTER_ID;
  resp->keyHandleLen = KEY_HANDLE_LEN;

#if EMULATOR
  // Generate keypair for this appId
  const HDNode *node =
      generateKeyHandle(last_req.appId, (uint8_t *)&resp->keyHandleCertSig);

  if (!node) {
    debugLog(0, "", "getDerivedNode Fail");
    send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
    return;
  }

  if (ecdsa_get_public_key65(node->curve->params, node->private_key,
                             (uint8_t *)&resp->pubKey) != 0) {
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }
#endif

  memcpy(resp->keyHandleCertSig + resp->keyHandleLen, U2F_ATT_CERT,
         sizeof(U2F_ATT_CERT));

  uint8_t sig[64] = {0};
#if EMULATOR
  U2F_REGISTER_SIG_STR sig_base = {0};
  sig_base.reserved = 0;
  memcpy(sig_base.appId, last_req.appId, U2F_APPID_SIZE);
  memcpy(sig_base.chal, last_req.chal, U2F_CHAL_SIZE);
  memcpy(sig_base.keyHandle, &resp->keyHandleCertSig, KEY_HANDLE_LEN);
  memcpy(sig_base.pubKey, &resp->pubKey, U2F_PUBKEY_LEN);
  if (ecdsa_sign(&nist256p1, HASHER_SHA2, U2F_ATT_PRIV_KEY,
                 (uint8_t *)&sig_base, sizeof(sig_base), sig, NULL,
                 NULL) != 0) {
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }
#else
  if (!se_u2f_register(last_req.appId, last_req.chal, resp->keyHandleCertSig,
                       (uint8_t *)&resp->pubKey, sig)) {
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }
#endif
  // Where to write the signature in the response
  uint8_t *resp_sig =
      resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT);
  // Convert to der for the response
  const uint8_t sig_len = ecdsa_sig_to_der(sig, resp_sig);

  // Append success bytes
  memcpy(resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT) +
             sig_len,
         "\x90\x00", 2);

  int l = 1 /* registerId */ + U2F_PUBKEY_LEN + 1 /* keyhandleLen */ +
          resp->keyHandleLen + sizeof(U2F_ATT_CERT) + sig_len + 2;

  send_u2f_msg(data, l);
  return;
}

void u2f_authenticate_ble(const APDU *a) {
  const U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)a->data;
  static U2F_AUTHENTICATE_REQ last_req;
  if (APDU_LEN(*a) < 64) {  /// FIXME: decent value
    debugLog(0, "", "u2f authenticate - badlen");
    send_u2f_error(U2F_SW_WRONG_LENGTH);
    return;
  }

  if (req->keyHandleLen != KEY_HANDLE_LEN) {
    debugLog(0, "", "u2f auth - bad keyhandle len");
    send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
    return;
  }

#if EMULATOR
  const HDNode *node = validateKeyHandle(req->appId, req->keyHandle);

  if (!node) {
    debugLog(0, "", "u2f auth - bad keyhandle len");
    send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
    return;
  }
#else
  if (!se_u2f_validate_handle(req->appId, req->keyHandle)) {
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }
#endif

  if (a->p1 == U2F_AUTH_CHECK_ONLY) {
    debugLog(0, "", "u2f authenticate check");
    // This is a success for a good keyhandle
    // A failed check would have happened earlier
    // error: testof-user-presence is required
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    return;
  }

  if (a->p1 != U2F_AUTH_ENFORCE && a->p1 != U2F_NOT_AUTH_ENFORCE) {
    debugLog(0, "", "u2f authenticate unknown");
    // error:bad key handle
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }

  if (memcmp(&last_req, req, sizeof(last_req)) != 0) {
    memcpy(&last_req, req, sizeof(last_req));
    dialog_manager.last_req_state = INIT;
  }

  if (dialog_manager.last_req_state == INIT) {
    const char *appname = NULL;
    getReadableAppId(last_req.appId, &appname);
    layoutDialogAdapterEx(_(T__U2F_AUTHENTICATE), NULL, NULL,
                          &bmp_bottom_right_arrow, NULL, NULL,
                          _(I__APP_NAME_COLON), appname, NULL, NULL);
    dialog_manager.last_req_state = AUTH;
  }

  if (dialog_manager.last_req_state == AUTH && ble_cmd_nest != 0) {
    return;
  }

  ble_cmd_nest++;
  uint32_t timer_start = timer_ms();
  bool button_ret = false;
  while (1) {
    usbPoll();
    buttonUpdate();
    if (button.YesUp) {
      button_ret = true;
      break;
    } else if (button.NoUp) {
      break;
    }
    if (timer_ms() - timer_start > USER_PRESENCE_TIMEOUT) {
      break;
    }
  }
  layoutHome();
  ble_cmd_nest--;
  if (!button_ret) {
    return;
  }

  // Buttons said yes
  uint8_t buf[(sizeof(U2F_AUTHENTICATE_RESP)) + 2] = {0};
  U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)&buf;

  uint8_t sig[64] = {0};
  resp->flags = a->p1 == U2F_AUTH_ENFORCE ? U2F_AUTH_FLAG_TUP : 0;
#if EMULATOR
  const uint32_t ctr = config_nextU2FCounter();
  resp->ctr[0] = ctr >> 24 & 0xff;
  resp->ctr[1] = ctr >> 16 & 0xff;
  resp->ctr[2] = ctr >> 8 & 0xff;
  resp->ctr[3] = ctr & 0xff;

  // Build and sign response
  U2F_AUTHENTICATE_SIG_STR sig_base = {0};

  memcpy(sig_base.appId, last_req.appId, U2F_APPID_SIZE);
  sig_base.flags = resp->flags;
  memcpy(sig_base.ctr, resp->ctr, 4);
  memcpy(sig_base.chal, last_req.chal, U2F_CHAL_SIZE);
  if (ecdsa_sign(&nist256p1, HASHER_SHA2, node->private_key,
                 (uint8_t *)&sig_base, sizeof(sig_base), sig, NULL,
                 NULL) != 0) {
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }
#else
  if (!se_u2f_authenticate(last_req.appId, last_req.keyHandle, last_req.chal,
                           resp->ctr, sig)) {
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }

#endif
  // Copy DER encoded signature into response
  const uint8_t sig_len = ecdsa_sig_to_der(sig, resp->sig);

  // Append OK
  memcpy(buf + sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len,
         "\x90\x00", 2);
  send_u2f_msg(
      buf, sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len + 2);
}

void ctap_ble_u2f_send(uint8_t cmd, uint8_t *data, uint16_t len) {
  ble_response_buffer[0] = cmd;
  ble_response_buffer[1] = (len >> 8) & 0xff;
  ble_response_buffer[2] = len & 0xff;
  memcpy(ble_response_buffer + 3, data, len);
  ctap_printf("ctap_ble_u2f_send cmd: %d\n", cmd);
  dump_hex1(NULL, ble_response_buffer, len + 3);
  i2c_slave_send_fido(ble_response_buffer, len + 3);
}

void ctap_ble_ping(uint8_t *data, uint16_t len) {
  ctap_ble_u2f_send(U2FHID_PING, data, len);
}

void ctap_ble_error(uint8_t err) {
  uint8_t data = err;
  ctap_ble_u2f_send(U2FHID_ERROR, &data, 1);
}

void ctap_ble_u2f_error(uint16_t err) {
  uint8_t data[2] = {0};
  data[0] = err >> 8 & 0xff;
  data[1] = err & 0xff;
  ctap_ble_u2f_send(U2FHID_MSG, data, 2);
}

void ctap_error(uint8_t err) {
  if (transport_type == TRANSPORT_BLE) {
    ctap_ble_error(err);
  } else {
    send_u2fhid_error(cid, err);
  }
}

void ble_u2f_msg(const APDU *a) {
  if (a->cla != 0 && a->cla != 0x80) {
    send_u2f_error(U2F_SW_CLA_NOT_SUPPORTED);
    return;
  }

  switch (a->ins) {
    case U2F_REGISTER:
    case U2F_AUTHENTICATE:
      if (!ble_u2f_check_device_status()) {
        return;
      }
      break;
  }
  switch (a->ins) {
    case U2F_REGISTER:
      u2f_register_ble(a);
      break;
    case U2F_AUTHENTICATE:
      u2f_authenticate_ble(a);
      break;
    case U2F_VERSION:
      u2f_version(a);
      break;
    default:
      send_u2f_error(U2F_SW_INS_NOT_SUPPORTED);
      break;
  }
}

void ctap_ble_msg(uint8_t *data, uint16_t len) {
  if (data[0] == 0x00 || data[0] == 0x80) {
    ble_u2f_msg((APDU *)data);
    return;
  } else {
    if (dialog_is_busy()) {
      return;
    }
    ctap_cbor_cmd(data, len);
  }
}

void ctap_ble_cmd(void) {
  uint8_t cmd = ble_fido_data[0];
  uint16_t data_len = ble_fido_data[1] << 8 | ble_fido_data[2];
  uint8_t *data_ptr = ble_fido_data + 3;

  if (transport_type == TRANSPORT_HID) {
    uint8_t err = CTAP1_ERR_CHANNEL_BUSY;
    ctap_ble_u2f_send(U2FHID_ERROR, &err, 1);
    return;
  }

  transport_type = TRANSPORT_BLE;
  poll_nest++;

  if (data_len + 3 != ble_fido_data_len) {
    send_u2fhid_error(cid, ERR_INVALID_LEN);
    transport_type = TRANSPORT_NULL;
    return;
  }

  protectAbortedByFIDO = true;

  ctap_printf("ctap_ble_cmd cmd: %d\n", cmd);
  dump_hex1(NULL, data_ptr, data_len);

  switch (cmd) {
    case U2FHID_PING:
      ctap_ble_ping(data_ptr, data_len);
      break;
    case U2FHID_MSG:
      ctap_ble_msg(data_ptr, data_len);
      break;
    default:
      break;
  }
  poll_nest--;
  if (poll_nest == 0) {
    transport_type = TRANSPORT_NULL;
  }
}
