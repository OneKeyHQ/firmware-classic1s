#include "thd89_boot.h"
#include "common.h"
#include "thd89.h"

#define SE_APP_READY_MAX_POLLS 120U
#define SE_APP_READY_POLL_DELAY_MS 100U

typedef enum {
  SE_UPDATE_IDLE,
  SE_UPDATE_HEADER_SENT,
  SE_UPDATE_BODY_SENT,
  SE_UPDATE_CHECKED,
} se_update_phase_t;

static se_update_phase_t se_update_phase = SE_UPDATE_IDLE;
static uint32_t se_update_expected_bytes;
static uint32_t se_update_sent_bytes;

static void se_update_reset(void) {
  se_update_phase = SE_UPDATE_IDLE;
  se_update_expected_bytes = 0;
  se_update_sent_bytes = 0;
}

bool se_reset_se(void) {
  uint8_t cmd[5] = {0x00, 0xF0, 0x00, 0x00, 0x00};
  uint16_t resp_len = 0;

  if (!thd89_transmit(cmd, sizeof(cmd), NULL, &resp_len)) {
    return false;
  }
  return true;
}

bool se_keep_stayinboot(void) {
  uint8_t cmd[5] = {0x00, 0xF1, 0x00, 0x00, 0x00};
  uint16_t resp_len = 0;

  if (!thd89_transmit(cmd, sizeof(cmd), NULL, &resp_len)) {
    return false;
  }
  return true;
}

bool se_reset_to_boot(void) {
  thd89_power_off();
  hal_delay(10);
  thd89_power_on();

  return se_keep_stayinboot();
}

bool se_get_firmware_version(uint8_t *version) {
  uint8_t cmd[5] = {0x00, 0xf7, 0x00, 00, 0x02};
  uint16_t ver_len = 2;

  if (version == NULL || !thd89_transmit(cmd, sizeof(cmd), version, &ver_len) ||
      ver_len != 2) {
    if (version != NULL) {
      version[0] = 0;
      version[1] = 0;
    }
    return false;
  }

  return true;
}

bool se_get_state(uint8_t *state) {
  uint8_t cmd[5] = {0x80, 0xca, 0x00, 00, 0x00};
  uint16_t resp_len = 1;

  if (!thd89_transmit(cmd, sizeof(cmd), state, &resp_len)) {
    return false;
  }

  if ((resp_len != 0x01) ||
      ((state[0] != 0x00) && (state[0] != 0x55) && (state[0] != 0x33))) {
    return false;
  }
  return true;
}

bool se_back_to_boot(void) {
  uint8_t cmd[5] = {0x80, 0xfc, 0x00, 0xff, 0x00};
  uint16_t resp_len = 0;
  if (!thd89_transmit(cmd, sizeof(cmd), NULL, &resp_len)) {
    return false;
  }
  return true;
}

static bool se_send_update_packet(uint8_t step, const uint8_t *data,
                                  uint16_t data_len) {
  uint8_t cmd[1032];
  uint16_t cmd_len = 5, resp_len = 0;
  cmd[0] = 0x80;
  cmd[1] = 0xFC;
  cmd[2] = 0x00;
  cmd[3] = step;
  cmd[4] = 0x00;

  if (step == 0x01) {
    if (data == NULL || data_len != 1024) goto fail;
    cmd[5] = 0x04;
    cmd[6] = 0x00;
    memcpy(cmd + 7, data, data_len);
    cmd_len += 2 + data_len;
  } else if (step == 0x02) {
    if (data == NULL || data_len != 512) goto fail;
    cmd[5] = 0x02;
    cmd[6] = 0x00;
    memcpy(cmd + 7, data, 512);
    cmd_len += 2 + 512;
  } else {
    goto fail;
  }

  if (!thd89_transmit(cmd, cmd_len, NULL, &resp_len)) {
    goto fail;
  }
  return true;

fail:
  se_update_reset();
  return false;
}

static bool se_send_check_packet(void) {
  const uint8_t cmd[5] = {0x80, 0xFC, 0x00, 0x03, 0x00};
  uint16_t resp_len = 0;

  if (!thd89_transmit(cmd, sizeof(cmd), NULL, &resp_len)) {
    se_update_reset();
    return false;
  }
  return true;
}

bool se_back_to_boot_progress(void) {
  uint8_t state;
  if (!se_get_state(&state)) {
    return false;
  }
  if (state == THD89_STATE_APP) {
    se_back_to_boot();
    hal_delay(1000);
    se_get_state(&state);
  }
  if (state != THD89_STATE_BOOT) {
    return false;
  }
  return true;
}

bool se_erase_storage_plaintext(void) {
  const uint8_t cmd[5] = {0x80, 0xE1, 0x00, 0x00, 0x00};
  uint8_t response[1] = {0};
  uint16_t response_len = sizeof(response);
  uint16_t sw1sw2 = 0;

  return thd89_transmit_raw(cmd, sizeof(cmd), response, &response_len,
                            &sw1sw2) == sectrue &&
         response_len == 0 && sw1sw2 == 0x9000;
}

bool se_verify_firmware(const uint8_t *header, uint32_t header_len,
                        uint32_t code_len) {
  if (se_update_phase != SE_UPDATE_IDLE || header == NULL ||
      header_len != 1024 || code_len == 0 || code_len % 512 != 0) {
    se_update_reset();
    return false;
  }
  if (!se_send_update_packet(0x01, header, (uint16_t)header_len)) {
    return false;
  }

  se_update_phase = SE_UPDATE_HEADER_SENT;
  se_update_expected_bytes = code_len;
  se_update_sent_bytes = 0;
  return true;
}

bool se_check_firmware(void) {
  if (se_update_phase != SE_UPDATE_BODY_SENT ||
      se_update_sent_bytes != se_update_expected_bytes) {
    se_update_reset();
    return false;
  }
  if (!se_send_check_packet()) {
    return false;
  }

  se_update_phase = SE_UPDATE_CHECKED;
  return true;
}

bool se_update_firmware(uint8_t *data, uint32_t data_len,
                        void (*ui_callback)(const char *msg, int progress)) {
  uint32_t offset_len = 0;
  if (se_update_phase != SE_UPDATE_HEADER_SENT || data == NULL ||
      data_len != se_update_expected_bytes) {
    se_update_reset();
    return false;
  }

  while (offset_len < data_len) {
    if (!se_send_update_packet(0x02, data + offset_len, 512)) {
      return false;
    }
    offset_len += 512;
    se_update_sent_bytes += 512;
    if (ui_callback) {
      ui_callback("Installing se...",
                  (int)(1000U * (uint64_t)se_update_sent_bytes /
                        se_update_expected_bytes));
    }
  }

  se_update_phase = SE_UPDATE_BODY_SENT;
  return true;
}

bool se_active_app_progress(void) {
  const uint8_t activate_cmd[5] = {0x80, 0xfc, 0x00, 0x04, 0x00};
  const uint8_t state_cmd[5] = {0x80, 0xca, 0x00, 0x00, 0x00};
  uint16_t response_len = 0;
  uint16_t sw1sw2 = 0;
  uint8_t state = 0;
  bool result = false;

  if (se_update_phase != SE_UPDATE_CHECKED) {
    se_update_reset();
    return false;
  }

  if (thd89_try_transmit_raw(activate_cmd, sizeof(activate_cmd), NULL,
                             &response_len, &sw1sw2) == sectrue &&
      (response_len != 0 || sw1sw2 != 0x9000)) {
    goto done;
  }

  for (uint32_t poll = 0; poll < SE_APP_READY_MAX_POLLS; poll++) {
    response_len = sizeof(state);
    sw1sw2 = 0;
    if (thd89_try_transmit_raw(state_cmd, sizeof(state_cmd), &state,
                               &response_len, &sw1sw2) == sectrue) {
      if (sw1sw2 != 0x9000 || response_len != sizeof(state) ||
          (state != THD89_STATE_BOOT && state != THD89_STATE_NOT_ACTIVATED &&
           state != THD89_STATE_APP)) {
        goto done;
      }
      if (state == THD89_STATE_APP) {
        result = true;
        goto done;
      }
    }
    if (poll + 1 < SE_APP_READY_MAX_POLLS) {
      hal_delay(SE_APP_READY_POLL_DELAY_MS);
    }
  }

done:
  se_update_reset();
  return result;
}

char *se_get_version(void) {
  uint8_t get_ver[5] = {0x00, 0xf7, 0x00, 00, 0x00};
  static char ver[8] = {0};
  uint16_t ver_len = sizeof(ver) - 1;

  memset(ver, 0, sizeof(ver));
  if (!thd89_transmit(get_ver, sizeof(get_ver), (uint8_t *)ver, &ver_len) ||
      ver_len == 0 || ver_len >= sizeof(ver) ||
      memchr(ver, '\0', ver_len) != NULL) {
    memset(ver, 0, sizeof(ver));
    return NULL;
  }
  ver[ver_len] = '\0';

  return ver;
}

char *se_get_build_id(void) {
  uint8_t get_build_id[5] = {0x00, 0xf7, 0x00, 0x01, 0x00};
  static char build_id[8] = {0};
  uint16_t len = sizeof(build_id) - 1;

  memset(build_id, 0, sizeof(build_id));
  if (!thd89_transmit(get_build_id, sizeof(get_build_id), (uint8_t *)build_id,
                      &len) ||
      len != sizeof(build_id) - 1) {
    memset(build_id, 0, sizeof(build_id));
    return NULL;
  }
  build_id[len] = '\0';

  return build_id;
}

char *se_get_hash(void) {
  uint8_t get_hash[5] = {0x00, 0xf7, 0x00, 0x02, 0x00};
  static char hash[32] = {0};
  uint16_t len = 32;

  memset(hash, 0, sizeof(hash));
  if (!thd89_transmit(get_hash, sizeof(get_hash), (uint8_t *)hash, &len) ||
      len != sizeof(hash)) {
    memset(hash, 0, sizeof(hash));
    return NULL;
  }

  return hash;
}
