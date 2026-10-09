/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <libopencm3/usb/usbd.h>
#include "../flash.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ble.h"
#include "bootloader.h"
#include "buttons.h"
#include "common.h"
#include "ecdsa.h"
#include "fw_signatures.h"
#include "layout.h"
#include "layout_boot.h"
#include "memory.h"
#include "memzero.h"
#include "oled.h"
#include "rng.h"
#include "secbool.h"
#include "secp256k1.h"
#include "sha2.h"
#include "si2c.h"
#include "sys.h"
#include "updateble.h"
#include "upgrade_policy.h"
#include "usb.h"
#include "util.h"

#include "timer.h"
#include "usart.h"

#include "compatible.h"
#include "mi2c.h"
#include "nordic_dfu.h"
#include "thd89_boot.h"
#include "usb21_standard.h"
#include "usb_desc.h"
#include "webusb.h"
#include "winusb.h"

enum {
  STATE_READY,
  STATE_OPEN,
  STATE_FLASHSTART,
  STATE_FLASHING,
  STATE_INTERRPUPT,
  STATE_CHECK,
  STATE_UPGRADE_HEADER,
  STATE_END,
};

#define NORDIC_BLE_UPDATE 1

#define UPDATE_BLE 0x5A
#define UPDATE_ST 0x55
#define UPDATE_SE 0x56

// Message ID constants
#define MSG_ID_INITIALIZE 0x0000
#define MSG_ID_PING 0x0001
#define MSG_ID_WIPE_DEVICE 0x0005
#define MSG_ID_FIRMWARE_ERASE 0x0006
#define MSG_ID_FIRMWARE_UPLOAD 0x0007
#define MSG_ID_FIRMWARE_ERASE_EX 0x0010
#define MSG_ID_FEATURES 0x0011
#define MSG_ID_BUTTON_ACK 0x001B
#define MSG_ID_GET_FEATURES 0x0037
#define MSG_ID_UPGRADE_FILE_HEADER 10050

// Failure codes
#define FAILURE_UNEXPECTED_MESSAGE 1
#define FAILURE_ACTION_CANCELLED 4
#define FAILURE_PROCESS_ERROR 9
#define FAILURE_BATTERY_LOW 30

// Protocol constants
#define PROTOCOL_HEADER "?##"
#define PROTOCOL_HEADER_LEN 3

// USB communication and firmware update context
typedef struct {
  // Update state and progress
  char state;            // Current update state
  uint32_t pos;          // Current flash position
  uint32_t len;          // Total firmware length
  uint32_t combine_pos;  // Combined firmware position (for SE update)
  uint8_t mode;          // Update mode (UPDATE_ST, UPDATE_BLE, UPDATE_SE)

  // Message processing
  uint16_t msg_id;    // Current message ID
  uint32_t msg_size;  // Current message size
  uint32_t w;         // Temporary word buffer for data assembly
  int wi;             // Word index (0-3)

  // Firmware verification
  secbool se_isUpdate;        // Whether SE firmware is being updated
  int old_was_signed;         // Whether old firmware was signed
  uint32_t previous_version;  // Previous firmware version
  uint32_t previous_purpose;  // Previous firmware purpose
  upgrade_previous_state_t previous_state;
  upgrade_erase_target_t erase_target;
  secbool erase_storage;         // Whether to erase storage
  uint32_t fix_version_current;  // Current fix version

  // Upgrade file header reception
  uint32_t
      upgrade_header_pos;  // Current position in upgrade header buffer (for
                           // MSG_ID_UPGRADE_FILE_HEADER) OR bytes skipped in
                           // firmware upload (for embedded upgrade header)
  uint32_t
      upgrade_header_len;  // Total expected header length (for
                           // MSG_ID_UPGRADE_FILE_HEADER) OR FLASH_FWHEADER_LEN
                           // (for embedded upgrade header)
  uint8_t
      upgrade_header_buffer[FLASH_FWHEADER_LEN];  // Buffer for receiving header
  secbool
      has_upgrade_header;  // Whether upgrade header was received (new format)
  secbool header_in_fw_header;  // Whether old format header is in
  // firmware_header_buffer
  upgrade_file_format_t preflight_format;
  upgrade_image_target_t preflight_target;
  upgrade_file_format_t upload_format;
  secbool upload_header_checked;
  secbool upload_wrapper_present;
  uint8_t *header_buffer;
} msg_context_t;

// Large data buffers (separated to reduce structure size)
static uint32_t COMBINED_FW_HEADER[FLASH_FWHEADER_LEN / sizeof(uint32_t)];
static uint8_t packet_buf[64] __attribute__((aligned(4)));

// Buffer for storing first 4KB of firmware (before verification)
#define FIRMWARE_HEADER_BUFFER_SIZE (4096)
static uint32_t
    firmware_header_buffer[FIRMWARE_HEADER_BUFFER_SIZE / sizeof(uint32_t)];

// Global USB context
static msg_context_t msg_ctx = {
    .state = STATE_READY,
    .pos = 0,
    .len = 0,
    .combine_pos = 0,
    .mode = 0,
    .msg_id = 0xFFFF,
    .msg_size = 0,
    .w = 0,
    .wi = 0,
    .se_isUpdate = secfalse,
    .old_was_signed = 0,
    .previous_version = 0,
    .previous_purpose = FIRMWARE_PURPOSE_GENERAL,
    .previous_state = UPGRADE_PREVIOUS_UNKNOWN,
    .erase_target = UPGRADE_ERASE_TARGET_NONE,
    .erase_storage = secfalse,
    .fix_version_current = 0xffffffff,
    .upgrade_header_pos = 0,
    .upgrade_header_len = 0,
    .has_upgrade_header = secfalse,
    .header_in_fw_header = secfalse,
    .preflight_format = UPGRADE_FILE_FORMAT_NONE,
    .preflight_target = UPGRADE_IMAGE_TARGET_NONE,
    .upload_format = UPGRADE_FILE_FORMAT_NONE,
    .upload_header_checked = secfalse,
    .upload_wrapper_present = secfalse,
    .header_buffer = (uint8_t *)firmware_header_buffer,
};

// Legacy global variables for backward compatibility
#define flash_state (msg_ctx.state)
#define flash_pos (msg_ctx.pos)
#define flash_len (msg_ctx.len)
#define flash_combine_pos (msg_ctx.combine_pos)
#define update_mode (msg_ctx.mode)

#include "usb_send.h"

static void flash_enter(void) { return; }
static void flash_exit(void) { return; }

#include "usb_erase.h"

// Forward declarations
static secbool process_flashing_data(usbd_device *dev, const uint8_t *p_buf,
                                     uint32_t *w, int *wi,
                                     secbool *se_isUpdate);
static secbool process_complete_upgrade_header(usbd_device *dev);
static secbool process_new_format_upgrade_header(usbd_device *dev);
static secbool process_old_format_upgrade_header(usbd_device *dev);
static secbool validate_upgrade_wrapper(usbd_device *dev,
                                        const upgrade_file_header_t *hdr);
static secbool consume_upgrade_wrapper(usbd_device *dev, const uint8_t *data,
                                       uint32_t available, uint32_t *consumed);
static secbool validate_uploaded_old_header(usbd_device *dev);
static void reset_upgrade_header_state(void);
static void reset_update_session_state(void);
static secbool capture_previous_mcu_info(usbd_device *dev, int *old_was_signed,
                                         uint32_t *fix_version_current,
                                         uint32_t *previous_purpose);
static secbool validate_preflight_erase_target(
    usbd_device *dev, upgrade_erase_target_t requested_erase_target);
static secbool validate_upload_target(usbd_device *dev);
static secbool validate_wrapper_inner_metadata(usbd_device *dev);
static void handle_error(usbd_device *dev, uint8_t error_code,
                         const char *line1, const char *line2);
static void get_current_mcu_info(uint32_t *version, uint32_t *purpose);
static secbool check_mcu_downgrade(usbd_device *dev, uint32_t new_version,
                                   uint32_t current_version,
                                   uint32_t new_purpose,
                                   uint32_t current_purpose);
static secbool check_mcu_install(usbd_device *dev, uint32_t new_version,
                                 uint32_t current_version, uint32_t new_purpose,
                                 uint32_t current_purpose);
static secbool check_se_minimum_version(usbd_device *dev,
                                        uint32_t se_minimum_version,
                                        uint32_t latest_se_version);
static secbool prompt_purpose_change(usbd_device *dev, uint32_t new_purpose,
                                     uint32_t current_purpose);
static secbool prompt_mcu_upgrade(usbd_device *dev, uint32_t new_version,
                                  uint32_t current_version, uint32_t purpose);
static void complete_upgrade_header_processing(void);

// read protobuf integer and advance pointer
static secbool readprotobufint(const uint8_t **ptr, uint32_t *result) {
  *result = 0;

  for (int i = 0; i <= 3; ++i) {
    *result += (**ptr & 0x7F) << (7 * i);
    if ((**ptr & 0x80) == 0) {
      (*ptr)++;
      return sectrue;
    }
    (*ptr)++;
  }

  if (**ptr & 0xF0) {
    // result does not fit into uint32_t
    *result = 0;

    // skip over the rest of the integer
    while (**ptr & 0x80) (*ptr)++;
    (*ptr)++;
    return secfalse;
  }

  *result += (uint32_t)(**ptr) << 28;
  (*ptr)++;
  return sectrue;
}

static void version_uint32_to_str(uint32_t version, char *str,
                                  size_t str_size) {
  uint8_t major = version & 0xFF;
  uint8_t minor = (version >> 8) & 0xFF;
  uint8_t patch = (version >> 16) & 0xFF;
  snprintf(str, str_size, "%d.%d.%d", major, minor, patch);
}

// Helper: Get current MCU firmware version and purpose
static void get_current_mcu_info(uint32_t *version, uint32_t *purpose) {
  *version = 0;
  *purpose = FIRMWARE_PURPOSE_GENERAL;
  if (firmware_present_new() || firmware_present_upgrade()) {
    const image_header *current_hdr =
        (const image_header *)FLASH_PTR(FLASH_FWHEADER_START);
    *version = current_hdr->onekey_version;
    *purpose = current_hdr->purpose;
  }
}

// Helper: Check MCU downgrade
static secbool check_mcu_downgrade(usbd_device *dev, uint32_t new_version,
                                   uint32_t current_version,
                                   uint32_t new_purpose,
                                   uint32_t current_purpose) {
  if (upgrade_mcu_downgrade_allowed(new_version, current_version, new_purpose,
                                    current_purpose) == sectrue) {
    return sectrue;
  }
  handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware downgrade",
               "not allowed.");
  return secfalse;
}

static secbool check_mcu_install(usbd_device *dev, uint32_t new_version,
                                 uint32_t current_version, uint32_t new_purpose,
                                 uint32_t current_purpose) {
  if (upgrade_mcu_install_allowed(msg_ctx.previous_state, new_version,
                                  current_version, new_purpose,
                                  current_purpose) == sectrue) {
    return sectrue;
  }
  handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware rollback", "not allowed.");
  return secfalse;
}

// Helper: Check SE minimum version requirement
// latest_se_version: the latest SE version (either current or upgraded version)
static secbool check_se_minimum_version(usbd_device *dev,
                                        uint32_t se_minimum_version,
                                        uint32_t latest_se_version) {
  if (se_minimum_version == 0) {
    return sectrue;  // No requirement
  }

  if (latest_se_version == 0 ||
      upgrade_version_compare(latest_se_version, se_minimum_version) < 0) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "SE version", "too old.");
    return secfalse;
  }
  return sectrue;
}

// Helper: Prompt user if firmware purpose changes
static secbool prompt_purpose_change(usbd_device *dev, uint32_t new_purpose,
                                     uint32_t current_purpose) {
  if (new_purpose == current_purpose) {
    return sectrue;  // No change
  }

  layoutDialogCenterAdapterEx(
      &bmp_icon_warning, &bmp_bottom_left_close, &bmp_bottom_right_confirm,
      NULL, "Change firmware type will", "erase seed, keep your",
      "recovery phrase safe.", NULL);
  if (!waitButtonResponse(BTN_PIN_YES, default_oper_time)) {
    handle_error(dev, FAILURE_ACTION_CANCELLED, "Installation", "cancelled.");
    return secfalse;
  }
  msg_ctx.erase_storage = sectrue;
  return sectrue;
}

// Helper: Show MCU version info and prompt for confirmation
static secbool prompt_mcu_upgrade(usbd_device *dev, uint32_t new_version,
                                  uint32_t current_version, uint32_t purpose) {
  char new_version_str[32] = {0};
  char current_version_str[32] = {0};
  char version_transition[70] = {0};

  version_uint32_to_str(new_version, new_version_str, sizeof(new_version_str));

  if (current_version > 0) {
    version_uint32_to_str(current_version, current_version_str,
                          sizeof(current_version_str));
    snprintf(version_transition, sizeof(version_transition), "%s -> %s",
             current_version_str, new_version_str);
  } else {
    snprintf(version_transition, sizeof(version_transition), "Version: %s",
             new_version_str);
  }

  if (purpose == FIRMWARE_PURPOSE_BTC_ONLY) {
    layoutDialogCenterAdapterEx(
        NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm, NULL, NULL,
        version_transition, "Install Bitcoin-only ", "firmware by OneKey?");
  } else {
    layoutDialogCenterAdapterEx(
        NULL, &bmp_bottom_left_close, &bmp_bottom_right_confirm, NULL, NULL,
        version_transition, "Install firmware by", "OneKey?");
  }

  if (!waitButtonResponse(BTN_PIN_YES, default_oper_time)) {
    handle_error(dev, FAILURE_ACTION_CANCELLED, "Installation", "cancelled.");
    return secfalse;
  }
  return sectrue;
}

// Helper: Complete upgrade header processing
static void complete_upgrade_header_processing(void) {
  msg_ctx.upgrade_header_pos = 0;
  msg_ctx.upgrade_header_len = 0;

  if (flash_state == STATE_UPGRADE_HEADER) {
    flash_state = STATE_OPEN;
  }
}

static int should_keep_storage(int old_was_signed,
                               uint32_t fix_version_current) {
  // FTFixed: Storage移动到se中，无须此函数
  (void)old_was_signed;
  (void)fix_version_current;
  return SIG_OK;
  // if the current firmware is unsigned, always erase storage
  if (SIG_OK != old_was_signed) return SIG_FAIL;

  const image_header *new_hdr = (const image_header *)firmware_header_buffer;
  // new header must be signed by v3 signmessage/verifymessage scheme
  if (SIG_OK != signatures_ok(new_hdr, NULL, sectrue)) return SIG_FAIL;
  // if the new header hashes don't match flash contents, erase storage
  if (SIG_OK != check_firmware_hashes(new_hdr, NULL, 0)) return SIG_FAIL;

  // if the current fix_version is higher than the new one, erase storage
  if (upgrade_version_compare(new_hdr->version, fix_version_current) < 0) {
    return SIG_FAIL;
  }

  return SIG_OK;
}

// Helper function: Check if packet has valid protocol header
static secbool validate_protocol_header(const uint8_t *buf) {
  return (buf[0] == '?' && buf[1] == '#' && buf[2] == '#') ? sectrue : secfalse;
}

// Helper function: Parse message header from packet
static secbool parse_message_header(const uint8_t *buf, uint16_t *msg_id,
                                    uint32_t *msg_size) {
  if (!validate_protocol_header(buf)) {
    return secfalse;
  }
  *msg_id = (buf[3] << 8) | buf[4];
  *msg_size = ((uint32_t)buf[5] << 24) | ((uint32_t)buf[6] << 16) |
              ((uint32_t)buf[7] << 8) | buf[8];
  return sectrue;
}

// Helper function: Handle error and update state
static void handle_error(usbd_device *dev, uint8_t error_code,
                         const char *line1, const char *line2) {
  char message[64] = {0};
  if (line1) {
    strcpy(message, line1);
  }
  if (line2) {
    if (line1) {
      strcat(message, " ");
    }
    strcat(message, line2);
  }
  send_msg_failure(dev, error_code, message);
  flash_state = STATE_END;
  if (line1 || line2) {
    show_halt(line1, line2);
  }
}

// Helper function: Check battery level before firmware operations
static secbool check_battery_level(usbd_device *dev) {
  if (sys_usbState() == false && battery_cap < 2) {
    layoutDialogCenterAdapterEx(
        &bmp_icon_warning, NULL, &bmp_bottom_right_confirm, NULL,
        "Low Battery!Use cable or", "Charge to 25% before",
        "updating the bootloader", NULL);
    while (1) {
      uint8_t key = keyScan();
      if (key == KEY_CONFIRM) {
        send_msg_failure(dev, FAILURE_BATTERY_LOW, NULL);
        flash_state = STATE_END;
        show_unplug("Low battery!", "aborted.");
        shutdown();
        return secfalse;
      }
      if (sys_usbState() == true) {
        break;
      }
    }
  }
  return sectrue;
}

// Helper function: Handle Initialize, Ping, GetFeatures messages
static secbool handle_simple_messages(usbd_device *dev, uint16_t msg_id) {
  switch (msg_id) {
    case MSG_ID_INITIALIZE:
      reset_update_session_state();
      send_msg_features(dev);
      flash_state = STATE_OPEN;
      return sectrue;
    case MSG_ID_GET_FEATURES:
      send_msg_features(dev);
      return sectrue;
    case MSG_ID_PING:
      send_msg_success(dev);
      return sectrue;
    default:
      return secfalse;
  }
}

// Helper function: Check if data starts with valid firmware magic
static secbool check_firmware_magic(const uint8_t *data) {
  return (memcmp(data, &FIRMWARE_MAGIC_NEW, 4) == 0) ||
                 (memcmp(data, &FIRMWARE_MAGIC_BLE, 4) == 0)
             ? sectrue
             : secfalse;
}

// Helper function: Determine update mode from firmware magic
static uint8_t get_update_mode_from_magic(const uint8_t *data) {
  if (memcmp(data, &FIRMWARE_MAGIC_NEW, 4) == 0) {
    return UPDATE_ST;
  } else if (memcmp(data, &FIRMWARE_MAGIC_BLE, 4) == 0) {
    return UPDATE_BLE;
  }
  return 0;
}

// Helper function: Reset upgrade header reception state
static void reset_upgrade_header_state(void) {
  msg_ctx.upgrade_header_pos = 0;
  msg_ctx.upgrade_header_len = 0;
  memzero(msg_ctx.upgrade_header_buffer, sizeof(msg_ctx.upgrade_header_buffer));
  msg_ctx.has_upgrade_header = secfalse;
  msg_ctx.header_in_fw_header = secfalse;
  msg_ctx.preflight_format = UPGRADE_FILE_FORMAT_NONE;
  msg_ctx.preflight_target = UPGRADE_IMAGE_TARGET_NONE;
  msg_ctx.upload_format = UPGRADE_FILE_FORMAT_NONE;
  msg_ctx.upload_header_checked = secfalse;
  msg_ctx.upload_wrapper_present = secfalse;
  // Restore to OPEN state if we were in UPGRADE_HEADER state
  if (flash_state == STATE_UPGRADE_HEADER) {
    flash_state = STATE_OPEN;
  }
}

static void reset_update_session_state(void) {
  reset_upgrade_header_state();
  msg_ctx.erase_target = UPGRADE_ERASE_TARGET_NONE;
  msg_ctx.previous_state = UPGRADE_PREVIOUS_UNKNOWN;
  msg_ctx.previous_version = 0;
  msg_ctx.previous_purpose = FIRMWARE_PURPOSE_GENERAL;
  msg_ctx.old_was_signed = SIG_FAIL;
  msg_ctx.fix_version_current = 0xffffffff;
  msg_ctx.erase_storage = secfalse;
  msg_ctx.se_isUpdate = secfalse;
  flash_combine_pos = 0;
  update_mode = 0;
}

// Helper function: Process upgrade file header data packet
static secbool process_upgrade_file_header_packet(usbd_device *dev,
                                                  const uint8_t *p_buf) {
  const uint8_t *p =
      p_buf + 9;  // Skip protocol header (3) + msg_id (2) + msg_size (4)
  static uint32_t progress_counter = 0;
  // First packet: parse protobuf header and initialize reception
  if (msg_ctx.upgrade_header_pos == 0) {
    reset_upgrade_header_state();
    progress_counter = 0;
    // Check if this is field 1 (data) with wire type 2 (bytes)
    if (*p != 0x0a) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Invalid header", "format.");
      return secfalse;
    }
    p++;

    // Read the length of the bytes field
    if (readprotobufint(&p, &msg_ctx.upgrade_header_len) != sectrue) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Invalid header", "length.");
      return secfalse;
    }

    if (msg_ctx.upgrade_header_len != FLASH_FWHEADER_LEN) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Header size", "mismatch.");
      return secfalse;
    }

    // Calculate how much data is in this first packet
    // After protobuf header (field tag + length), we have the actual data
    uint32_t data_in_packet = (uint32_t)((p_buf + 64) - p);
    if (data_in_packet > msg_ctx.upgrade_header_len) {
      data_in_packet = msg_ctx.upgrade_header_len;
    }

    // Detect header format by checking magic (first 4 bytes)
    uint32_t header_magic = 0;
    if (data_in_packet >= 4) {
      header_magic = *(const uint32_t *)p;
    }

    if (header_magic == UPGRADE_HEADER_MAGIC) {
      // New format: upgrade_file_header_t -> use upgrade_header_buffer
      msg_ctx.header_buffer = msg_ctx.upgrade_header_buffer;

    } else if (header_magic == FIRMWARE_MAGIC_NEW ||
               header_magic == FIRMWARE_MAGIC_BLE) {
      // Old format: image_header -> use firmware_header_buffer
      msg_ctx.header_buffer = (uint8_t *)firmware_header_buffer;

    } else {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Unknown header", "format.");
      return secfalse;
    }

    // Copy data from first packet
    if (data_in_packet > 0) {
      memcpy(msg_ctx.header_buffer, p, data_in_packet);
      msg_ctx.upgrade_header_pos = data_in_packet;
    } else {
      flash_state = STATE_UPGRADE_HEADER;
      return sectrue;
    }

    flash_state = STATE_UPGRADE_HEADER;

    return sectrue;
  }

  if (flash_state != STATE_UPGRADE_HEADER) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Unexpected", "packet.");
    return secfalse;
  }

  // Check protocol header (first byte should be '?')
  if (p_buf[0] != '?') {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Invalid packet", "header.");
    return secfalse;
  }

  // Calculate how much data we can copy from this packet
  // Subsequent packets: first byte is '?', remaining 63 bytes are data
  uint32_t remaining = msg_ctx.upgrade_header_len - msg_ctx.upgrade_header_pos;
  uint32_t data_in_packet = 63;  // 64 - 1 (skip '?' byte)
  if (data_in_packet > remaining) {
    data_in_packet = remaining;
  }

  // Copy data from packet (skip first byte '?', data starts at offset 1)
  const uint8_t *data_start = p_buf + 1;
  memcpy(msg_ctx.header_buffer + msg_ctx.upgrade_header_pos, data_start,
         data_in_packet);
  msg_ctx.upgrade_header_pos += data_in_packet;

  progress_counter++;
  if (progress_counter % 16 == 0) {
    uint32_t progress =
        (msg_ctx.upgrade_header_pos * 1000) / msg_ctx.upgrade_header_len;
    layoutProgress("Receiving header...", progress);
  }

  // Check if we've received all data
  if (msg_ctx.upgrade_header_pos >= msg_ctx.upgrade_header_len) {
    return process_complete_upgrade_header(dev);
  }

  return sectrue;
}

// Helper function: Verify upgrade header checksum
static secbool verify_upgrade_header_checksum(
    const upgrade_file_header_t *hdr) {
  // Calculate SHA256 of header data excluding the checksum field
  uint8_t calculated_checksum[32];
  uint8_t temp_header[FLASH_FWHEADER_LEN];

  // Copy header to temp buffer
  memcpy(temp_header, hdr, FLASH_FWHEADER_LEN);

  size_t checksum_offset = offsetof(upgrade_file_header_t, header_checksum);
  memset(temp_header + checksum_offset, 0, 32);

  // Calculate SHA256 of entire header (1024 bytes) with checksum field zeroed
  sha256_Raw(temp_header, FLASH_FWHEADER_LEN, calculated_checksum);

  // Compare checksums
  return (memcmp(hdr->header_checksum, calculated_checksum, 32) == 0)
             ? sectrue
             : secfalse;
}

static secbool validate_upgrade_wrapper(usbd_device *dev,
                                        const upgrade_file_header_t *hdr) {
  if (hdr->magic != UPGRADE_HEADER_MAGIC ||
      hdr->header_version != UPGRADE_HEADER_VERSION) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Unsupported header", "version.");
    return secfalse;
  }
  if (verify_upgrade_header_checksum(hdr) != sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Header checksum", "mismatch.");
    return secfalse;
  }

  uint8_t flags = hdr->flags;
  secbool supported =
      (flags == UPGRADE_FLAG_MCU_PRESENT ||
       flags == (UPGRADE_FLAG_MCU_PRESENT | UPGRADE_FLAG_SE_PRESENT) ||
       flags == UPGRADE_FLAG_BLE_PRESENT)
          ? sectrue
          : secfalse;
  if (supported != sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Unsupported firmware",
                 "combination.");
    return secfalse;
  }
  if (upgrade_wrapper_declared_lengths_allowed(
          hdr, FLASH_FWHEADER_LEN + FLASH_APP_LEN,
          FLASH_FWHEADER_LEN + FLASH_BLE_MAX_LEN) != sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware module",
                 "length invalid.");
    return secfalse;
  }
  return sectrue;
}

static secbool process_complete_upgrade_header(usbd_device *dev) {
  uint32_t header_magic = *(const uint32_t *)msg_ctx.header_buffer;

  // Check if this is new format (upgrade header) or old format (firmware
  // header)
  if (header_magic == UPGRADE_HEADER_MAGIC) {
    // New format: upgrade_file_header_t
    return process_new_format_upgrade_header(dev);
  } else if (header_magic == FIRMWARE_MAGIC_NEW ||
             header_magic == FIRMWARE_MAGIC_BLE) {
    // Old format: image_header (firmware header)
    return process_old_format_upgrade_header(dev);
  } else {
    // Unknown format
    handle_error(dev, FAILURE_PROCESS_ERROR, "Unknown header", "format.");
    return secfalse;
  }
}

// Helper function: Process new format upgrade header (upgrade_file_header_t)
static secbool process_new_format_upgrade_header(usbd_device *dev) {
  const upgrade_file_header_t *upgrade_hdr =
      (const upgrade_file_header_t *)msg_ctx.upgrade_header_buffer;

  if (validate_upgrade_wrapper(dev, upgrade_hdr) != sectrue) {
    return secfalse;
  }

  upgrade_image_target_t preflight_target =
      upgrade_wrapper_image_target(upgrade_hdr->flags);
  if (preflight_target == UPGRADE_IMAGE_TARGET_NONE) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Unsupported firmware", "target.");
    return secfalse;
  }

  // Get current MCU info
  uint32_t current_mcu_version = 0;
  uint32_t current_mcu_purpose = FIRMWARE_PURPOSE_GENERAL;
  get_current_mcu_info(&current_mcu_version, &current_mcu_purpose);

  // Get current SE version
  char *se_version_str = se_get_version();
  uint32_t current_se_version = 0;
  if (se_version_str != NULL) {
    current_se_version = version_string_to_int(se_version_str);
  }

  // Process SE upgrade first (if present) - check downgrade and get latest
  // version
  uint32_t latest_se_version = current_se_version;
  if (upgrade_hdr->flags & UPGRADE_FLAG_SE_PRESENT) {
    int se_version_diff = upgrade_version_compare(upgrade_hdr->se_info.version,
                                                  current_se_version);
    if (se_version_diff < 0) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "SE downgrade", "not allowed.");
      return secfalse;
    }
    // If not downgrade, use upgraded version as latest
    latest_se_version = upgrade_hdr->se_info.version;
  }

  // Process MCU upgrade (if present)
  if (upgrade_hdr->flags & UPGRADE_FLAG_MCU_PRESENT) {
    // Check downgrade
    if (check_mcu_downgrade(dev, upgrade_hdr->mcu_info.version,
                            current_mcu_version, upgrade_hdr->mcu_info.purpose,
                            current_mcu_purpose) != sectrue) {
      return secfalse;
    }

    // Check SE minimum version requirement (using latest SE version)
    if (check_se_minimum_version(dev, upgrade_hdr->mcu_info.se_minimum_version,
                                 latest_se_version) != sectrue) {
      return secfalse;
    }

    // Prompt purpose change
    if ((firmware_present_new() || firmware_present_upgrade()) &&
        prompt_purpose_change(dev, upgrade_hdr->mcu_info.purpose,
                              current_mcu_purpose) != sectrue) {
      return secfalse;
    }

    // Show version and prompt for confirmation
    if (prompt_mcu_upgrade(dev, upgrade_hdr->mcu_info.version,
                           current_mcu_version,
                           upgrade_hdr->mcu_info.purpose) != sectrue) {
      return secfalse;
    }
  }

  // Complete processing
  msg_ctx.has_upgrade_header = sectrue;
  msg_ctx.preflight_format = UPGRADE_FILE_FORMAT_NEW;
  msg_ctx.preflight_target = preflight_target;
  complete_upgrade_header_processing();
  send_msg_success(dev);
  return sectrue;
}

// Helper function: Process old format upgrade header (image_header)
static secbool process_old_format_upgrade_header(usbd_device *dev) {
  const image_header *firmware_hdr =
      (const image_header *)firmware_header_buffer;
  upgrade_image_target_t preflight_target = UPGRADE_IMAGE_TARGET_NONE;

  if (firmware_hdr->magic == FIRMWARE_MAGIC_NEW) {
    // allow only v3 signmessage/verifymessage signature for new FW
    if (SIG_OK != signatures_ok(firmware_hdr, NULL, sectrue)) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Signatures is", "wrong.");
      return secfalse;
    }

    if (memcmp((const uint8_t *)firmware_hdr + 24, HW_MODEL_C2B2, 4) != 0) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Wrong hardware model",
                   "header.");
      return secfalse;
    }

    // Get current MCU info
    uint32_t current_mcu_version = 0;
    uint32_t current_mcu_purpose = FIRMWARE_PURPOSE_GENERAL;
    get_current_mcu_info(&current_mcu_version, &current_mcu_purpose);

    // Check downgrade
    if (check_mcu_downgrade(dev, firmware_hdr->onekey_version,
                            current_mcu_version, firmware_hdr->purpose,
                            current_mcu_purpose) != sectrue) {
      return secfalse;
    }

    // Prompt purpose change
    if ((firmware_present_new() || firmware_present_upgrade()) &&
        prompt_purpose_change(dev, firmware_hdr->purpose,
                              current_mcu_purpose) != sectrue) {
      return secfalse;
    }

    // Show version and prompt for confirmation
    if (prompt_mcu_upgrade(dev, firmware_hdr->onekey_version,
                           current_mcu_version,
                           firmware_hdr->purpose) != sectrue) {
      return secfalse;
    }
    update_mode = UPDATE_ST;
    preflight_target = UPGRADE_IMAGE_TARGET_MCU;

  } else if (firmware_hdr->magic == FIRMWARE_MAGIC_BLE) {
    update_mode = UPDATE_BLE;
    preflight_target = UPGRADE_IMAGE_TARGET_BLE;

  } else {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Wrong firmware", "header.");
    return secfalse;
  }

  // Preserve the accepted signed header for complete-file comparison while
  // retaining firmware_header_buffer for the legacy body-only upload path.
  memcpy(msg_ctx.upgrade_header_buffer, firmware_header_buffer,
         FLASH_FWHEADER_LEN);
  msg_ctx.preflight_format = UPGRADE_FILE_FORMAT_OLD;
  msg_ctx.preflight_target = preflight_target;
  msg_ctx.header_in_fw_header = sectrue;
  complete_upgrade_header_processing();
  send_msg_success(dev);
  return sectrue;
}

// Helper function: Handle WipeDevice message
static secbool handle_wipe_device(usbd_device *dev) {
  layoutDialogCenterAdapterEx(&bmp_icon_question, &bmp_bottom_left_close,
                              &bmp_bottom_right_confirm, NULL,
                              "Do you really want to", "wipe the device?",
                              "All data will be lost.", NULL);
  bool but = waitButtonResponse(BTN_PIN_YES, default_oper_time);
  if (host_channel == CHANNEL_SLAVE) {
    return sectrue;
  }
  if (but) {
    erase_code_progress();
    if (!se_erase_storage_plaintext()) {
      flash_state = STATE_END;
      send_msg_failure(dev, FAILURE_PROCESS_ERROR, NULL);
      return secfalse;
    }
    flash_state = STATE_END;
    show_unplug("Device", "successfully wiped.");
    send_msg_success(dev);
  } else {
    flash_state = STATE_END;
    show_unplug("Device wipe", "aborted.");
    send_msg_failure(dev, FAILURE_ACTION_CANCELLED, NULL);
    shutdown();
  }
  return sectrue;
}

// Helper function: Handle FirmwareErase message (id 6)
static secbool validate_preflight_erase_target(
    usbd_device *dev, upgrade_erase_target_t requested_erase_target) {
  if (upgrade_preflight_erase_allowed(msg_ctx.preflight_format,
                                      msg_ctx.preflight_target,
                                      requested_erase_target) == sectrue) {
    return sectrue;
  }
  handle_error(dev, FAILURE_PROCESS_ERROR, "Erase/header type", "mismatch.");
  return secfalse;
}

static secbool capture_previous_mcu_info(usbd_device *dev, int *old_was_signed,
                                         uint32_t *fix_version_current,
                                         uint32_t *previous_purpose) {
  const image_header *stored =
      (const image_header *)FLASH_PTR(FLASH_FWHEADER_START);
  image_header normalized = {0};

  msg_ctx.previous_state = UPGRADE_PREVIOUS_UNKNOWN;
  msg_ctx.previous_version = 0;
  *previous_purpose = FIRMWARE_PURPOSE_GENERAL;
  *old_was_signed = SIG_FAIL;
  *fix_version_current = 0xffffffff;

  if (upgrade_previous_header_is_empty(stored) == sectrue) {
    msg_ctx.previous_state = UPGRADE_PREVIOUS_EMPTY;
    return sectrue;
  }

  if (upgrade_normalize_previous_header(stored, &normalized) != sectrue ||
      normalized.codelen > FLASH_APP_LEN || normalized.codelen < 4096U ||
      memcmp((const uint8_t *)&normalized + 24, HW_MODEL_C2B2, 4) != 0 ||
      signatures_ok(&normalized, NULL, sectrue) != SIG_OK) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Previous firmware", "invalid.");
    return secfalse;
  }

  msg_ctx.previous_version = normalized.onekey_version;
  *previous_purpose = normalized.purpose;
  *fix_version_current = normalized.fix_version;
  msg_ctx.previous_state = UPGRADE_PREVIOUS_VERIFIED;
  if (stored->magic == FIRMWARE_MAGIC_NEW &&
      check_firmware_hashes(stored, NULL, 0) == SIG_OK) {
    *old_was_signed = SIG_OK;
  }
  return sectrue;
}

static secbool handle_firmware_erase(usbd_device *dev, int *old_was_signed,
                                     uint32_t *fix_version_current,
                                     uint32_t *previous_purpose) {
  if (validate_preflight_erase_target(dev, UPGRADE_ERASE_TARGET_MCU) !=
      sectrue) {
    return secfalse;
  }
  if (check_battery_level(dev) != sectrue) {
    return secfalse;
  }

  bool proceed = false;
  if (msg_ctx.has_upgrade_header == sectrue ||
      msg_ctx.header_in_fw_header == sectrue) {
    proceed = true;
  } else {
    if (firmware_present_new() || firmware_present_upgrade()) {
      layoutDialogCenterAdapterEx(NULL, &bmp_bottom_left_close,
                                  &bmp_bottom_right_confirm, NULL, NULL, NULL,
                                  "Install firmware by", "OneKey?");
      proceed = waitButtonResponse(BTN_PIN_YES, default_oper_time);
    } else {
      proceed = true;
    }
  }

  if (proceed) {
    msg_ctx.erase_target = UPGRADE_ERASE_TARGET_NONE;
    if (capture_previous_mcu_info(dev, old_was_signed, fix_version_current,
                                  previous_purpose) != sectrue) {
      return secfalse;
    }

    flash_enter();
    flash_unlock_ex();
    const uint32_t *current_magic =
        (const uint32_t *)FLASH_PTR(FLASH_FWHEADER_START);

    if (*current_magic == FIRMWARE_MAGIC_NEW ||
        (*current_magic & FIRMWARE_MAGIC_UPGRADING) ==
            FIRMWARE_MAGIC_UPGRADING) {
      // Can write upgrading marker by bit flipping
      ensure(flash_write_word_item_ex(FLASH_FWHEADER_START,
                                      FIRMWARE_MAGIC_UPGRADING),
             "write upgrading marker failed");
    } else if (*current_magic == 0xFFFFFFFF) {
      // Page is erased, can write any value
      ensure(flash_write_word_item_ex(FLASH_FWHEADER_START,
                                      FIRMWARE_MAGIC_UPGRADING),
             "write upgrading marker failed");
    }
    // If current magic is already upgrading marker, do nothing
    flash_exit();
    erase_code_progress();
    flash_unlock_ex();
    msg_ctx.erase_target = UPGRADE_ERASE_TARGET_MCU;
    send_msg_success(dev);
    flash_state = STATE_FLASHSTART;
    timer_out_set(timer_out_oper, timer1s * 5);
    return sectrue;
  } else {
    send_msg_failure(dev, FAILURE_ACTION_CANCELLED, NULL);
    flash_state = STATE_END;
    show_unplug("Firmware installation", "aborted.");
    shutdown();
    return secfalse;
  }
}

// Helper function: Handle FirmwareErase_ex message (id 16)
static secbool handle_firmware_erase_ex(usbd_device *dev) {
  if (validate_preflight_erase_target(dev, UPGRADE_ERASE_TARGET_BLE) !=
      sectrue) {
    return secfalse;
  }
  layoutDialogCenterAdapterEx(NULL, &bmp_bottom_left_close,
                              &bmp_bottom_right_confirm, NULL, NULL, NULL,
                              "Install ble firmware by", "OneKey?");
  bool proceed = waitButtonResponse(BTN_PIN_YES, default_oper_time);
  if (proceed) {
    erase_ble_code_progress();
    flash_unlock_ex();
    msg_ctx.previous_state = UPGRADE_PREVIOUS_UNKNOWN;
    msg_ctx.previous_version = 0;
    msg_ctx.previous_purpose = FIRMWARE_PURPOSE_GENERAL;
    msg_ctx.erase_target = UPGRADE_ERASE_TARGET_BLE;
    send_msg_success(dev);
    flash_state = STATE_FLASHSTART;
    timer_out_set(timer_out_oper, timer1s * 5);
    return sectrue;
  } else {
    send_msg_failure(dev, FAILURE_ACTION_CANCELLED, NULL);
    flash_state = STATE_END;
    show_unplug("Firmware installation", "aborted.");
    shutdown();
    return secfalse;
  }
}

static secbool consume_upgrade_wrapper(usbd_device *dev, const uint8_t *data,
                                       uint32_t available, uint32_t *consumed) {
  if (msg_ctx.upgrade_header_pos > FLASH_FWHEADER_LEN) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Upgrade header", "overflow.");
    return secfalse;
  }

  uint32_t remaining = FLASH_FWHEADER_LEN - msg_ctx.upgrade_header_pos;
  uint32_t count = available < remaining ? available : remaining;

  if (msg_ctx.preflight_format == UPGRADE_FILE_FORMAT_NEW) {
    if (upgrade_header_chunk_matches(msg_ctx.upgrade_header_buffer, data,
                                     msg_ctx.upgrade_header_pos,
                                     count) != sectrue) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Upgrade header", "changed.");
      return secfalse;
    }
  } else {
    memcpy(msg_ctx.upgrade_header_buffer + msg_ctx.upgrade_header_pos, data,
           count);
  }

  msg_ctx.upgrade_header_pos += count;
  *consumed = count;
  if (msg_ctx.upgrade_header_pos == FLASH_FWHEADER_LEN) {
    const upgrade_file_header_t *wrapper =
        (const upgrade_file_header_t *)msg_ctx.upgrade_header_buffer;
    if (validate_upgrade_wrapper(dev, wrapper) != sectrue) {
      return secfalse;
    }
    if (upgrade_wrapper_payload_length_matches(wrapper, flash_len) != sectrue) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware payload",
                   "length mismatch.");
      return secfalse;
    }
    msg_ctx.upload_header_checked = sectrue;
  }
  return sectrue;
}

static secbool validate_uploaded_old_header(usbd_device *dev) {
  if (msg_ctx.upload_header_checked == sectrue ||
      msg_ctx.preflight_format != UPGRADE_FILE_FORMAT_OLD ||
      msg_ctx.upload_format != UPGRADE_FILE_FORMAT_OLD ||
      flash_pos < FLASH_FWHEADER_LEN) {
    return sectrue;
  }
  if (upgrade_header_chunk_matches(msg_ctx.upgrade_header_buffer,
                                   (const uint8_t *)firmware_header_buffer, 0,
                                   FLASH_FWHEADER_LEN) != sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware header", "changed.");
    return secfalse;
  }
  msg_ctx.upload_header_checked = sectrue;
  return sectrue;
}

static secbool validate_upload_target(usbd_device *dev) {
  upgrade_image_target_t image_target = UPGRADE_IMAGE_TARGET_NONE;
  if (update_mode == UPDATE_ST) {
    image_target = UPGRADE_IMAGE_TARGET_MCU;
  } else if (update_mode == UPDATE_BLE) {
    image_target = UPGRADE_IMAGE_TARGET_BLE;
  }

  if (upgrade_upload_target_allowed(msg_ctx.erase_target, image_target) !=
      sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Erase/upload type", "mismatch.");
    return secfalse;
  }

  if (msg_ctx.upload_wrapper_present == sectrue) {
    const upgrade_file_header_t *wrapper =
        (const upgrade_file_header_t *)msg_ctx.upgrade_header_buffer;
    if (upgrade_wrapper_target_allowed(wrapper->flags, image_target) !=
        sectrue) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware module", "mismatch.");
      return secfalse;
    }
  }
  return sectrue;
}

static secbool validate_wrapper_inner_metadata(usbd_device *dev) {
  if (msg_ctx.upload_wrapper_present != sectrue) {
    return sectrue;
  }

  const upgrade_file_header_t *wrapper =
      (const upgrade_file_header_t *)msg_ctx.upgrade_header_buffer;
  const image_header *inner = (const image_header *)firmware_header_buffer;
  secbool matches = secfalse;
  if (update_mode == UPDATE_ST) {
    matches = upgrade_mcu_metadata_matches(wrapper, inner);
  } else if (update_mode == UPDATE_BLE) {
    matches =
        upgrade_aux_metadata_matches(&wrapper->ble_info, inner, flash_len);
  }
  if (matches != sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware metadata", "mismatch.");
    return secfalse;
  }
  return sectrue;
}

// Helper function: Validate and initialize firmware upload
static secbool handle_firmware_upload_init(usbd_device *dev,
                                           const uint8_t *p_buf,
                                           secbool *se_isUpdate) {
  if (p_buf[9] != 0x0a) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Error installing", "firmware.");
    return secfalse;
  }

  *se_isUpdate = secfalse;
  flash_combine_pos = 0;

  // read payload length
  const uint8_t *p = p_buf + 10;
  if (readprotobufint(&p, &flash_len) != sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware is", "too big.");
    return secfalse;
  }

  if (p + sizeof(uint32_t) > p_buf + 64) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware format", "missing.");
    return secfalse;
  }

  uint32_t data_magic = 0;
  memcpy(&data_magic, p, sizeof(data_magic));
  upgrade_file_format_t actual_format = UPGRADE_FILE_FORMAT_NONE;
  if (data_magic == UPGRADE_HEADER_MAGIC) {
    actual_format = UPGRADE_FILE_FORMAT_NEW;
  } else if (data_magic == FIRMWARE_MAGIC_NEW ||
             data_magic == FIRMWARE_MAGIC_BLE) {
    actual_format = UPGRADE_FILE_FORMAT_OLD;
  } else if (msg_ctx.preflight_format == UPGRADE_FILE_FORMAT_OLD &&
             msg_ctx.header_in_fw_header == sectrue) {
    actual_format = UPGRADE_FILE_FORMAT_OLD_BODY;
  }

  if (upgrade_file_format_allowed(msg_ctx.preflight_format, actual_format) !=
      sectrue) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware format", "changed.");
    return secfalse;
  }

  msg_ctx.upload_format = actual_format;
  msg_ctx.upload_wrapper_present =
      actual_format == UPGRADE_FILE_FORMAT_NEW ? sectrue : secfalse;
  msg_ctx.has_upgrade_header = msg_ctx.upload_wrapper_present;

  uint32_t actual_firmware_len = flash_len;
  const uint8_t *firmware_start = NULL;
  if (actual_format == UPGRADE_FILE_FORMAT_OLD_BODY) {
    if (flash_len > UINT32_MAX - FLASH_FWHEADER_LEN) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware is", "too big.");
      return secfalse;
    }
    msg_ctx.upload_header_checked = sectrue;
    flash_len += FLASH_FWHEADER_LEN;
    actual_firmware_len = flash_len;
    firmware_start = (const uint8_t *)firmware_header_buffer;
  } else if (actual_format == UPGRADE_FILE_FORMAT_OLD) {
    msg_ctx.header_in_fw_header = secfalse;
    firmware_start = p;
  } else {
    msg_ctx.header_in_fw_header = secfalse;
    if (flash_len <= FLASH_FWHEADER_LEN) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware is", "too small.");
      return secfalse;
    }
    actual_firmware_len = flash_len - FLASH_FWHEADER_LEN;
    msg_ctx.upgrade_header_pos = 0;
    msg_ctx.upgrade_header_len = FLASH_FWHEADER_LEN;
    if (msg_ctx.preflight_format == UPGRADE_FILE_FORMAT_NONE) {
      memzero(msg_ctx.upgrade_header_buffer,
              sizeof(msg_ctx.upgrade_header_buffer));
    }
  }

  if (firmware_start != NULL) {
    if (check_firmware_magic(firmware_start) != sectrue) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Wrong firmware", "header.");
      return secfalse;
    }
    update_mode = get_update_mode_from_magic(firmware_start);
    if (validate_upload_target(dev) != sectrue) {
      return secfalse;
    }
    if (update_mode == UPDATE_ST &&
        memcmp(firmware_start + 24, HW_MODEL_C2B2, 4) != 0) {
      handle_error(dev, FAILURE_PROCESS_ERROR, "Wrong hardware model",
                   "header.");
      return secfalse;
    }
  }

  if (actual_firmware_len <= FLASH_FWHEADER_LEN) {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware is", "too small.");
    return secfalse;
  }

  if (firmware_start != NULL) {
    if (UPDATE_ST == update_mode) {
      if (actual_firmware_len > FLASH_FWHEADER_LEN + FLASH_APP_LEN) {
        handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware is", "too big");
        return secfalse;
      }
    } else if (UPDATE_BLE == update_mode) {
      if (actual_firmware_len > FLASH_FWHEADER_LEN + FLASH_BLE_MAX_LEN) {
        handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware is", "too big.");
        return secfalse;
      }
    }
  }

  // From this point onward flash_len always describes the inner module payload,
  // never the optional 1024-byte upgrade wrapper.
  flash_len = actual_firmware_len;

  if (msg_ctx.header_in_fw_header != sectrue) {
    memzero(firmware_header_buffer, sizeof(firmware_header_buffer));
  }
  flash_state = STATE_FLASHING;
  flash_pos = 0;
  msg_ctx.w = 0;
  msg_ctx.wi = 0;
  const uint8_t *data_ptr = p;

  if (msg_ctx.header_in_fw_header == sectrue) {
    flash_pos = FLASH_FWHEADER_LEN;
    data_ptr = p;  // Start from beginning of data (firmware data starts here)

    // Process firmware data from first packet
    // For MCU: store first 4KB in buffer (sector 4's first 4KB is not erased)
    // For BLE: can write directly after 1KB header (sector is fully erased)
    uint32_t buffer_size =
        (UPDATE_BLE == update_mode) ? 0 : FIRMWARE_HEADER_BUFFER_SIZE;
    while (data_ptr < p_buf + 64) {
      // Process firmware data
      msg_ctx.w = (msg_ctx.w >> 8) | (((uint32_t)*data_ptr) << 24);
      msg_ctx.wi++;
      if (msg_ctx.wi == 4) {
        if (UPDATE_ST == update_mode && flash_pos < buffer_size) {
          // Store in buffer for MCU (first 4KB)
          firmware_header_buffer[flash_pos / 4] = msg_ctx.w;
        } else {
          // Write to Flash immediately (BLE or MCU after buffer)
          flash_enter();
          if (UPDATE_ST == update_mode) {
            ensure(flash_write_word_item_ex(FLASH_FWHEADER_START + flash_pos,
                                            msg_ctx.w),
                   "flash write error");
          } else {
            ensure(flash_write_word_item_ex(FLASH_BLE_SE_ADDR_START + flash_pos,
                                            msg_ctx.w),
                   "flash write error");
          }
          flash_exit();
        }
        flash_pos += 4;
        msg_ctx.wi = 0;
      }
      data_ptr++;
    }
  } else {
    uint32_t bytes_available = (uint32_t)((p_buf + 64) - p);

    if (actual_format == UPGRADE_FILE_FORMAT_NEW) {
      uint32_t consumed = 0;
      if (consume_upgrade_wrapper(dev, data_ptr, bytes_available, &consumed) !=
          sectrue) {
        return secfalse;
      }
      data_ptr += consumed;
    }

    while (data_ptr < p_buf + 64) {
      // Process firmware data
      msg_ctx.w = (msg_ctx.w >> 8) | (((uint32_t)*data_ptr) << 24);
      msg_ctx.wi++;
      if (msg_ctx.wi == 4) {
        // For MCU: store first 4KB in buffer (sector 4's first 4KB is not
        // erased) For BLE: store first 1KB in buffer (sector is fully erased,
        // can write after 1KB)
        uint32_t buffer_size = (UPDATE_BLE == update_mode)
                                   ? FLASH_FWHEADER_LEN
                                   : FIRMWARE_HEADER_BUFFER_SIZE;
        if (flash_pos < buffer_size) {
          firmware_header_buffer[flash_pos / 4] = msg_ctx.w;
        } else {
          // After buffer, write directly to flash
          flash_enter();
          if (UPDATE_ST == update_mode) {
            ensure(flash_write_word_item_ex(FLASH_FWHEADER_START + flash_pos,
                                            msg_ctx.w),
                   "flash write error");
          } else {
            ensure(flash_write_word_item_ex(FLASH_BLE_SE_ADDR_START + flash_pos,
                                            msg_ctx.w),
                   "flash write error");
          }
          flash_exit();
        }
        flash_pos += 4;
        msg_ctx.wi = 0;
      }
      data_ptr++;
    }
  }

  if (validate_uploaded_old_header(dev) != sectrue) {
    return secfalse;
  }

  return sectrue;
}

// Helper function: Process firmware flashing data
static secbool process_flashing_data(usbd_device *dev, const uint8_t *p_buf,
                                     uint32_t *w, int *wi,
                                     secbool *se_isUpdate) {
  if (p_buf[0] != '?') {
    handle_error(dev, FAILURE_PROCESS_ERROR, "Error installing", "firmware.");
    return secfalse;
  }

  timer_out_set(timer_out_oper, timer1s * 5);
  static uint8_t flash_anim = 0;
  if (flash_anim % 32 == 4) {
    layoutProgress("Installing...", 1000 * flash_pos / flash_len);
  }
  flash_anim++;

  const uint8_t *p = p_buf + 1;
  static secbool firmware_magic_checked = sectrue;

  if (msg_ctx.upload_format == UPGRADE_FILE_FORMAT_NEW &&
      msg_ctx.upgrade_header_pos < msg_ctx.upgrade_header_len) {
    firmware_magic_checked = secfalse;
    uint32_t consumed = 0;
    if (consume_upgrade_wrapper(dev, p, (uint32_t)((p_buf + 64) - p),
                                &consumed) != sectrue) {
      return secfalse;
    }
    p += consumed;
    if (msg_ctx.upgrade_header_pos < msg_ctx.upgrade_header_len) {
      return sectrue;
    }
  }

  if (firmware_magic_checked == secfalse) {
    // header start position

    while (p < p_buf + 64 && flash_pos < FLASH_FWHEADER_LEN &&
           flash_pos < flash_len) {
      *w = ((*w) >> 8) | (((uint32_t)*p) << 24);
      (*wi)++;
      if (*wi == 4) {
        firmware_header_buffer[flash_pos / 4] = *w;
        flash_pos += 4;
        *wi = 0;
      }
      p++;
    }

    if (flash_pos >= FLASH_FWHEADER_LEN) {
      if (check_firmware_magic((const uint8_t *)firmware_header_buffer) !=
          sectrue) {
        handle_error(dev, FAILURE_PROCESS_ERROR, "Wrong firmware", "header.");
        return secfalse;
      }
      update_mode =
          get_update_mode_from_magic((const uint8_t *)firmware_header_buffer);
      if (validate_upload_target(dev) != sectrue) {
        return secfalse;
      }
      if (validate_wrapper_inner_metadata(dev) != sectrue) {
        return secfalse;
      }
      // Validate hardware model for UPDATE_ST
      if (update_mode == UPDATE_ST) {
        if (memcmp((const uint8_t *)firmware_header_buffer + 24, HW_MODEL_C2B2,
                   4) != 0) {
          handle_error(dev, FAILURE_PROCESS_ERROR, "Wrong hardware model",
                       "header.");
          return secfalse;
        }
      }
      firmware_magic_checked = sectrue;
    }
    if (flash_pos < FLASH_FWHEADER_LEN) {
      return validate_uploaded_old_header(dev);
    }
  }

  while (p < p_buf + 64 && flash_pos < flash_len) {
    *w = ((*w) >> 8) | (((uint32_t)*p) << 24);
    (*wi)++;
    if (*wi == 4) {
      // For MCU: store first 4KB in buffer (sector 4's first 4KB is not erased)
      // For BLE: store first 1KB in buffer (sector is fully erased, can write
      // after 1KB) For SE: store in COMBINED_FW_HEADER
      uint32_t buffer_size = (UPDATE_BLE == update_mode)
                                 ? FLASH_FWHEADER_LEN
                                 : FIRMWARE_HEADER_BUFFER_SIZE;
      if (flash_pos < buffer_size) {
        firmware_header_buffer[flash_pos / 4] = *w;
      } else {
        // After buffer, write directly to flash
        // mcu or bluetooth firmware update
        if (UPDATE_ST == update_mode || UPDATE_BLE == update_mode) {
          image_header *hdr = (image_header *)firmware_header_buffer;
          if (flash_pos < hdr->codelen + FLASH_FWHEADER_LEN) {
            flash_enter();
            if (UPDATE_ST == update_mode) {
              ensure(flash_write_word_item_ex(FLASH_FWHEADER_START + flash_pos,
                                              *w),
                     "flash write error");
            } else {
              ensure(flash_write_word_item_ex(
                         FLASH_BLE_SE_ADDR_START + flash_pos, *w),
                     "flash write error");
            }
            flash_exit();
          } else {  // se firmware update
                    // first w is FIRMWARE_MAGIC_SE it need strict judge
            if (*w != FIRMWARE_MAGIC_SE && flash_combine_pos == 0) {
              show_unplug("Firmware error", NULL);
              shutdown();
              return secfalse;
            }
            *se_isUpdate = sectrue;
            if (flash_combine_pos < FLASH_FWHEADER_LEN) {
              COMBINED_FW_HEADER[flash_combine_pos / 4] = *w;
              flash_combine_pos += 4;
            } else {
              flash_write_word_item_ex(
                  FLASH_BLE_SE_ADDR_START + flash_combine_pos, *w);
              flash_combine_pos += 4;
            }
          }
        }
      }
      flash_pos += 4;
      *wi = 0;
    }
    p++;
  }

  return validate_uploaded_old_header(dev);
}

static void rx_callback(usbd_device *dev, uint8_t ep) {
  (void)ep;
  uint8_t *p_buf = packet_buf;

  (void)(send_msg_buttonrequest_firmwarecheck);

  // Read packet from USB or use I2C buffer
  if (dev != NULL) {
    if (usbd_ep_read_packet(dev, ENDPOINT_ADDRESS_OUT, packet_buf, 64) != 64)
      return;
    host_channel = CHANNEL_USB;
    // Reset interrupt state if needed
    if (flash_state == STATE_INTERRPUPT) {
      flash_state = STATE_READY;
      flash_pos = 0;
    }
  } else {
    host_channel = CHANNEL_SLAVE;
  }

  // Early return if in end state
  if (flash_state == STATE_END) {
    return;
  }

  // Parse message header for states that need it
  // as subsequent packets only contain data with '?' prefix
  if (flash_state == STATE_READY || flash_state == STATE_OPEN ||
      flash_state == STATE_FLASHSTART || flash_state == STATE_CHECK ||
      flash_state == STATE_INTERRPUPT) {
    if (parse_message_header(p_buf, &msg_ctx.msg_id, &msg_ctx.msg_size) !=
        sectrue) {
      return;  // Invalid header, discard packet
    }
  }

  // Handle messages in READY or OPEN state
  if (flash_state == STATE_READY || flash_state == STATE_OPEN) {
    // Handle simple messages (Initialize, Ping, GetFeatures)
    if (handle_simple_messages(dev, msg_ctx.msg_id) == sectrue) {
      return;
    }

    // Handle WipeDevice message
    if (msg_ctx.msg_id == MSG_ID_WIPE_DEVICE) {
      handle_wipe_device(dev);
      return;
    }

    // Handle UpgradeFileHeader message
    if (msg_ctx.msg_id == MSG_ID_UPGRADE_FILE_HEADER) {
      if (process_upgrade_file_header_packet(dev, p_buf) != sectrue) {
        reset_upgrade_header_state();
        return;
      }
      return;
    }

    // Handle messages in OPEN state
    if (flash_state == STATE_OPEN) {
      if (msg_ctx.msg_id == MSG_ID_FIRMWARE_ERASE) {
        msg_ctx.erase_storage = secfalse;
        if (handle_firmware_erase(dev, &msg_ctx.old_was_signed,
                                  &msg_ctx.fix_version_current,
                                  &msg_ctx.previous_purpose) == sectrue) {
          return;
        }
        return;
      } else if (msg_ctx.msg_id == MSG_ID_FIRMWARE_ERASE_EX) {
        if (handle_firmware_erase_ex(dev) == sectrue) {
          return;
        }
        return;
      }
      send_msg_failure(dev, FAILURE_UNEXPECTED_MESSAGE, NULL);
      return;
    }
  }

  if (flash_state == STATE_UPGRADE_HEADER) {
    if (process_upgrade_file_header_packet(dev, p_buf) != sectrue) {
      reset_upgrade_header_state();
      return;
    }
  }

  // Handle FLASHSTART state
  if (flash_state == STATE_FLASHSTART) {
    if (msg_ctx.msg_id == MSG_ID_INITIALIZE) {  // end resume state
      reset_update_session_state();
      send_msg_features(dev);
      flash_state = STATE_OPEN;
      flash_pos = 0;
      return;
    } else if (msg_ctx.msg_id == MSG_ID_FIRMWARE_UPLOAD) {
      handle_firmware_upload_init(dev, p_buf, &msg_ctx.se_isUpdate);
      return;
    }
    send_msg_failure(dev, FAILURE_UNEXPECTED_MESSAGE, NULL);
    return;
  }

  // Handle INTERRUPT state
  if (flash_state == STATE_INTERRPUPT) {
    if (msg_ctx.msg_id == MSG_ID_INITIALIZE) {
      send_msg_failure(dev, FAILURE_PROCESS_ERROR, NULL);
      flash_state = STATE_FLASHSTART;
      timer_out_set(timer_out_oper, timer1s * 5);
      return;
    }
  }

  // Handle FLASHING state
  if (flash_state == STATE_FLASHING) {
    if (process_flashing_data(dev, p_buf, &msg_ctx.w, &msg_ctx.wi,
                              &msg_ctx.se_isUpdate) != sectrue) {
      return;
    }
    // Check if flashing is complete and handle verification
    if (flash_pos >= flash_len) {
      // Reset static variables for next upload
      // (firmware_magic_checked will be reset on next call)
      flash_state = STATE_CHECK;
      if (UPDATE_ST == update_mode) {
        const image_header *hdr = (const image_header *)firmware_header_buffer;
        image_header se_hdr = {0};
        // allow only v3 signmessage/verifymessage signature for new FW
        if (SIG_OK != signatures_ok(hdr, NULL, sectrue)) {
          handle_error(dev, FAILURE_PROCESS_ERROR, "Signatures is", "wrong.");
          return;
        }

        if (SIG_OK !=
            check_firmware_hashes(
                hdr,
                (const uint8_t *)firmware_header_buffer + FLASH_FWHEADER_LEN,
                FIRMWARE_HEADER_BUFFER_SIZE - FLASH_FWHEADER_LEN)) {
          handle_error(dev, FAILURE_PROCESS_ERROR, "Broken firmware",
                       "detected.");
          return;
        }

        if (memcmp((const uint8_t *)hdr + 24, HW_MODEL_C2B2, 4) != 0) {
          handle_error(dev, FAILURE_PROCESS_ERROR, "Wrong hardware model",
                       "header.");
          return;
        }

        if (msg_ctx.upload_wrapper_present == sectrue) {
          const upgrade_file_header_t *wrapper =
              (const upgrade_file_header_t *)msg_ctx.upgrade_header_buffer;
          if (msg_ctx.upload_header_checked != sectrue ||
              upgrade_mcu_metadata_matches(wrapper, hdr) != sectrue) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware metadata",
                         "mismatch.");
            return;
          }
          if (upgrade_wrapper_payload_allowed(wrapper->flags,
                                              UPGRADE_IMAGE_TARGET_MCU,
                                              msg_ctx.se_isUpdate) != sectrue) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "Firmware modules",
                         "mismatch.");
            return;
          }
        }

        if (msg_ctx.se_isUpdate == sectrue) {
          if (!load_thd89_image_header((uint8_t *)COMBINED_FW_HEADER,
                                       FIRMWARE_MAGIC_SE, &se_hdr)) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "SE firmware",
                         "header invalid.");
            return;
          }
          if (msg_ctx.upload_wrapper_present == sectrue) {
            const upgrade_file_header_t *wrapper =
                (const upgrade_file_header_t *)msg_ctx.upgrade_header_buffer;
            if (upgrade_aux_metadata_matches(&wrapper->se_info, &se_hdr,
                                             flash_combine_pos) != sectrue) {
              handle_error(dev, FAILURE_PROCESS_ERROR, "SE metadata",
                           "mismatch.");
              return;
            }
          }
        }

        if (check_mcu_install(dev, hdr->onekey_version,
                              msg_ctx.previous_version, hdr->purpose,
                              msg_ctx.previous_purpose) != sectrue) {
          return;
        }

        char *se_version = se_get_version();
        if (se_version == NULL) {
          handle_error(dev, FAILURE_PROCESS_ERROR, "SE version", "not found.");
          return;
        }

        uint32_t se_version_uint32 = 0;
        if (msg_ctx.se_isUpdate) {
          se_version_uint32 = version_string_to_int(se_version);
          if (upgrade_version_compare(se_hdr.version, se_version_uint32) < 0) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "Downgrade SE",
                         "not allowed.");
            return;
          }
          se_version_uint32 = se_hdr.version;
        } else {
          se_version_uint32 = version_string_to_int(se_version);
        }
        if (hdr->se_minimum_version != 0) {
          if (upgrade_version_compare(se_version_uint32,
                                      hdr->se_minimum_version) < 0) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "SE version", "too old.");
            return;
          }
        }

        if (hdr->purpose != msg_ctx.previous_purpose) {
          msg_ctx.erase_storage = sectrue;
        }

        if (msg_ctx.se_isUpdate) {
          if (!se_back_to_boot_progress()) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "SE back to boot",
                         "error.");
            return;
          }
          if (!se_verify_firmware((uint8_t *)COMBINED_FW_HEADER,
                                  FLASH_FWHEADER_LEN, se_hdr.codelen)) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "SE verify header",
                         "error.");
            return;
          }

          // install
          if (!se_update_firmware(
                  (uint8_t *)(FLASH_BLE_SE_ADDR_START + FLASH_FWHEADER_LEN),
                  se_hdr.codelen, layoutProgress)) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "SE update", "error.");
            return;
          }
          if (!se_check_firmware()) {
            handle_error(dev, FAILURE_PROCESS_ERROR, "Update SE", "aborted.");
            return;
          }
          if (!se_active_app_progress()) {
            flash_state = STATE_END;
            show_unplug("Update SE", "aborted.");
            send_msg_failure(dev, FAILURE_ACTION_CANCELLED, NULL);
            shutdown();
            return;
          }
        }
      }
    }
  }

  // Handle CHECK state
  if (flash_state == STATE_CHECK) {
    timer_out_set(timer_out_oper, 0);
    if (UPDATE_ST == update_mode) {
      // use the firmware header from buffer
      const image_header *hdr = (const image_header *)firmware_header_buffer;

      bool hash_check_ok;
      // show fingerprint of unsigned firmware
      if (SIG_OK != signatures_ok(hdr, NULL, sectrue)) {
        if (msg_ctx.msg_id != MSG_ID_BUTTON_ACK) {
          return;
        }
        // OneKey not allowed Unofficial firmware
        hash_check_ok = false;
      } else {
        hash_check_ok = true;
      }
      layoutProgress("Programing...", 1000);

      (void)should_keep_storage(msg_ctx.old_was_signed,
                                msg_ctx.fix_version_current);

      if (msg_ctx.erase_storage) {
        if (!se_erase_storage_plaintext()) {
          handle_error(dev, FAILURE_PROCESS_ERROR, "SE erase", "error.");
          return;
        }
      }

      flash_enter();
      // write firmware header only when hash was confirmed
      if (hash_check_ok) {
        // Erase the page first (to clear upgrading marker if present)
        ensure(flash_page_erase(FLASH_FWHEADER_START), "page erase failed");
        for (size_t i = 0; i < FIRMWARE_HEADER_BUFFER_SIZE / sizeof(uint32_t);
             i++) {
          flash_write_word_item_ex(FLASH_FWHEADER_START + i * sizeof(uint32_t),
                                   firmware_header_buffer[i]);
        }
      }
      flash_exit();
      flash_state = STATE_END;
      if (hash_check_ok) {
        send_msg_success(dev);
        layoutDialogCenterAdapterEx(&bmp_icon_ok, NULL, NULL, NULL,
                                    "New firmware installed.",
                                    "Device will be power off.", NULL, NULL);
        shutdown();
      } else {
        layoutDialogCenterAdapterEx(
            &bmp_icon_warning, NULL, NULL, NULL, "Installation Aborted!",
            "Repeat the procedure with", "OneKey official firmware", NULL);
        send_msg_failure(dev, FAILURE_PROCESS_ERROR, NULL);
        shutdown();
      }
      return;
    } else if (UPDATE_BLE == update_mode) {
      if (msg_ctx.upload_wrapper_present == sectrue) {
        const upgrade_file_header_t *wrapper =
            (const upgrade_file_header_t *)msg_ctx.upgrade_header_buffer;
        const image_header *ble_hdr =
            (const image_header *)firmware_header_buffer;
        if (msg_ctx.upload_header_checked != sectrue ||
            upgrade_wrapper_payload_allowed(wrapper->flags,
                                            UPGRADE_IMAGE_TARGET_BLE,
                                            secfalse) != sectrue ||
            upgrade_aux_metadata_matches(&wrapper->ble_info, ble_hdr,
                                         flash_len) != sectrue) {
          handle_error(dev, FAILURE_PROCESS_ERROR, "BLE metadata", "mismatch.");
          return;
        }
      }
      flash_state = STATE_END;
      i2c_set_wait(false);
      send_msg_success(dev);
      layoutProgress("Updating ... Please wait", 1000);
      delay_ms(500);  // important!!! delay for nordic reset

      uint32_t fw_len = flash_len - FLASH_FWHEADER_LEN;
      bool update_status = false;
#if BLE_SWD_UPDATE
      update_status = bUBLE_UpdateBleFirmware(
          fw_len, FLASH_BLE_SE_ADDR_START + FLASH_FWHEADER_LEN, ERASE_ALL);

#else
      uint8_t *p_init = (uint8_t *)FLASH_INIT_DATA_START;
      uint32_t init_data_len = p_init[0] + (p_init[1] << 8);
#if NORDIC_BLE_UPDATE
      update_status = updateBle(p_init + 4, init_data_len,
                                (uint8_t *)FLASH_BLE_FIRMWARE_START,
                                fw_len - FLASH_INIT_DATA_LEN);
#else
      (void)fw_len;
      (void)init_data_len;
      update_status = false;
#endif
#endif
      if (update_status == false) {
        layoutDialogCenterAdapterEx(
            &bmp_icon_warning, NULL, NULL, NULL, "ble installation aborted!",
            "Repeat the procedure with", "OneKey official firmware", NULL);
      } else {
        show_unplug("ble firmware", "successfully installed.");
      }
      delay_ms(1000);
      shutdown();
    } else {
      send_msg_success(dev);
      show_unplug("se firmware", "successfully installed.");
      delay_ms(500);
      shutdown();
    }
  }
}
static void set_config(usbd_device *dev, uint16_t wValue) {
  (void)wValue;

  usbd_ep_setup(dev, ENDPOINT_ADDRESS_IN, USB_ENDPOINT_ATTR_INTERRUPT, 64, 0);
  usbd_ep_setup(dev, ENDPOINT_ADDRESS_OUT, USB_ENDPOINT_ATTR_INTERRUPT, 64,
                rx_callback);
}

static usbd_device *usbd_dev;
static uint8_t usbd_control_buffer[256] __attribute__((aligned(2)));

static const struct usb_device_capability_descriptor *capabilities_landing[] = {
    (const struct usb_device_capability_descriptor
         *)&webusb_platform_capability_descriptor_landing,
};

static const struct usb_device_capability_descriptor
    *capabilities_no_landing[] = {
        (const struct usb_device_capability_descriptor
             *)&webusb_platform_capability_descriptor_no_landing,
};

static const struct usb_bos_descriptor bos_descriptor_landing = {
    .bLength = USB_DT_BOS_SIZE,
    .bDescriptorType = USB_DT_BOS,
    .bNumDeviceCaps =
        sizeof(capabilities_landing) / sizeof(capabilities_landing[0]),
    .capabilities = capabilities_landing};

static const struct usb_bos_descriptor bos_descriptor_no_landing = {
    .bLength = USB_DT_BOS_SIZE,
    .bDescriptorType = USB_DT_BOS,
    .bNumDeviceCaps =
        sizeof(capabilities_no_landing) / sizeof(capabilities_no_landing[0]),
    .capabilities = capabilities_no_landing};

static void usbInit(bool firmware_present) {
  usbd_dev = usbd_init(&otgfs_usb_driver_onekey, &dev_descr, &config,
                       usb_strings, sizeof(usb_strings) / sizeof(const char *),
                       usbd_control_buffer, sizeof(usbd_control_buffer));
  usbd_register_set_config_callback(usbd_dev, set_config);
  usb21_setup(usbd_dev, firmware_present ? &bos_descriptor_no_landing
                                         : &bos_descriptor_landing);
  webusb_setup(usbd_dev, "onekey.so");
  winusb_setup(usbd_dev, USB_INTERFACE_INDEX_MAIN);
}

static void checkButtons(void) {
  static bool btn_left = false, btn_right = false, btn_final = false;
  if (btn_final) {
    return;
  }
  uint16_t state = gpio_get(BTN_PORT, BTN_PIN_YES);
  state |= gpio_get(BTN_PORT_NO, BTN_PIN_NO);
  if ((btn_left == false) && (state & BTN_PIN_NO)) {
    btn_left = true;
    oledBox(0, 0, 3, 3, true);
    oledRefresh();
  }
  if ((btn_right == false) && (state & BTN_PIN_YES) != BTN_PIN_YES) {
    btn_right = true;
    oledBox(OLED_WIDTH - 4, 0, OLED_WIDTH - 1, 3, true);
    oledRefresh();
  }
  if (btn_left && btn_right) {
    btn_final = true;
  }
}

static void i2cSlavePoll(void) {
  volatile uint32_t total_len, len;
  if (i2c_recv_done) {
    while (1) {
      total_len = fifo_lockdata_len(&i2c_fifo_in);
      if (total_len == 0) break;
      len = total_len > 64 ? 64 : total_len;
      fifo_read_lock(&i2c_fifo_in, packet_buf, len);
      rx_callback(NULL, 0);
    }
    i2c_recv_done = false;
  }
}

void usbLoop(void) {
  bool firmware_present = firmware_present_new();
  usbInit(firmware_present);
  for (;;) {
    ble_update_poll();
    usbd_poll(usbd_dev);
    i2cSlavePoll();
    if (!firmware_present &&
        (flash_state == STATE_READY || flash_state == STATE_OPEN)) {
      checkButtons();
    }
    if (flash_state == STATE_FLASHSTART || flash_state == STATE_FLASHING) {
      if (checkButtonOrTimeout(BTN_PIN_NO, timer_out_oper)) {
        flash_state = STATE_INTERRPUPT;
        fifo_flush(&i2c_fifo_in);
        layoutRefreshSet(true);
      }
    }
    if (flash_state == STATE_READY || flash_state == STATE_OPEN ||
        flash_state == STATE_INTERRPUPT)
      layoutBootHome();
  }
}
