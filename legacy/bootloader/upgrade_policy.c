#include "upgrade_policy.h"

#include <limits.h>
#include <string.h>

_Static_assert(sizeof(upgrade_file_header_t) == UPGRADE_POLICY_HEADER_SIZE,
               "upgrade header size changed");
_Static_assert(sizeof(image_header) == UPGRADE_POLICY_HEADER_SIZE,
               "firmware header size changed");

int upgrade_version_compare(uint32_t vera, uint32_t verb) {
  for (uint32_t shift = 0; shift < 32; shift += 8) {
    int a = (int)((vera >> shift) & 0xffU);
    int b = (int)((verb >> shift) & 0xffU);
    if (a != b) {
      return a - b;
    }
  }
  return 0;
}

secbool upgrade_file_format_allowed(upgrade_file_format_t preflight,
                                    upgrade_file_format_t upload) {
  switch (preflight) {
    case UPGRADE_FILE_FORMAT_NONE:
      return (upload == UPGRADE_FILE_FORMAT_OLD ||
              upload == UPGRADE_FILE_FORMAT_NEW)
                 ? sectrue
                 : secfalse;
    case UPGRADE_FILE_FORMAT_OLD:
      return (upload == UPGRADE_FILE_FORMAT_OLD ||
              upload == UPGRADE_FILE_FORMAT_OLD_BODY)
                 ? sectrue
                 : secfalse;
    case UPGRADE_FILE_FORMAT_NEW:
      return upload == UPGRADE_FILE_FORMAT_NEW ? sectrue : secfalse;
    default:
      return secfalse;
  }
}

secbool upgrade_header_chunk_matches(const uint8_t *expected,
                                     const uint8_t *actual, size_t offset,
                                     size_t length) {
  if (expected == NULL || actual == NULL ||
      offset > UPGRADE_POLICY_HEADER_SIZE ||
      length > UPGRADE_POLICY_HEADER_SIZE - offset) {
    return secfalse;
  }
  return memcmp(expected + offset, actual, length) == 0 ? sectrue : secfalse;
}

secbool upgrade_mcu_metadata_matches(const upgrade_file_header_t *wrapper,
                                     const image_header *image) {
  if (wrapper == NULL || image == NULL ||
      (wrapper->flags & UPGRADE_FLAG_MCU_PRESENT) == 0 ||
      image->codelen > UINT32_MAX - UPGRADE_POLICY_HEADER_SIZE) {
    return secfalse;
  }

  const module_upgrade_info_t *mcu = &wrapper->mcu_info;
  if (mcu->version != image->onekey_version || mcu->purpose != image->purpose ||
      mcu->se_minimum_version != image->se_minimum_version ||
      mcu->length != UPGRADE_POLICY_HEADER_SIZE + image->codelen) {
    return secfalse;
  }
  return sectrue;
}

secbool upgrade_mcu_downgrade_allowed(uint32_t new_version,
                                      uint32_t current_version,
                                      uint32_t new_purpose,
                                      uint32_t current_purpose) {
  if (current_version == 0 ||
      upgrade_version_compare(new_version, current_version) >= 0) {
    return sectrue;
  }
  return (current_purpose == FIRMWARE_PURPOSE_GENERAL &&
          new_purpose == FIRMWARE_PURPOSE_BTC_ONLY)
             ? sectrue
             : secfalse;
}

secbool upgrade_mcu_install_allowed(upgrade_previous_state_t previous_state,
                                    uint32_t new_version,
                                    uint32_t current_version,
                                    uint32_t new_purpose,
                                    uint32_t current_purpose) {
  switch (previous_state) {
    case UPGRADE_PREVIOUS_EMPTY:
      return sectrue;
    case UPGRADE_PREVIOUS_VERIFIED:
      return upgrade_mcu_downgrade_allowed(new_version, current_version,
                                           new_purpose, current_purpose);
    case UPGRADE_PREVIOUS_UNKNOWN:
    default:
      return secfalse;
  }
}

secbool upgrade_upload_target_allowed(upgrade_erase_target_t erase_target,
                                      upgrade_image_target_t image_target) {
  return ((erase_target == UPGRADE_ERASE_TARGET_MCU &&
           image_target == UPGRADE_IMAGE_TARGET_MCU) ||
          (erase_target == UPGRADE_ERASE_TARGET_BLE &&
           image_target == UPGRADE_IMAGE_TARGET_BLE))
             ? sectrue
             : secfalse;
}

upgrade_image_target_t upgrade_wrapper_image_target(uint8_t flags) {
  switch (flags) {
    case UPGRADE_FLAG_MCU_PRESENT:
    case UPGRADE_FLAG_MCU_PRESENT | UPGRADE_FLAG_SE_PRESENT:
      return UPGRADE_IMAGE_TARGET_MCU;
    case UPGRADE_FLAG_BLE_PRESENT:
      return UPGRADE_IMAGE_TARGET_BLE;
    default:
      return UPGRADE_IMAGE_TARGET_NONE;
  }
}

secbool upgrade_preflight_erase_allowed(
    upgrade_file_format_t preflight_format,
    upgrade_image_target_t preflight_target,
    upgrade_erase_target_t requested_erase_target) {
  if (requested_erase_target != UPGRADE_ERASE_TARGET_MCU &&
      requested_erase_target != UPGRADE_ERASE_TARGET_BLE) {
    return secfalse;
  }

  switch (preflight_format) {
    case UPGRADE_FILE_FORMAT_NONE:
      return preflight_target == UPGRADE_IMAGE_TARGET_NONE ? sectrue : secfalse;
    case UPGRADE_FILE_FORMAT_OLD:
    case UPGRADE_FILE_FORMAT_NEW:
      return upgrade_upload_target_allowed(requested_erase_target,
                                           preflight_target);
    case UPGRADE_FILE_FORMAT_OLD_BODY:
    default:
      return secfalse;
  }
}

secbool upgrade_wrapper_target_allowed(uint8_t flags,
                                       upgrade_image_target_t image_target) {
  if (image_target == UPGRADE_IMAGE_TARGET_MCU) {
    return (flags == UPGRADE_FLAG_MCU_PRESENT ||
            flags == (UPGRADE_FLAG_MCU_PRESENT | UPGRADE_FLAG_SE_PRESENT))
               ? sectrue
               : secfalse;
  }
  if (image_target == UPGRADE_IMAGE_TARGET_BLE) {
    return flags == UPGRADE_FLAG_BLE_PRESENT ? sectrue : secfalse;
  }
  return secfalse;
}

secbool upgrade_wrapper_payload_allowed(uint8_t flags,
                                        upgrade_image_target_t image_target,
                                        secbool se_present) {
  if (upgrade_wrapper_target_allowed(flags, image_target) != sectrue) {
    return secfalse;
  }
  if (image_target == UPGRADE_IMAGE_TARGET_MCU) {
    secbool expects_se =
        (flags & UPGRADE_FLAG_SE_PRESENT) != 0 ? sectrue : secfalse;
    return expects_se == se_present ? sectrue : secfalse;
  }
  return se_present == secfalse ? sectrue : secfalse;
}

secbool upgrade_wrapper_payload_length_matches(
    const upgrade_file_header_t *wrapper, uint32_t payload_length) {
  if (wrapper == NULL) {
    return secfalse;
  }

  uint32_t expected_length = 0;
  switch (wrapper->flags) {
    case UPGRADE_FLAG_MCU_PRESENT:
      expected_length = wrapper->mcu_info.length;
      break;
    case UPGRADE_FLAG_MCU_PRESENT | UPGRADE_FLAG_SE_PRESENT:
      if (wrapper->mcu_info.length > UINT32_MAX - wrapper->se_info.length) {
        return secfalse;
      }
      expected_length = wrapper->mcu_info.length + wrapper->se_info.length;
      break;
    case UPGRADE_FLAG_BLE_PRESENT:
      expected_length = wrapper->ble_info.length;
      break;
    default:
      return secfalse;
  }
  return expected_length == payload_length ? sectrue : secfalse;
}

static secbool upgrade_module_length_allowed(uint32_t length,
                                             uint32_t maximum) {
  return (length > UPGRADE_POLICY_HEADER_SIZE && length <= maximum &&
          (length & (sizeof(uint32_t) - 1U)) == 0)
             ? sectrue
             : secfalse;
}

secbool upgrade_wrapper_declared_lengths_allowed(
    const upgrade_file_header_t *wrapper, uint32_t max_mcu_length,
    uint32_t max_aux_length) {
  if (wrapper == NULL || max_mcu_length <= UPGRADE_POLICY_HEADER_SIZE ||
      max_aux_length <= UPGRADE_POLICY_HEADER_SIZE) {
    return secfalse;
  }

  switch (wrapper->flags) {
    case UPGRADE_FLAG_MCU_PRESENT:
      return upgrade_module_length_allowed(wrapper->mcu_info.length,
                                           max_mcu_length);
    case UPGRADE_FLAG_MCU_PRESENT | UPGRADE_FLAG_SE_PRESENT:
      return (upgrade_module_length_allowed(wrapper->mcu_info.length,
                                            max_mcu_length) == sectrue &&
              upgrade_module_length_allowed(wrapper->se_info.length,
                                            max_aux_length) == sectrue)
                 ? sectrue
                 : secfalse;
    case UPGRADE_FLAG_BLE_PRESENT:
      return upgrade_module_length_allowed(wrapper->ble_info.length,
                                           max_aux_length);
    default:
      return secfalse;
  }
}

secbool upgrade_aux_metadata_matches(const module_upgrade_info_t *module,
                                     const image_header *image,
                                     uint32_t actual_length) {
  if (module == NULL || image == NULL ||
      image->codelen > UINT32_MAX - UPGRADE_POLICY_HEADER_SIZE) {
    return secfalse;
  }
  uint32_t image_length = UPGRADE_POLICY_HEADER_SIZE + image->codelen;
  return (module->version == image->version && module->length == image_length &&
          actual_length == image_length)
             ? sectrue
             : secfalse;
}

secbool upgrade_normalize_previous_header(const image_header *stored,
                                          image_header *normalized) {
  if (stored == NULL || normalized == NULL) {
    return secfalse;
  }
  if (stored->magic != FIRMWARE_MAGIC_NEW &&
      stored->magic != FIRMWARE_MAGIC_UPGRADING) {
    return secfalse;
  }
  memcpy(normalized, stored, sizeof(*normalized));
  normalized->magic = FIRMWARE_MAGIC_NEW;
  return sectrue;
}

secbool upgrade_previous_header_is_empty(const image_header *stored) {
  if (stored == NULL || (stored->magic != 0xffffffffU &&
                         stored->magic != FIRMWARE_MAGIC_UPGRADING)) {
    return secfalse;
  }
  const uint8_t *bytes = (const uint8_t *)stored;
  for (size_t i = sizeof(stored->magic); i < sizeof(*stored); i++) {
    if (bytes[i] != 0xffU) {
      return secfalse;
    }
  }
  return sectrue;
}
