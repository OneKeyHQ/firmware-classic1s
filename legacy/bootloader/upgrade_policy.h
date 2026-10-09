#ifndef LEGACY_BOOTLOADER_UPGRADE_POLICY_H
#define LEGACY_BOOTLOADER_UPGRADE_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "fw_signatures.h"
#include "secbool.h"

#define UPGRADE_POLICY_HEADER_SIZE 1024U

typedef enum {
  UPGRADE_FILE_FORMAT_NONE = 0,
  UPGRADE_FILE_FORMAT_OLD = 0x4f4c4431,
  UPGRADE_FILE_FORMAT_NEW = 0x4e455731,
  UPGRADE_FILE_FORMAT_OLD_BODY = 0x424f4459,
} upgrade_file_format_t;

typedef enum {
  UPGRADE_ERASE_TARGET_NONE = 0,
  UPGRADE_ERASE_TARGET_MCU = 0x4d435531,
  UPGRADE_ERASE_TARGET_BLE = 0x424c4531,
} upgrade_erase_target_t;

typedef enum {
  UPGRADE_PREVIOUS_UNKNOWN = 0,
  UPGRADE_PREVIOUS_EMPTY = 0x454d5054,
  UPGRADE_PREVIOUS_VERIFIED = 0x56455249,
} upgrade_previous_state_t;

typedef enum {
  UPGRADE_IMAGE_TARGET_NONE = 0,
  UPGRADE_IMAGE_TARGET_MCU = 0x4d435531,
  UPGRADE_IMAGE_TARGET_BLE = 0x424c4531,
} upgrade_image_target_t;

int upgrade_version_compare(uint32_t vera, uint32_t verb);
secbool upgrade_file_format_allowed(upgrade_file_format_t preflight,
                                    upgrade_file_format_t upload);
secbool upgrade_header_chunk_matches(const uint8_t *expected,
                                     const uint8_t *actual, size_t offset,
                                     size_t length);
secbool upgrade_mcu_metadata_matches(const upgrade_file_header_t *wrapper,
                                     const image_header *image);
secbool upgrade_mcu_downgrade_allowed(uint32_t new_version,
                                      uint32_t current_version,
                                      uint32_t new_purpose,
                                      uint32_t current_purpose);
secbool upgrade_mcu_install_allowed(upgrade_previous_state_t previous_state,
                                    uint32_t new_version,
                                    uint32_t current_version,
                                    uint32_t new_purpose,
                                    uint32_t current_purpose);
secbool upgrade_upload_target_allowed(upgrade_erase_target_t erase_target,
                                      upgrade_image_target_t image_target);
upgrade_image_target_t upgrade_wrapper_image_target(uint8_t flags);
secbool upgrade_preflight_erase_allowed(
    upgrade_file_format_t preflight_format,
    upgrade_image_target_t preflight_target,
    upgrade_erase_target_t requested_erase_target);
secbool upgrade_wrapper_target_allowed(uint8_t flags,
                                       upgrade_image_target_t image_target);
secbool upgrade_wrapper_payload_allowed(uint8_t flags,
                                        upgrade_image_target_t image_target,
                                        secbool se_present);
secbool upgrade_wrapper_payload_length_matches(
    const upgrade_file_header_t *wrapper, uint32_t payload_length);
secbool upgrade_wrapper_declared_lengths_allowed(
    const upgrade_file_header_t *wrapper, uint32_t max_mcu_length,
    uint32_t max_aux_length);
secbool upgrade_aux_metadata_matches(const module_upgrade_info_t *module,
                                     const image_header *image,
                                     uint32_t actual_length);
secbool upgrade_normalize_previous_header(const image_header *stored,
                                          image_header *normalized);
secbool upgrade_previous_header_is_empty(const image_header *stored);

#endif
