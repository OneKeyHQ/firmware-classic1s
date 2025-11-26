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

#ifndef __FW_SIGNATURES_H__
#define __FW_SIGNATURES_H__

#include <stdbool.h>
#include <stdint.h>
#include "secbool.h"

extern const uint32_t FIRMWARE_MAGIC_NEW;  // TRZF
extern const uint32_t FIRMWARE_MAGIC_BLE;  // 5283
extern const uint32_t FIRMWARE_MAGIC_SE;
extern const uint32_t FIRMWARE_MAGIC_UPGRADING;  // TRZP

#define HW_MODEL_C2B2 "C2B2"

#define FIRMWARE_PURPOSE_GENERAL 0x00000000   // General
#define FIRMWARE_PURPOSE_BTC_ONLY 0x00000001  // Bitcoin-Only

#define SIG_OK 0x5A3CA5C3
#define SIG_FAIL 0x00000000

bool firmware_present_old(void);
int signatures_old_ok(void);

// we use the same structure as T2 firmware header
// but we don't use the field sig
// and rather introduce fields sig1, sig2, sig3
// immediately following the chunk hashes

typedef struct {
  uint32_t magic;
  uint32_t hdrlen;
  uint32_t expiry;
  uint32_t codelen;
  uint32_t version;
  uint32_t fix_version;
  uint32_t hw_model;
  uint8_t hw_revision;
  uint8_t monotonic;
  uint8_t __reserved1[2];
  uint8_t hashes[512];
  uint8_t sig1[64];
  uint8_t sig2[64];
  uint8_t sig3[64];
  union {
    struct {
      uint8_t sig4[64];
      uint8_t sigindex1;
      uint8_t sigindex2;
      uint8_t sigindex3;
      uint8_t sigindex4;
      uint8_t __reserved2[143];
    } signatures_4;
    struct {
      uint8_t sigindex1;
      uint8_t sigindex2;
      uint8_t sigindex3;
      uint8_t __reserved2[208];
    } signatures_3;
  };
  uint32_t purpose;
  uint32_t se_minimum_version;
  uint32_t onekey_version;
  uint8_t __sigmask;
  uint8_t __sig[64];
} __attribute__((packed)) image_header;

#define FW_CHUNK_SIZE 65536

// Upgrade file header structure (1024 bytes total)
#define UPGRADE_HEADER_MAGIC 0x55475244  // "UGRD" - Upgrade Header
#define UPGRADE_HEADER_VERSION 1

// Flags for upgrade header
#define UPGRADE_FLAG_MCU_PRESENT 0x01  // MCU firmware is present
#define UPGRADE_FLAG_SE_PRESENT 0x02   // SE firmware is present
#define UPGRADE_FLAG_BLE_PRESENT 0x04  // BLE firmware is present

// Module upgrade information structure (64 bytes each)
typedef struct {
  uint32_t version;             // Firmware version (major.minor.patch.build)
  uint32_t length;              // Firmware file length in bytes
  uint32_t se_minimum_version;  // SE minimum version requirement (for MCU info)
  uint32_t purpose;             // Firmware purpose (FIRMWARE_PURPOSE_*)
  uint8_t reserved[48];
} __attribute__((packed)) module_upgrade_info_t;

typedef struct {
  uint32_t magic;          // Magic number: 0x55475244 ("UGRD")
  uint8_t header_version;  // Header format version
  uint8_t flags;  // Flags: bit0=MCU present, bit1=SE present, bit2=BLE present
  uint8_t reserved[2];  // Reserved for future use

  // MCU firmware information (64 bytes, if UPGRADE_FLAG_MCU_PRESENT is set)
  module_upgrade_info_t mcu_info;

  // SE firmware information (64 bytes, if UPGRADE_FLAG_SE_PRESENT is set)
  module_upgrade_info_t se_info;

  // BLE firmware information (64 bytes, if UPGRADE_FLAG_BLE_PRESENT is set)
  module_upgrade_info_t ble_info;

  // Reserved area for future extensions
  uint8_t reserved_area[792];  // 1024 - 232 = 792 bytes reserved

  // Header checksum (SHA256 of header data excluding this checksum field)
  // Placed at the end of the header (last 32 bytes)
  uint8_t header_checksum[32];  // SHA256 checksum
} __attribute__((packed)) upgrade_file_header_t;

/**
 * Check if firmware with FIRMWARE_MAGIC_NEW is installed
 * @return true if magic present with some size checks
 */
bool firmware_present_new(void);

bool firmware_present_upgrade(void);

/**
 * Compute fingerprint for given header. Fingerprint is done
 * from header that has signature and sigindex fields zeroed.
 *
 * The "v2" scheme is used. This is what is shown as firmware
 * fingerprint on device.
 *
 * @param hdr header
 * @param hash store resulting hash here
 */
void compute_firmware_fingerprint(const image_header *hdr, uint8_t hash[32]);

/**
 * Compute fingerprint for given header. Fingerprint is done
 * from header that has signature and sigindex fields zeroed.
 *
 * Then it's prefixed using the SignMessage/VerifyMessage method
 * as described here:
 *
 * https://github.com/trezor/trezor-firmware/issues/2513
 *
 * @param hdr header
 * @param hash store resulting hash here
 */
void compute_firmware_fingerprint_for_verifymessage(const image_header *hdr,
                                                    uint8_t hash[32]);

/**
 * Check if header is signed by v2 or v3 scheme based on `use_verifymessage`.
 *
 * Both are 3-of-5 scheme, where 3 signatures specified by sigindex fields
 * must match corresponding secp256k1 pubkey.
 *
 * @param hdr header to check
 * @param store_fingerprint if non-NULL, store hash computed with chosen method
 * here
 * @param use_verifymessage false - use v2 signature scheme, true - use v3
 * SignMessage/VerifyMessage scheme
 * @return SIG_OK or SIG_FAIL
 */
int signatures_ok(const image_header *hdr, uint8_t store_fingerprint[32],
                  secbool use_verifymessage);

/**
 * Check if either v2 or v3 signature of header is valid.
 *
 * Stored fingerprint is the "of v2 scheme" which we still display as hash
 * and use as "firmware hash".
 *
 * @param hdr header to check
 * @param store_fingerprint if non-NULL, store v2 fingerprint here (not v3)
 * @return SIG_OK or SIG_FAIL
 */
int signatures_match(const image_header *hdr, uint8_t store_fingerprint[32]);

/**
 * Check hashes of FW chunks according to what header says they should be.
 * @param hdr header with chunk hashes
 * @return SIG_OK or SIG_FAIL
 */
int check_firmware_hashes(const image_header *hdr, const uint8_t *external_data,
                          uint32_t external_data_len);

uint8_t *get_firmware_hash(const image_header *hdr);

/**
 * Check that block of memory is zeroed. Not constant-time.
 *
 * @param src start pointer
 * @param len length in bytes
 * @return 0 for false or 1 for true
 */
int mem_is_empty(const uint8_t *src, uint32_t len);

bool load_thd89_image_header(const uint8_t *const data, const uint32_t magic,
                             image_header *const hdr);

#endif
