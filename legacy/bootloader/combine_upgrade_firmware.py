#!/usr/bin/env python3
"""
Combine MCU, SE, and BLE firmware files into a single upgrade file with upgrade header.

This script:
1. Reads MCU, SE, and/or BLE firmware binary files
2. Parses image_header from each file (first 1024 bytes)
3. Extracts version and length information
4. Generates upgrade_file_header_t (1024 bytes)
5. Combines: upgrade header + MCU file + SE file + BLE file (if present)
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

# Constants from fw_signatures.h
UPGRADE_HEADER_MAGIC = 0x55475244  # "UGRD"
UPGRADE_HEADER_VERSION = 1
UPGRADE_FLAG_MCU_PRESENT = 0x01
UPGRADE_FLAG_SE_PRESENT = 0x02
UPGRADE_FLAG_BLE_PRESENT = 0x04

FWHEADER_SIZE = 1024  # image_header size

# image_header structure offsets
OFFSET_MAGIC = 0
OFFSET_CODELEN = 12
OFFSET_VERSION = 16
OFFSET_PURPOSE = 947
OFFSET_SE_MINIMUM_VERSION = 951  # se_minimum_version offset in image_header
OFFSET_ONEKEY_VERSION = 955     # onekey_version offset in image_header

# upgrade_file_header_t structure layout
# uint32_t magic (4 bytes)
# uint8_t header_version (1 byte)
# uint8_t flags (1 byte)
# uint8_t reserved[2] (2 bytes)
# module_upgrade_info_t mcu_info (64 bytes)
#   - uint32_t version (4 bytes) - from onekey_version
#   - uint32_t length (4 bytes)
#   - uint32_t se_minimum_version (4 bytes) - from se_minimum_version
#   - uint32_t purpose (4 bytes)
#   - uint8_t reserved[48] (48 bytes)
# module_upgrade_info_t se_info (64 bytes)
#   - uint32_t version (4 bytes)
#   - uint32_t length (4 bytes)
#   - uint32_t se_minimum_version (4 bytes) - unused for SE, set to 0
#   - uint32_t purpose (4 bytes)
#   - uint8_t reserved[48] (48 bytes)
# module_upgrade_info_t ble_info (64 bytes)
#   - uint32_t version (4 bytes)
#   - uint32_t length (4 bytes)
#   - uint32_t se_minimum_version (4 bytes) - unused for BLE, set to 0
#   - uint32_t purpose (4 bytes) - unused for BLE, set to 0
#   - uint8_t reserved[48] (48 bytes)
# uint8_t reserved_area[792] (792 bytes)
# uint8_t header_checksum[32] (32 bytes) - at the end
# Total: 1024 bytes

OFFSET_UPGRADE_MAGIC = 0
OFFSET_UPGRADE_VERSION = 4
OFFSET_UPGRADE_FLAGS = 5
OFFSET_UPGRADE_MCU_INFO = 8
OFFSET_UPGRADE_SE_INFO = 72
OFFSET_UPGRADE_BLE_INFO = 136  # 72 + 64 = 136
OFFSET_UPGRADE_CHECKSUM = 992  # Last 32 bytes (1024 - 32 = 992)


def parse_image_header(data, is_mcu=False, is_ble=False):
    """Parse image_header from firmware file data (first 1024 bytes)."""
    if len(data) < FWHEADER_SIZE:
        raise ValueError(f"File too small, need at least {FWHEADER_SIZE} bytes for header")

    header = data[:FWHEADER_SIZE]
    magic = struct.unpack("<I", header[OFFSET_MAGIC : OFFSET_MAGIC + 4])[0]
    codelen = struct.unpack("<I", header[OFFSET_CODELEN : OFFSET_CODELEN + 4])[0]
    
    # For MCU, use onekey_version; for SE/BLE, use version
    if is_mcu:
        version = struct.unpack("<I", header[OFFSET_ONEKEY_VERSION : OFFSET_ONEKEY_VERSION + 4])[0]
        se_minimum_version = struct.unpack("<I", header[OFFSET_SE_MINIMUM_VERSION : OFFSET_SE_MINIMUM_VERSION + 4])[0]
        purpose = struct.unpack("<I", header[OFFSET_PURPOSE : OFFSET_PURPOSE + 4])[0]
    else:
        version = struct.unpack("<I", header[OFFSET_VERSION : OFFSET_VERSION + 4])[0]
        se_minimum_version = 0  # SE/BLE don't have se_minimum_version requirement
        if is_ble:
            purpose = 0  # BLE doesn't have purpose
        else:
            purpose = struct.unpack("<I", header[OFFSET_PURPOSE : OFFSET_PURPOSE + 4])[0]

    # Total file length = header (1024) + code length
    total_length = FWHEADER_SIZE + codelen

    return {
        "magic": magic,
        "codelen": codelen,
        "version": version,
        "se_minimum_version": se_minimum_version,
        "total_length": total_length,
        "purpose": purpose,
    }


def create_upgrade_header(mcu_info=None, se_info=None, ble_info=None):
    """Create upgrade_file_header_t structure (1024 bytes)."""
    header = bytearray(1024)

    # Set magic
    struct.pack_into("<I", header, OFFSET_UPGRADE_MAGIC, UPGRADE_HEADER_MAGIC)

    # Set header version
    header[OFFSET_UPGRADE_VERSION] = UPGRADE_HEADER_VERSION

    # Set flags
    flags = 0
    if mcu_info:
        flags |= UPGRADE_FLAG_MCU_PRESENT
    if se_info:
        flags |= UPGRADE_FLAG_SE_PRESENT
    if ble_info:
        flags |= UPGRADE_FLAG_BLE_PRESENT
    header[OFFSET_UPGRADE_FLAGS] = flags

    # Reserved[2] is already zero

    # Set MCU info (if present)
    if mcu_info:
        struct.pack_into("<I", header, OFFSET_UPGRADE_MCU_INFO, mcu_info["version"])
        struct.pack_into("<I", header, OFFSET_UPGRADE_MCU_INFO + 4, mcu_info["total_length"])
        struct.pack_into("<I", header, OFFSET_UPGRADE_MCU_INFO + 8, mcu_info["se_minimum_version"])
        struct.pack_into("<I", header, OFFSET_UPGRADE_MCU_INFO + 12, mcu_info["purpose"])
        # Reserved[48] is already zero

    # Set SE info (if present)
    if se_info:
        struct.pack_into("<I", header, OFFSET_UPGRADE_SE_INFO, se_info["version"])
        struct.pack_into("<I", header, OFFSET_UPGRADE_SE_INFO + 4, se_info["total_length"])
        struct.pack_into("<I", header, OFFSET_UPGRADE_SE_INFO + 8, 0)  # SE requirement unused
        struct.pack_into("<I", header, OFFSET_UPGRADE_SE_INFO + 12, se_info.get("purpose", 0))
        # Reserved[48] is already zero

    # Set BLE info (if present)
    if ble_info:
        struct.pack_into("<I", header, OFFSET_UPGRADE_BLE_INFO, ble_info["version"])
        struct.pack_into("<I", header, OFFSET_UPGRADE_BLE_INFO + 4, ble_info["total_length"])
        struct.pack_into("<I", header, OFFSET_UPGRADE_BLE_INFO + 8, 0)  # BLE requirement unused
        struct.pack_into("<I", header, OFFSET_UPGRADE_BLE_INFO + 12, 0)  # BLE purpose unused
        # Reserved[48] is already zero

    # Calculate checksum: SHA256 of header with checksum field zeroed
    checksum_field = header[OFFSET_UPGRADE_CHECKSUM : OFFSET_UPGRADE_CHECKSUM + 32]
    header[OFFSET_UPGRADE_CHECKSUM : OFFSET_UPGRADE_CHECKSUM + 32] = b"\x00" * 32
    checksum = hashlib.sha256(header).digest()
    header[OFFSET_UPGRADE_CHECKSUM : OFFSET_UPGRADE_CHECKSUM + 32] = checksum

    return bytes(header)


def main():
    parser = argparse.ArgumentParser(
        description="Combine MCU, SE, and BLE firmware files into upgrade file with header"
    )
    parser.add_argument(
        "-m",
        "--mcu",
        dest="mcu_file",
        help="MCU firmware binary file",
    )
    parser.add_argument(
        "-s",
        "--se",
        dest="se_file",
        help="SE firmware binary file (optional)",
    )
    parser.add_argument(
        "-b",
        "--ble",
        dest="ble_file",
        help="BLE firmware binary file (optional)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        required=True,
        help="Output upgrade file",
    )

    args = parser.parse_args()

    if not args.mcu_file and not args.se_file and not args.ble_file:
        parser.error("At least one of --mcu, --se, or --ble must be specified")

    # Validate supported combinations: MCU only, MCU+SE, or BLE only
    has_mcu = args.mcu_file is not None
    has_se = args.se_file is not None
    has_ble = args.ble_file is not None

    is_mcu_only = has_mcu and not has_se and not has_ble
    is_mcu_se = has_mcu and has_se and not has_ble
    is_ble_only = has_ble and not has_mcu and not has_se

    if not is_mcu_only and not is_mcu_se and not is_ble_only:
        parser.error(
            "Unsupported combination. Only these combinations are supported:\n"
            "  - MCU only: --mcu\n"
            "  - MCU + SE: --mcu --se\n"
            "  - BLE only: --ble"
        )

    mcu_info = None
    se_info = None
    ble_info = None

    # Read and parse MCU file
    if args.mcu_file:
        mcu_path = Path(args.mcu_file)
        if not mcu_path.exists():
            print(f"Error: MCU file not found: {args.mcu_file}", file=sys.stderr)
            sys.exit(1)

        print(f"Reading MCU file: {args.mcu_file}")
        with open(mcu_path, "rb") as f:
            mcu_data = f.read()

        mcu_info = parse_image_header(mcu_data, is_mcu=True)
        print(f"  Magic: 0x{mcu_info['magic']:08x}")
        print(f"  Version (onekey_version): 0x{mcu_info['version']:08x}")
        print(f"  SE minimum version: 0x{mcu_info['se_minimum_version']:08x}")
        print(f"  Code length: {mcu_info['codelen']} bytes")
        print(f"  Total length: {mcu_info['total_length']} bytes")

        # Verify file size matches
        if len(mcu_data) != mcu_info["total_length"]:
            print(
                f"  Warning: File size ({len(mcu_data)}) doesn't match expected length ({mcu_info['total_length']})",
                file=sys.stderr,
            )

    # Read and parse SE file
    if args.se_file:
        se_path = Path(args.se_file)
        if not se_path.exists():
            print(f"Error: SE file not found: {args.se_file}", file=sys.stderr)
            sys.exit(1)

        print(f"Reading SE file: {args.se_file}")
        with open(se_path, "rb") as f:
            se_data = f.read()

        se_info = parse_image_header(se_data, is_mcu=False)
        print(f"  Magic: 0x{se_info['magic']:08x}")
        print(f"  Version: 0x{se_info['version']:08x}")
        print(f"  Code length: {se_info['codelen']} bytes")
        print(f"  Total length: {se_info['total_length']} bytes")

        # Verify file size matches
        if len(se_data) != se_info["total_length"]:
            print(
                f"  Warning: File size ({len(se_data)}) doesn't match expected length ({se_info['total_length']})",
                file=sys.stderr,
            )

    # Read and parse BLE file
    ble_data = None
    if args.ble_file:
        ble_path = Path(args.ble_file)
        if not ble_path.exists():
            print(f"Error: BLE file not found: {args.ble_file}", file=sys.stderr)
            sys.exit(1)

        print(f"Reading BLE file: {args.ble_file}")
        with open(ble_path, "rb") as f:
            ble_data = f.read()

        ble_info = parse_image_header(ble_data, is_mcu=False, is_ble=True)
        print(f"  Magic: 0x{ble_info['magic']:08x}")
        print(f"  Version: 0x{ble_info['version']:08x}")
        print(f"  Code length: {ble_info['codelen']} bytes")
        print(f"  Total length: {ble_info['total_length']} bytes")

        # Verify file size matches
        if len(ble_data) != ble_info["total_length"]:
            print(
                f"  Warning: File size ({len(ble_data)}) doesn't match expected length ({ble_info['total_length']})",
                file=sys.stderr,
            )

    # Create upgrade header
    print("\nCreating upgrade header...")
    upgrade_header = create_upgrade_header(mcu_info, se_info, ble_info)
    print(f"  Upgrade header size: {len(upgrade_header)} bytes")

    # Verify checksum
    verify_header = bytearray(upgrade_header)
    verify_header[OFFSET_UPGRADE_CHECKSUM : OFFSET_UPGRADE_CHECKSUM + 32] = b"\x00" * 32
    calculated_checksum = hashlib.sha256(verify_header).digest()
    stored_checksum = upgrade_header[OFFSET_UPGRADE_CHECKSUM : OFFSET_UPGRADE_CHECKSUM + 32]
    if calculated_checksum != stored_checksum:
        print("  Error: Checksum verification failed!", file=sys.stderr)
        sys.exit(1)
    print("  Checksum verified")

    # Combine files
    print(f"\nWriting output file: {args.output_file}")
    output_path = Path(args.output_file)
    with open(output_path, "wb") as f:
        # Write upgrade header
        f.write(upgrade_header)
        print(f"  Wrote upgrade header: {len(upgrade_header)} bytes")

        # Write MCU file
        if mcu_info:
            f.write(mcu_data)
            print(f"  Wrote MCU file: {len(mcu_data)} bytes")

        # Write SE file
        if se_info:
            f.write(se_data)
            print(f"  Wrote SE file: {len(se_data)} bytes")

        # Write BLE file
        if ble_info:
            f.write(ble_data)
            print(f"  Wrote BLE file: {len(ble_data)} bytes")

    total_size = len(upgrade_header) + (len(mcu_data) if mcu_info else 0) + (len(se_data) if se_info else 0) + (len(ble_data) if ble_info else 0)
    print(f"\nTotal output size: {total_size} bytes")
    print(f"Output file: {args.output_file}")


if __name__ == "__main__":
    main()
