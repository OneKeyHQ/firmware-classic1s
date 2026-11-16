"""Runtime bounds coverage for the production TON comment writers."""

import os
from pathlib import Path
import subprocess
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("LEGACY_TON_CELL_SOURCE", ROOT / "legacy/firmware/ton_cell.c"))


def test_ton_comment_protocol_ceiling(tmp_path: Path) -> None:
    source, binary = tmp_path / "ton.c", tmp_path / "ton"
    source.write_text(textwrap.dedent(r'''
        #include <assert.h>
        #include <stdint.h>
        #include <string.h>
        #include "ton_cell.h"
        bool build_message_ref(bool, uint8_t, uint8_t *, uint64_t, CellRef_t *,
                               bool, const char *, const BitString_t *,
                               const CellRef_t *, uint8_t, CellRef_t *);
        void data2hexaddr(const uint8_t *in, uint32_t len, char *out) {
          static const char h[] = "0123456789abcdef";
          for (uint32_t i = 0; i < len; ++i) { out[2 * i] = h[in[i] >> 4]; out[2 * i + 1] = h[in[i] & 15]; }
          out[2 * len] = 0;
        }
        static void memo(char *p, size_t n) { memset(p, 'M', n - 1); p[n - 1] = 0; }
        int main(void) {
          uint8_t hash[HASH_LEN] = {0}, value[] = {1};
          CellRef_t payload = {0}, message = {0};
          char text[1024];
          /* 125 text bytes means 1032 bits, so historical code really writes
             beyond BitString_t here under ASan. */
          memo(text, 126); assert(!ton_create_transfer_body(text, &payload));
          memo(text, 124); assert(ton_create_transfer_body(text, &payload));
          memo(text, 125); assert(!ton_create_transfer_body(text, &payload));
          memo(text, 126); assert(!ton_create_transfer_body(text, &payload));
          memo(text, 251); assert(!ton_create_transfer_body(text, &payload));
          memo(text, 256); assert(!ton_create_transfer_body(text, &payload));
          memo(text, 257); assert(!ton_create_transfer_body(text, &payload));
          memo(text, 1024); assert(!ton_create_transfer_body(text, &payload));
          /* Actual message header leaves 74 bytes for an inline comment. */
          memo(text, 75); assert(build_message_ref(true, 0, hash, 1, NULL, false, text, NULL, NULL, 0, &message));
          memo(text, 76); assert(!build_message_ref(true, 0, hash, 1, NULL, false, text, NULL, NULL, 0, &message));
          /* Jetton's real dynamic header leaves 41 bytes for its inline comment. */
          memo(text, 42); assert(ton_create_jetton_transfer_body(0, hash, value, sizeof(value), 1, text, 0, hash, &payload));
          memo(text, 43); assert(!ton_create_jetton_transfer_body(0, hash, value, sizeof(value), 1, text, 0, hash, &payload));
          return 0;
        }
    '''))
    subprocess.run([
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-D_DEFAULT_SOURCE", "-DSTM32F4", "-DEMULATOR=1", "-DBITCOIN_ONLY=0",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-pie", "-ffunction-sections", "-fdata-sections",
        f"-I{ROOT / 'legacy'}", f"-I{ROOT / 'crypto'}", f"-I{ROOT / 'legacy/firmware'}", f"-I{ROOT / 'legacy/firmware/protob'}", f"-I{ROOT / 'legacy/gen'}", f"-I{ROOT / 'legacy/vendor/libopencm3/include'}", f"-I{ROOT / 'legacy/vendor/nanopb'}", f"-I{ROOT / 'legacy/vendor/trezor-crypto'}",
        str(source), str(SOURCE), str(ROOT / "legacy/firmware/ton_bits.c"), str(ROOT / "legacy/vendor/trezor-crypto/sha2.c"), str(ROOT / "legacy/vendor/trezor-crypto/memzero.c"), "-Wl,--gc-sections", "-no-pie", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
