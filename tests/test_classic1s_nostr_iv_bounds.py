"""Execute the production Nostr IV decode span with ASan/UBSan."""

import os
from pathlib import Path
import subprocess
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("LEGACY_NOSTR_SOURCE", ROOT / "legacy/firmware/nostr.c"))


def test_nostr_iv_must_decode_to_one_aes_block(tmp_path: Path) -> None:
    text = SOURCE.read_text()
    after_marker = text.index("iv_b64 += 4;") + len("iv_b64 += 4;")
    decode_ct = text.index("end = b64tobin(ct, msg->msg);", after_marker)
    span = text[after_marker:decode_ct]
    source, binary = tmp_path / "nostr_iv.c", tmp_path / "nostr_iv"
    source.write_text(textwrap.dedent(r'''
        #include <assert.h>
        #include <stdbool.h>
        #include <stdint.h>
        #include <string.h>
        #include "base64.h"
        enum { FailureType_Failure_DataError = 1 };
        static unsigned failures, homes;
        static void fsm_sendFailure(int code, const char *message) {(void)code;(void)message;++failures;}
        static void layoutHome(void) {++homes;}
        static bool decode_iv(char *message, uint8_t out[16]) {
          uint8_t iv[16] = {0};
          char *iv_b64 = message;
          iv_b64 += 4;
    ''') + span + textwrap.dedent(r'''
          memcpy(out, iv, sizeof(iv));
          return true;
        }
        static void reset(void) { failures = homes = 0; }
        static void rejected(char *input) { uint8_t out[16]; reset(); assert(!decode_iv(input, out)); assert(failures == 1 && homes == 1); }
        int main(void) {
          uint8_t expected[16], out[16];
          for (unsigned i = 0; i < sizeof(expected); ++i) expected[i] = (uint8_t)i;
          char valid[] = "?iv=AAECAwQFBgcICQoLDA0ODw==";
          reset(); assert(decode_iv(valid, out)); assert(!failures && !homes && memcmp(out, expected, sizeof(out)) == 0);
          char short_iv[] = "?iv=AAAAAAAAAAAAAAAAAAAAAAA";
          char unpadded_24[] = "?iv=AAAAAAAAAAAAAAAAAAAAAAAA";
          char one_pad[] = "?iv=AAAAAAAAAAAAAAAAAAAAAAA=";
          char early_invalid[] = "?iv=!AAAAAAAAAAAAAAAAAAAAA==";
          char very_long[1561]; memset(very_long, 'A', sizeof(very_long)); memcpy(very_long, "?iv=", 4); very_long[sizeof(very_long) - 1] = 0;
          /* Historical b64tobin writes 18 bytes for this 24-character form. */
          rejected(unpadded_24); rejected(short_iv); rejected(one_pad); rejected(early_invalid); rejected(very_long);
          return 0;
        }
    '''))
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-pie", "-no-pie", f"-I{ROOT / 'legacy/firmware'}", str(source), str(ROOT / "legacy/firmware/base64.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
