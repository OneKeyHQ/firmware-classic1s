"""ASan/UBSan coverage for the exact OP_RETURN confirmation body."""

import os
from pathlib import Path
import subprocess
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("LEGACY_OPRETURN_SOURCE", ROOT / "legacy/firmware/layout2.c"))


def _function(text: str, signature: str) -> str:
    start, opening, depth = text.index(signature), 0, 0
    opening = text.index("{", start)
    for end in range(opening, len(text)):
        if text[end] == "{": depth += 1
        elif text[end] == "}":
            depth -= 1
            if not depth: return text[start:end + 1]
    raise AssertionError("unterminated function")


def test_opreturn_wire_limit_before_real_hex_formatting(tmp_path: Path) -> None:
    layout = SOURCE.read_text()
    util = (ROOT / "legacy/util.c").read_text()
    body = _function(layout, "uint8_t layoutConfirmOpReturn(")
    hexdigits = next(
        line for line in util.splitlines() if line.startswith("static const char *hexdigits")
    )
    helpers = "\n".join(_function(util, s) for s in (
        "void data2hex(", "bool is_valid_ascii(", "bool is_valid_utf8(", "bool is_printable("))
    source, binary = tmp_path / "opreturn.c", tmp_path / "opreturn"
    source.write_text(textwrap.dedent(r'''
        #include <assert.h>
        #include <stdbool.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <string.h>
        typedef struct { uint8_t unused; } CoinInfo;
        typedef struct { uint8_t size; uint8_t bytes[150]; } Bytes150;
        typedef struct { Bytes150 op_return_data; } TxOutputType;
        typedef struct { uint8_t unused; } BITMAP;
        enum { KEY_CANCEL = 0, KEY_CONFIRM = 1, FONT_STANDARD = 0, AmountUnit_BITCOIN = 0 };
        static const BITMAP bmp_icon_warning, bmp_bottom_left_close, bmp_bottom_right_arrow;
        static char shown[301]; static unsigned calls;
        static uint8_t warning_key = KEY_CONFIRM, result_key = KEY_CONFIRM;
        #define _(x) (x)
        #define TITLE__OP_RETURN_DESC "OP_RETURN may destroy funds"
        #define I__AMOUNT_COLON "Amount:"
        static void oledClear(void) {}
        static void oledDrawBitmap(int x, int y, const BITMAP *b) {(void)x;(void)y;(void)b;}
        static void layoutHeader(const char *s) {(void)s;}
        static void oledDrawStringAdapter(int x,int y,const char *s,int f) {(void)x;(void)y;(void)s;(void)f;}
        static void format_coin_amount(uint64_t a, void *u, const CoinInfo *c,int unit,char *out,size_t n) {(void)a;(void)u;(void)c;(void)unit; snprintf(out,n,"1");}
        static uint8_t oledDrawPageableStringAdapter(int x,int y,const char *s,int f,const BITMAP *l,const BITMAP *r) {
          (void)x;(void)y;(void)f;(void)l;(void)r; ++calls;
          if (calls == 1 && warning_key == KEY_CANCEL) return KEY_CANCEL;
          assert(strlen(s) < sizeof(shown)); strcpy(shown, s); return result_key;
        }
    ''') + hexdigits + "\n" + helpers + "\n" + body + textwrap.dedent(r'''
        static void reset(void) { memset(shown, 0, sizeof(shown)); calls = 0; warning_key = result_key = KEY_CONFIRM; }
        int main(void) {
          CoinInfo coin = {0}; uint8_t binary[151], printable[151];
          for (size_t i = 0; i < sizeof(binary); ++i) { binary[i] = (uint8_t)i; printable[i] = 'P'; }
          /* The historical 161-byte stack array is overflowed by this exact
             data2hex call (150 input bytes -> 300 chars). */
          reset(); assert(layoutConfirmOpReturn(&coin, binary, 150, 0) == KEY_CONFIRM);
          assert(calls == 1 && strlen(shown) == 300 && shown[0] == '0' && shown[1] == '0' && shown[298] == '9' && shown[299] == '5');
          reset(); assert(layoutConfirmOpReturn(&coin, printable, 150, 0) == KEY_CONFIRM);
          assert(strlen(shown) == 150 && shown[149] == 'P');
          reset(); assert(layoutConfirmOpReturn(&coin, binary, 0, 0) == KEY_CONFIRM && shown[0] == 0);
          reset(); assert(layoutConfirmOpReturn(&coin, binary, 80, 0) == KEY_CONFIRM && strlen(shown) == 160);
          reset(); assert(layoutConfirmOpReturn(&coin, binary, 81, 0) == KEY_CONFIRM && strlen(shown) == 162);
          reset(); assert(layoutConfirmOpReturn(&coin, binary, 151, 0) == KEY_CANCEL && calls == 0);
          reset(); result_key = KEY_CANCEL; assert(layoutConfirmOpReturn(&coin, binary, 1, 0) == KEY_CANCEL);
          reset(); warning_key = KEY_CANCEL; assert(layoutConfirmOpReturn(&coin, binary, 1, 1) == KEY_CANCEL && calls == 1 && shown[0] == 0);
          return 0;
        }
    '''))
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-pie", "-no-pie", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
