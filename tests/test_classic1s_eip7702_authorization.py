"""Runtime EIP-7702 authorization binding regression coverage."""

import os
from pathlib import Path
import subprocess
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("LEGACY_EIP7702_SOURCE", ROOT / "legacy/firmware/ethereum_onekey.c"))


def _function(text: str, signature: str) -> str:
    start, opening, depth = text.index(signature), 0, 0
    opening = text.index("{", start)
    for end in range(opening, len(text)):
        if text[end] == "{": depth += 1
        elif text[end] == "}":
            depth -= 1
            if not depth: return text[start:end + 1]
    raise AssertionError("unterminated function")


def test_authorization_uses_displayed_sender_and_checked_nonces(tmp_path: Path) -> None:
    text = SOURCE.read_text()
    to_uint64 = _function(text, "static uint64_t ethereum_bytes_to_uint64(")
    check = _function(text, "static bool ethereum_check_authorization_list(")
    is_old = "uint64_t nonce)" in check
    call = (
        "return ethereum_check_authorization_list(params, list, count, ethereum_bytes_to_uint64(nonce, nonce_size));"
        if is_old else
        "return ethereum_check_authorization_list(params, list, count, path, path_count, nonce, nonce_size);"
    )
    unused_parameters = "(void)path; (void)path_count;" if is_old else ""
    source, binary = tmp_path / "eip7702.c", tmp_path / "eip7702"
    source.write_text(textwrap.dedent(r'''
        #include <assert.h>
        #include <stdbool.h>
        #include <stddef.h>
        #include <stdint.h>
        #include <string.h>
        enum { FailureType_Failure_DataError = 1, ButtonRequestType_ButtonRequest_ProtectCall = 1 };
        typedef struct { size_t size; uint8_t bytes[32]; } Bytes;
        typedef struct { uint32_t y_parity; Bytes r, s; } EthereumAuthorizationSignature;
        typedef struct {
          size_t address_n_count; uint32_t address_n[8]; uint64_t chain_id;
          char address[43]; Bytes nonce; bool has_signature;
          EthereumAuthorizationSignature signature;
        } EthereumAuthorizationOneKey;
        typedef struct { const char *name; uint8_t address[20]; uint8_t initial_data_size; uint8_t initial_data[4]; } Delegator;
        struct signing_params { uint32_t data_initial_chunk_size; const uint8_t *data_initial_chunk_bytes; };
        static uint64_t chain_id = 1; static unsigned failures;
        static const int bmp_icon_warning, bmp_bottom_left_close, bmp_bottom_right_confirm;
        #define _(x) (x)
        #define I_NOT_IN_SMART_ACCOUNT_WHITELIST "not registered"
        static void fsm_sendFailure(int code, const char *message) {(void)code;(void)message;++failures;}
        static void layoutDialogCenterAdapterV2(const void *a, const void *b, const void *c, const void *d, const void *e, const void *f, const void *g, const void *h, const void *i, const void *j, const char *k) {(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;}
        static void protectButton(int code, bool confirm) {(void)code;(void)confirm;}
        static bool ethereum_parse_onekey(const char *address, uint8_t out[20]) {(void)address; memset(out, 0, 20); return true;}
        static bool is_registered_delegator(uint64_t network, const uint8_t address[20]) {(void)network;(void)address; return true;}
        static const Delegator *get_delegator_by_address(uint64_t network, const uint8_t address[20]) { static const Delegator d = {"test", {0}, 0, {0}}; (void)network;(void)address; return &d; }
    ''') + to_uint64 + "\n" + check + textwrap.dedent("\n"
        "static bool call_check(const struct signing_params *params, const EthereumAuthorizationOneKey *list, uint32_t count, const uint32_t *path, uint32_t path_count, const uint8_t *nonce, size_t nonce_size) {\n"
        f"  {unused_parameters}\n"
        f"  {call}\n" "}\n") + textwrap.dedent(r'''
        static EthereumAuthorizationOneKey make_authorization(void) {
          EthereumAuthorizationOneKey auth = {0};
          strcpy(auth.address, "0x0000000000000000000000000000000000000000");
          auth.nonce.size = 1; auth.nonce.bytes[0] = 2; return auth;
        }
        static bool validate(EthereumAuthorizationOneKey *auth, const uint32_t *path,
                             uint32_t path_count, const uint8_t *nonce, size_t nonce_size) {
          uint8_t initial = 0; struct signing_params params = {0, &initial}; failures = 0;
          return call_check(&params, auth, 1, path, path_count, nonce, nonce_size);
        }
        int main(void) {
          const uint32_t path[] = {44, 60}; const uint32_t wrong_path[] = {44, 61};
          const uint8_t nonce1[] = {1}; const uint8_t nonce9[] = {0,0,0,0,0,0,0,0,1};
          const uint8_t max_nonce[] = {255,255,255,255,255,255,255,255};
          EthereumAuthorizationOneKey auth = make_authorization();
          assert(validate(&auth, path, 2, nonce1, sizeof(nonce1)));       /* implicit authority */
          auth = make_authorization(); auth.address_n_count = 2; memcpy(auth.address_n, path, sizeof(path));
          assert(validate(&auth, path, 2, nonce1, sizeof(nonce1)));       /* explicit matching path */
          auth = make_authorization(); auth.address_n_count = 2; memcpy(auth.address_n, wrong_path, sizeof(wrong_path));
          assert(!validate(&auth, path, 2, nonce1, sizeof(nonce1)));      /* different path */
          auth = make_authorization(); auth.address_n_count = 1; auth.address_n[0] = path[0];
          assert(!validate(&auth, path, 2, nonce1, sizeof(nonce1)));      /* different count */
          auth = make_authorization(); auth.address_n_count = 2; memcpy(auth.address_n, path, sizeof(path)); auth.nonce.bytes[0] = 7;
          assert(!validate(&auth, path, 2, nonce1, sizeof(nonce1)));      /* matching path, bad nonce */
          auth = make_authorization(); auth.nonce.size = 9;
          assert(!validate(&auth, path, 2, nonce1, sizeof(nonce1)));      /* authority nonce too wide */
          auth = make_authorization();
          assert(!validate(&auth, path, 2, nonce9, sizeof(nonce9)));      /* transaction nonce too wide */
          auth = make_authorization(); auth.nonce.bytes[0] = 0;
          assert(!validate(&auth, path, 2, max_nonce, sizeof(max_nonce)));/* no uint64 wraparound */
          auth = make_authorization(); auth.has_signature = true; auth.signature.r.size = auth.signature.s.size = 32;
          assert(validate(&auth, path, 2, nonce1, sizeof(nonce1)));       /* presigned stays valid */
          auth.address_n_count = 2; memcpy(auth.address_n, path, sizeof(path));
          assert(!validate(&auth, path, 2, nonce1, sizeof(nonce1)));      /* signature and path conflict */
          return 0;
        }
    '''))
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-pie", "-no-pie", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


def test_authorization_signing_reuses_the_sender_node(tmp_path: Path) -> None:
    text = SOURCE.read_text()
    signing_start = text.index("bool sign_authorization_list(")
    signing_end = text.index("\nstatic void send_signature(", signing_start)
    signing = text[signing_start:signing_end]
    source, binary = tmp_path / "eip7702_signing.c", tmp_path / "eip7702_signing"
    source.write_text(textwrap.dedent(r'''
        #include <assert.h>
        #include <stdbool.h>
        #include <stddef.h>
        #include <stdint.h>
        #include <string.h>
        enum {
          FailureType_Failure_DataError = 1,
          FailureType_Failure_ProcessError = 2,
        };
        #define SECP256K1_NAME "secp256k1"
        typedef struct { uint8_t private_key[32]; } HDNode;
        typedef struct { size_t size; uint8_t bytes[32]; } Bytes;
        typedef struct { uint32_t y_parity; Bytes r, s; } EthereumAuthorizationSignature;
        typedef struct {
          size_t address_n_count; uint32_t address_n[8]; uint64_t chain_id;
          char address[43]; Bytes nonce; bool has_signature;
          EthereumAuthorizationSignature signature;
        } EthereumAuthorizationOneKey;
        typedef struct {
          uint32_t authorization_list_count;
          EthereumAuthorizationOneKey authorization_list[16];
        } EthereumSignTxEIP7702OneKey;
        static EthereumAuthorizationOneKey signing_authorization_list[16];
        static uint32_t signing_authorization_list_count;
        static HDNode *_node;
        static HDNode derived_node;
        static const HDNode *signed_node;
        static unsigned signing_calls, derive_calls, failures;
        static int signing_result;
        static bool make_authorization_digest(const EthereumAuthorizationOneKey *auth,
                                              uint8_t digest[32]) {
          (void)auth; memset(digest, 0x5a, 32); return true;
        }
        static int ethereum_is_canonic(uint8_t v, uint8_t signature[64]) {
          (void)v; (void)signature; return 1;
        }
        static int hdnode_sign_digest(const HDNode *node, const uint8_t digest[32],
                                      uint8_t signature[64], uint8_t *v,
                                      int (*is_canonic)(uint8_t, uint8_t[64])) {
          signed_node = node; signing_calls++; memset(signature, 0xa5, 64); *v = 1;
          (void)digest; (void)is_canonic; return signing_result;
        }
        HDNode *fsm_getDerivedNode(const char *curve, const uint32_t *path,
                                  size_t path_count, uint32_t *fingerprint) {
          (void)curve; (void)path; (void)path_count; (void)fingerprint;
          derive_calls++; return &derived_node;
        }
        static void fsm_sendFailure(int code, const char *message) {
          (void)code; (void)message; failures++;
        }
    ''') + signing + textwrap.dedent(r'''
        static EthereumAuthorizationOneKey unsigned_authorization(void) {
          EthereumAuthorizationOneKey auth = {0};
          auth.address_n_count = 2; auth.address_n[0] = 44; auth.address_n[1] = 60;
          auth.nonce.size = 1; auth.nonce.bytes[0] = 2;
          return auth;
        }
        static void reset(void) {
          memset(signing_authorization_list, 0, sizeof(signing_authorization_list));
          signing_authorization_list_count = 0; signed_node = NULL; signing_calls = 0;
          derive_calls = 0; failures = 0; signing_result = 0;
        }
        int main(void) {
          HDNode sender = {{1}};
          EthereumSignTxEIP7702OneKey msg = {0};
          reset(); msg.authorization_list_count = 1;
          msg.authorization_list[0] = unsigned_authorization();
          assert(sign_authorization_list(&msg, &sender));
          assert(signing_calls == 1 && signed_node == &sender && derive_calls == 0);
          assert(signing_authorization_list_count == 1);
          assert(signing_authorization_list[0].has_signature);

          reset(); msg.authorization_list_count = 1;
          msg.authorization_list[0] = unsigned_authorization();
          msg.authorization_list[0].address_n_count = 0;
          assert(sign_authorization_list(&msg, &sender));
          assert(signing_calls == 1 && signed_node == &sender && derive_calls == 0);

          reset(); msg.authorization_list_count = 1;
          msg.authorization_list[0] = unsigned_authorization();
          msg.authorization_list[0].has_signature = true;
          msg.authorization_list[0].address_n_count = 0;
          msg.authorization_list[0].signature.r.size = 32;
          msg.authorization_list[0].signature.s.size = 32;
          assert(sign_authorization_list(&msg, &sender));
          assert(signing_calls == 0 && derive_calls == 0);

          reset(); msg.authorization_list_count = 1;
          msg.authorization_list[0] = unsigned_authorization();
          signing_result = 1;
          assert(!sign_authorization_list(&msg, &sender));
          assert(signing_calls == 1 && signed_node == &sender && failures == 1);
          return 0;
        }
    '''))
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-pie", "-no-pie", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
