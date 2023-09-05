#if defined(EMULATOR) && EMULATOR

#include "se_chip.h"

bool se_device_init(uint8_t mode, const char *passphrase) { return false; }

bool se_ecdsa_get_pubkey(uint32_t *address, uint8_t count, uint8_t *pubkey) {
  return false;
}
bool se_set_value(uint16_t key, const void *val_dest, uint16_t len) {
  return false;
}
bool se_get_value(uint16_t key, void *val_dest, uint16_t max_len,
                  uint16_t *len) {
  return false;
}
bool se_delete_key(uint16_t key) { return false; }
void se_reset_storage(void) { return false; }
bool se_get_sn(char **serial) { return false; }
char *se_get_version(void) { return false; }
bool se_verify(void *message, uint16_t message_len, uint16_t max_len,
               void *cert_val, uint16_t *cert_len, void *signature_val,
               uint16_t *signature_len) {
  return false;
}
bool se_isInitialized(void) { return false; }
bool se_hasPin(void) { return false; }
bool se_setPin(uint32_t pin) { return false; }
bool se_verifyPin(uint32_t pin, uint8_t mode) { return false; }
bool se_changePin(uint32_t oldpin, uint32_t newpin) { return false; }
uint32_t se_pinFailedCounter(void) { return false; }
bool se_getRetryTimes(uint8_t *pcnts) { return false; }
bool se_setPinValidtime(uint8_t minutes) { return false; }
bool se_getPinValidtime(uint8_t *pbuf) { return false; }
bool se_clearSecsta(void) { return false; }
bool se_getSecsta(void) { return false; }
bool se_isFactoryMode(void) { return false; }
bool se_isLifecyComSta(void) { return false; }
bool se_set_u2f_counter(uint32_t u2fcounter) { return false; }
bool se_get_u2f_counter(uint32_t *u2fcounter) { return false; }
bool se_setSeed(uint8_t *preCnts, uint8_t mode) { return false; }
bool se_setMinisec(uint8_t *preCnts, uint8_t mode) { return false; }
bool se_get_entropy(uint8_t entroy[32]) { return false; }
bool se_set_entropy(const void *entropy) { return false; }
bool se_set_mnemonic(const void *mnemonic, uint16_t len) { return false; }
bool se_sessionStart(OUT uint8_t *session_id_bytes) { return false; }
bool se_sessionOpen(IN uint8_t *session_id_bytes) { return false; }
bool se_sessionGens(uint8_t *pass_phase, uint16_t len, uint8_t mode) {
  return false;
}
bool se_sessionClose(void) { return false; }
bool se_set_public_region(uint16_t offset, const void *val_dest, uint16_t len) {
  return false;
}
bool se_get_public_region(uint16_t offset, void *val_dest, uint16_t len) {
  return false;
}
bool se_set_private_region(uint16_t offset, const void *val_dest,
                           uint16_t len) {
  return false;
}
bool se_get_private_region(uint16_t offset, void *val_dest, uint16_t len) {
  return false;
}
bool se_ecdsa_sign_digest(uint8_t curve, uint32_t mode, uint8_t sec_genk,
                          uint8_t *hash, uint16_t hash_len, uint8_t *sig,
                          uint16_t max_len, uint16_t *len) {
  return false;
}
bool se_25519_sign_diget(uint8_t mode, uint8_t *hash, uint16_t hash_len,
                         uint8_t *sig, uint16_t max_len, uint16_t *len) {
  return false;
}
bool se_schnoor_sign_plain(uint8_t *data, uint16_t data_len, uint8_t *sig,
                           uint16_t max_len, uint16_t *len) {
  return false;
}
bool se_aes_128_encrypt(uint8_t mode, uint8_t *key, uint8_t *iv, uint8_t *send,
                        uint16_t send_len, uint8_t *recv, uint16_t *recv_len) {
  return false;
}
bool se_aes_128_decrypt(uint8_t mode, uint8_t *key, uint8_t *iv, uint8_t *send,
                        uint16_t send_len, uint8_t *recv, uint16_t *recv_len) {
  return false;
}

#endif
