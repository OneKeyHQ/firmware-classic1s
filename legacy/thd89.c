#include "thd89.h"
#include "common.h"
#include "mi2c.h"
#include "sys.h"
#include "usart.h"

static secbool thd89_transmit_with_policy(const uint8_t *cmd, uint16_t len,
                                          uint8_t *resp, uint16_t *resp_len,
                                          uint16_t *sw1sw2, bool fatal) {
  if (!bMI2CDRV_SendDataRaw(cmd, len, fatal)) {
    return secfalse;
  }

  hal_delay(1);
  if (!bMI2CDRV_ReceiveDataRaw(resp, resp_len, sw1sw2, fatal)) {
    return secfalse;
  }
  return sectrue;
}

secbool thd89_transmit_raw(const uint8_t *cmd, uint16_t len, uint8_t *resp,
                           uint16_t *resp_len, uint16_t *sw1sw2) {
  return thd89_transmit_with_policy(cmd, len, resp, resp_len, sw1sw2, true);
}

secbool thd89_try_transmit_raw(const uint8_t *cmd, uint16_t len, uint8_t *resp,
                               uint16_t *resp_len, uint16_t *sw1sw2) {
  return thd89_transmit_with_policy(cmd, len, resp, resp_len, sw1sw2, false);
}

secbool thd89_transmit(const uint8_t *cmd, uint16_t len, uint8_t *resp,
                       uint16_t *resp_len) {
  uint16_t sw1sw2 = 0;

  if (thd89_transmit_raw(cmd, len, resp, resp_len, &sw1sw2) == secfalse ||
      sw1sw2 != 0x9000) {
    return secfalse;
  }
  return sectrue;
}

void thd89_power_off(void) { se_power_off(); }
void thd89_power_on(void) { se_power_on(); }

uint16_t thd89_last_error() { return get_lasterror(); };
