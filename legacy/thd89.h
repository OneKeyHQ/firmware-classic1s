#ifndef __THD89_H__
#define __THD89_H__

#include <stdint.h>

#include "secbool.h"

#define THD89_STATE_BOOT 0x00
#define THD89_STATE_NOT_ACTIVATED 0x33
#define THD89_STATE_APP 0x55

secbool thd89_transmit(const uint8_t *cmd, uint16_t len, uint8_t *resp,
                       uint16_t *resp_len);
secbool thd89_transmit_raw(const uint8_t *cmd, uint16_t len, uint8_t *resp,
                           uint16_t *resp_len, uint16_t *sw1sw2);
secbool thd89_try_transmit_raw(const uint8_t *cmd, uint16_t len, uint8_t *resp,
                               uint16_t *resp_len, uint16_t *sw1sw2);
void thd89_power_off(void);
void thd89_power_on(void);
uint16_t thd89_last_error(void);

#endif
