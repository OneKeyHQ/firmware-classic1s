#ifndef __THD89_H__
#define __THD89_H__

#include "mi2c.h"
#include "secbool.h"

#define THD89_STATE_BOOT 0x00
#define THD89_STATE_NOT_ACTIVATED 0x33
#define THD89_STATE_APP 0x55

secbool thd89_transmit(uint8_t *cmd, uint16_t len, uint8_t *resp,
                       uint16_t *resp_len);
uint16_t thd89_last_error(void);

#endif
