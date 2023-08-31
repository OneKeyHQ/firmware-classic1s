#include "thd89.h"
#include "common.h"
#include "usart.h"

secbool thd89_transmit(uint8_t *cmd, uint16_t len, uint8_t *resp,
                       uint16_t *resp_len) {
  uart_debug("thd89 cmd ", cmd, 5);
  if (secfalse == bMI2CDRV_SendData(cmd, len)) {
    return secfalse;
  }

  hal_delay(1);
  if (secfalse == bMI2CDRV_ReceiveData(resp, resp_len)) {
    return secfalse;
  }
  return sectrue;
}

uint16_t thd89_last_error() { return get_lasterror(); };
