#include <stdint.h>
#include <string.h>

#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/i2c.h>
#include <libopencm3/stm32/rcc.h>
#include <vendor/libopencm3/include/libopencmsis/core_cm3.h>

#include "common.h"
#include "compatible.h"
#include "mi2c.h"
#include "mi2c_frame.h"
#include "secbool.h"
#include "timer.h"
#include "usart.h"

uint16_t g_lasterror;  // TODO:will change in encrypt+MAC
uint16_t i2c_retry_cnts = 0;

static uint8_t ucXorCheck(uint8_t ucInputXor, const uint8_t *pucSrc,
                          uint16_t usLen) {
  uint16_t i;
  uint8_t ucXor;

  ucXor = ucInputXor;
  for (i = 0; i < usLen; i++) {
    ucXor ^= pucSrc[i];
  }
  return ucXor;
}

static bool bMI2CDRV_WaitForRxNE(uint32_t i2c) {
  uint32_t timeout = 0;

  while (!(I2C_SR1(i2c) & I2C_SR1_RxNE)) {
    if (++timeout > MI2C_TIMEOUT) {
      return false;
    }
  }
  return true;
}

static int bMI2CDRV_AbortRead(uint32_t i2c, uint8_t *res, uint16_t received_len,
                              uint16_t *pusOutLen) {
  if (res != NULL && received_len != 0) {
    memset(res, 0, received_len);
  }
  *pusOutLen = 0;
  i2c_disable_ack(i2c);
  i2c_send_stop(i2c);
  return -1;
}

static int bMI2CDRV_ReadBytes(uint32_t i2c, uint8_t *res, uint16_t *pusOutLen,
                              uint16_t *sw1sw2) {
  uint8_t ucLenBuf[2], ucSW[2], ucXor = 0, ucXor1 = 0;
  uint16_t i, usRevLen, usTimeout = 0;
  uint16_t caller_capacity;
  bool invalid_frame = false;

  caller_capacity = *pusOutLen;
  *pusOutLen = 0;
  if (sw1sw2 != NULL) {
    *sw1sw2 = 0;
  }
  i2c_retry_cnts = 0;
  while (1) {
    if (i2c_retry_cnts > MI2C_RETRYCNTS) {
      return -1;
    }

    // send start
    i2c_send_start(i2c);
    i2c_enable_ack(i2c);
    usTimeout = 0;
    while (!(I2C_SR1(i2c) & I2C_SR1_SB)) {
      usTimeout++;
      if (usTimeout > MI2C_TIMEOUT) {  // setup timeout is 5ms once
        break;
      }
    }
    if (usTimeout > MI2C_TIMEOUT) {
      i2c_retry_cnts++;
      i2c_send_stop(i2c);
      delay_ms(2);
      continue;
    }
    // send read address
    i2c_send_7bit_address(i2c, MI2C_ADDR, MI2C_READ);
    usTimeout = 0;
    // Waiting for address is transferred.
    while (!(I2C_SR1(i2c) & I2C_SR1_ADDR)) {
      usTimeout++;
      if (usTimeout > MI2C_ADDR_ACK_TIMEOUT) {  // setup timeout is 5ms once
        break;
      }
    }
    if (usTimeout > MI2C_ADDR_ACK_TIMEOUT) {
      usTimeout = 0;
      i2c_retry_cnts++;
      i2c_send_stop(i2c);  // it will release i2c bus
      delay_ms(2);
      continue;
    }
    /* Clearing ADDR condition sequence. */
    (void)I2C_SR1(i2c);
    (void)I2C_SR2(i2c);
    break;
  }
  // rev len
  for (i = 0; i < 2; i++) {
    if (!bMI2CDRV_WaitForRxNE(i2c)) {
      return bMI2CDRV_AbortRead(i2c, NULL, 0, pusOutLen);
    }
    ucLenBuf[i] = i2c_get_data(i2c);
  }
  // cal len xor
  ucXor = ucXorCheck(ucXor, ucLenBuf, sizeof(ucLenBuf));

  if (!mi2c_frame_payload_length((ucLenBuf[0] << 8) + ucLenBuf[1],
                                 caller_capacity, TRANSPORT_MAX_RESPONSE,
                                 &usRevLen) ||
      (usRevLen > 0 && res == NULL)) {
    invalid_frame = true;
  }
  if (invalid_frame) {
    return bMI2CDRV_AbortRead(i2c, NULL, 0, pusOutLen);
  }

  // rev data
  for (i = 0; i < usRevLen; i++) {
    if (!bMI2CDRV_WaitForRxNE(i2c)) {
      return bMI2CDRV_AbortRead(i2c, res, i, pusOutLen);
    }
    res[i] = i2c_get_data(i2c);
    ucXor = ucXorCheck(ucXor, res + i, 1);
  }

  // sw1 sw2 len
  for (i = 0; i < 2; i++) {
    if (!bMI2CDRV_WaitForRxNE(i2c)) {
      return bMI2CDRV_AbortRead(i2c, res, usRevLen, pusOutLen);
    }
    ucSW[i] = i2c_get_data(i2c);
  }
  // cal sw1sw2 xor
  ucXor = ucXorCheck(ucXor, ucSW, sizeof(ucSW));

  // xor len
  i2c_disable_ack(i2c);
  for (i = 0; i < MI2C_XOR_LEN; i++) {
    if (!bMI2CDRV_WaitForRxNE(i2c)) {
      return bMI2CDRV_AbortRead(i2c, res, usRevLen, pusOutLen);
    }
    ucXor1 = i2c_get_data(i2c);
  }

  i2c_send_stop(i2c);
  if (ucXor != ucXor1) {
    if (res != NULL && usRevLen != 0) {
      memset(res, 0, usRevLen);
    }
    *pusOutLen = 0;
    return -1;
  }
  g_lasterror = (ucSW[0] << 8) + ucSW[1];
  if (sw1sw2 != NULL) {
    *sw1sw2 = g_lasterror;
  }
  if ((0x90 != ucSW[0]) || (0x00 != ucSW[1])) {
    *pusOutLen = usRevLen;
    return 1;
  }
  *pusOutLen = usRevLen;
  return 0;
}

static bool bMI2CDRV_WriteBytes(uint32_t i2c, const uint8_t *data,
                                uint16_t ucSendLen) {
  uint8_t ucLenBuf[2], ucXor = 0;
  uint16_t i, usTimeout = 0;

  i2c_retry_cnts = 0;
  while (1) {
    if (i2c_retry_cnts > MI2C_RETRYCNTS) {
      return false;
    }

    i2c_send_start(i2c);
    usTimeout = 0;
    while (!(I2C_SR1(i2c) & I2C_SR1_SB)) {
      usTimeout++;
      if (usTimeout > MI2C_TIMEOUT) {
        break;
      }
    }
    if (usTimeout > MI2C_TIMEOUT) {
      i2c_retry_cnts++;
      i2c_send_stop(i2c);
      delay_ms(2);
      continue;
    }

    i2c_send_7bit_address(i2c, MI2C_ADDR, MI2C_WRITE);
    usTimeout = 0;
    // Waiting for address is transferred.
    while (!(I2C_SR1(i2c) & I2C_SR1_ADDR)) {
      usTimeout++;
      if (usTimeout > MI2C_ADDR_ACK_TIMEOUT) {
        break;
      }
    }
    if (usTimeout > MI2C_ADDR_ACK_TIMEOUT) {
      i2c_retry_cnts++;
      usTimeout = 0;
      i2c_send_stop(i2c);
      delay_ms(2);
      continue;
    }
    /* Clearing ADDR condition sequence. */
    (void)I2C_SR1(i2c);
    (void)I2C_SR2(i2c);
    break;
  }
  // send L + V + xor
  ucLenBuf[0] = ((ucSendLen >> 8) & 0xFF);
  ucLenBuf[1] = ucSendLen & 0xFF;
  // len xor
  ucXor = ucXorCheck(ucXor, ucLenBuf, sizeof(ucLenBuf));
  // send len
  for (i = 0; i < 2; i++) {
    i2c_send_data(i2c, ucLenBuf[i]);
    usTimeout = 0;
    while (!(I2C_SR1(i2c) & (I2C_SR1_TxE))) {
      usTimeout++;
      if (usTimeout > MI2C_TIMEOUT) {
        goto write_failed;
      }
    }
  }
  // cal xor
  ucXor = ucXorCheck(ucXor, data, ucSendLen);
  // send data
  for (i = 0; i < ucSendLen; i++) {
    i2c_send_data(i2c, data[i]);
    usTimeout = 0;
    while (!(I2C_SR1(i2c) & (I2C_SR1_TxE))) {
      usTimeout++;
      if (usTimeout > MI2C_TIMEOUT) {
        goto write_failed;
      }
    }
  }
  // send Xor
  i2c_send_data(i2c, ucXor);
  usTimeout = 0;
  while (!(I2C_SR1(i2c) & (I2C_SR1_TxE))) {
    usTimeout++;
    if (usTimeout > MI2C_TIMEOUT) {
      goto write_failed;
    }
  }

  i2c_send_stop(i2c);
  return true;

write_failed:
  i2c_send_stop(i2c);
  return false;
}

void vMI2CDRV_Init(void) {
  rcc_periph_clock_enable(RCC_I2C1);
  rcc_periph_clock_enable(RCC_GPIOB);

  gpio_set_output_options(GPIO_MI2C_PORT, GPIO_OTYPE_OD, GPIO_OSPEED_50MHZ,
                          GPIO_MI2C_SCL | GPIO_MI2C_SDA);
  gpio_set_af(GPIO_MI2C_PORT, GPIO_AF4, GPIO_MI2C_SCL | GPIO_MI2C_SDA);
  gpio_mode_setup(GPIO_MI2C_PORT, GPIO_MODE_AF, GPIO_PUPD_NONE,
                  GPIO_MI2C_SCL | GPIO_MI2C_SDA);
  i2c_reset(MI2CX);
  delay_ms(100);
  i2c_peripheral_disable(MI2CX);

  // 100k
  i2c_set_speed(MI2CX, i2c_speed_sm_100k, 30);
  i2c_peripheral_enable(MI2CX);
  delay_ms(100);
}

/*
 *master i2c rev
 */
bool bMI2CDRV_ReceiveData(uint8_t *pucStr, uint16_t *pusRevLen) {
  uint16_t sw1sw2 = 0;

  return bMI2CDRV_ReceiveDataRaw(pucStr, pusRevLen, &sw1sw2, true) &&
         sw1sw2 == 0x9000;
}
/*
 *master i2c send
 */
bool bMI2CDRV_SendData(uint8_t *pucStr, uint16_t usStrLen) {
  return bMI2CDRV_SendDataRaw(pucStr, usStrLen, true);
}

bool bMI2CDRV_ReceiveDataRaw(uint8_t *data, uint16_t *data_len,
                             uint16_t *sw1sw2, bool fatal) {
  int ret;
  uint16_t ignored_length = 0;

  if (data_len == NULL) {
    data_len = &ignored_length;
  }

  __disable_irq();
  ret = bMI2CDRV_ReadBytes(MI2CX, data, data_len, sw1sw2);
  __enable_irq();
  if (ret < 0) {
    if (fatal) {
      ensure(secfalse, "i2c read error");
    }
    return false;
  }
  return mi2c_frame_transport_success(ret);
}

bool bMI2CDRV_SendDataRaw(const uint8_t *data, uint16_t usStrLen, bool fatal) {
  if ((data == NULL && usStrLen != 0) || usStrLen > (MI2C_BUF_MAX_LEN - 3)) {
    return false;
  }
  __disable_irq();
  if (!bMI2CDRV_WriteBytes(MI2CX, data, usStrLen)) {
    __enable_irq();
    if (fatal) {
      ensure(secfalse, "i2c write error");
    }
    return false;
  }
  __enable_irq();
  return true;
}

uint16_t get_lasterror(void) { return g_lasterror; }
