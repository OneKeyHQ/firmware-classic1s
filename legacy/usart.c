/*
 * This file is part of the libopencm3 project.
 *
 * Copyright (C) 2009 Uwe Hermann <uwe@hermann-uwe.de>,
 * Copyright (C) 2011 Piotr Esden-Tempski <piotr@esden.net>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/usart.h>
#include <stdio.h>
#include <string.h>

#include "ble.h"
#include "compatible.h"
#include "usart.h"

// 500ms
#define USART_TIMEOUT 10000
#define UART_PACKET_MAX_LEN 128

#if (_SUPPORT_DEBUG_UART_)

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void uart_sendstring(char *pt) {
  while (*pt) usart_send_blocking(USART3, *pt++);
}

void uart_printf(char *fmt, ...) {
  va_list ap;
  char string[256];
  va_start(ap, fmt);
  vsprintf(string, fmt,
           ap);  // Use It Will Increase the code size, Reduce the efficiency
  uart_sendstring(string);
  va_end(ap);
}

static void vUART_HtoA(uint8_t *pucSrc, uint16_t usLen, uint8_t *pucDes) {
  uint16_t i, j;
  uint8_t mod = 1;  //,sign;

  for (i = 0, j = 0; i < 2 * usLen; i += 2, j++) {
    mod = (pucSrc[j] >> 4) & 0x0F;
    if (mod <= 9)
      pucDes[i] = mod + 48;
    else
      pucDes[i] = mod + 55;

    mod = pucSrc[j] & 0x0F;
    if (mod <= 9)
      pucDes[i + 1] = mod + 48;
    else
      pucDes[i + 1] = mod + 55;
  }
}

static void vUART_SendData(uint8_t *pucSendData, uint16_t usStrLen) {
  uint16_t i;
  for (i = 0; i < usStrLen; i++) {
    usart_send_blocking(USART3, pucSendData[i]);
  }
}

void uart_debug(char *pcMsg, uint8_t *pucSendData, uint16_t usStrLen) {
  uint8_t ucBuff[600];

  vUART_SendData((uint8_t *)pcMsg, strlen(pcMsg));
  if (pucSendData != NULL) {
    vUART_HtoA(pucSendData, usStrLen, ucBuff);
    vUART_SendData(ucBuff, usStrLen * 2);
  }
  vUART_SendData((uint8_t *)"\n", 1);
}

void usart_setup(void) {
  rcc_periph_clock_enable(RCC_USART3);
  rcc_periph_clock_enable(RCC_GPIOC);
  gpio_mode_setup(GPIOC, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO10);
  gpio_set_af(GPIOC, GPIO_AF7, GPIO10);

  /* Setup UART parameters. */
  usart_set_baudrate(USART3, 115200);
  usart_set_databits(USART3, 8);
  usart_set_stopbits(USART3, USART_STOPBITS_1);
  usart_set_parity(USART3, USART_PARITY_NONE);
  usart_set_flow_control(USART3, USART_FLOWCONTROL_NONE);
  usart_set_mode(USART3, USART_MODE_TX);

  /* Finally enable the USART. */
  usart_enable(USART3);
}

#endif

void ble_usart_init(void) {
  // enable USART clock
  rcc_periph_clock_enable(RCC_USART2);
  //	set GPIO for USART1
  rcc_periph_clock_enable(RCC_GPIOA);
  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO2 | GPIO3);
  gpio_set_af(GPIOA, GPIO_AF7, GPIO2 | GPIO3);

  usart_disable(BLE_UART);
  // usart2 set
  usart_set_baudrate(BLE_UART, 115200);
  usart_set_databits(BLE_UART, 8);
  usart_set_stopbits(BLE_UART, USART_STOPBITS_1);
  usart_set_parity(BLE_UART, USART_PARITY_NONE);
  usart_set_flow_control(BLE_UART, USART_FLOWCONTROL_NONE);
  usart_set_mode(BLE_UART, USART_MODE_TX_RX);
  usart_enable(BLE_UART);

  // set NVIC
  ble_usart_irq_set();
}

void ble_usart_irq_set(void) {
  // set NVIC
  nvic_set_priority(NVIC_USART2_IRQ, 0);
  nvic_enable_irq(NVIC_USART2_IRQ);
  usart_enable_rx_interrupt(BLE_UART);
}

void ble_usart_enable(void) { usart_enable(BLE_UART); }
void ble_usart_disable(void) { usart_disable(BLE_UART); }

void ble_usart_irq_enable(void) { usart_enable_rx_interrupt(BLE_UART); }
void ble_usart_irq_disable(void) { usart_disable_rx_interrupt(BLE_UART); }

void ble_usart_sendByte(uint8_t data) {
  usart_send_blocking(BLE_UART, data);
  while (!usart_get_flag(BLE_UART, USART_SR_TXE))
    ;
}

void ble_usart_send(uint8_t *buf, uint32_t len) {
  uint32_t i;
  for (i = 0; i < len; i++) {
    usart_send_blocking(BLE_UART, buf[i]);
    while (!usart_get_flag(BLE_UART, USART_SR_TXE))
      ;
  }
}

bool ble_read_byte(uint8_t *buf) {
  uint16_t tmp;
  if (usart_get_flag(BLE_UART, USART_SR_RXNE) != 0) {
    tmp = usart_recv(BLE_UART);
    buf[0] = (uint8_t)tmp;
    return true;
  }
  return false;
}

static uint8_t calXor(uint8_t *buf, uint32_t len) {
  uint8_t tmp = 0;
  uint32_t i;
  for (i = 0; i < len; i++) {
    tmp ^= buf[i];
  }
  return tmp;
}

static bool usart_read_bytes(uint8_t *buf, uint32_t len, uint32_t timeout) {
  for (uint32_t i = 0; i < len; i++) {
    while (usart_get_flag(BLE_UART, USART_SR_RXNE) == 0) {
      timeout--;
      if (timeout == 0) {
        return false;
      }
    }
    buf[i] = usart_recv(BLE_UART) & 0xff;
    timeout = USART_TIMEOUT;
  }
  return true;
}

extern trans_fifo ble_update_fifo;

static bool usart_rev_package(uint8_t *buf) {
  uint8_t len = 0;
  uint8_t *p_buf = buf;
  if (!usart_read_bytes(p_buf, 2, USART_TIMEOUT)) {
    return false;
  }
  if (p_buf[0] == 0x0B && p_buf[1] <= 100) {
    if (!fifo_write_no_overflow(&ble_update_fifo, p_buf, 2)) {
    }
    return false;
  }
  if (p_buf[0] != 0x5A || p_buf[1] != 0xA5) {
    return false;
  }
  p_buf += 2;
  if (!usart_read_bytes(p_buf, 2, USART_TIMEOUT)) {
    return false;
  }

  len = (p_buf[0] << 8) + p_buf[1];
  if (len > UART_PACKET_MAX_LEN - 5) {
    return false;
  }
  p_buf += 2;
  if (!usart_read_bytes(p_buf, len - 1, USART_TIMEOUT)) {
    return false;
  }
  p_buf += len - 1;
  if (!usart_read_bytes(p_buf, 1, USART_TIMEOUT)) {
    return false;
  }
  uint8_t xor = calXor(buf, len + 3);
  if (xor != *p_buf) {
    return false;
  }
  return true;
}

void usart2_isr(void) {
  uint8_t uart_buf[UART_PACKET_MAX_LEN] = {0};
  if (usart_get_flag(BLE_UART, USART_SR_RXNE) != 0) {
    if (usart_rev_package(uart_buf)) {
      ble_uart_poll(uart_buf);
    }
  }
}