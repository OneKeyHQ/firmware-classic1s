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
#include <libopencm3/stm32/dma.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/usart.h>
#include <stdio.h>
#include <string.h>

#include "ble.h"
#include "compatible.h"
#include "timer.h"
#include "usart.h"

#define UART_PACKET_MAX_LEN 128

#define USART_DMA_RX_BUFFER_SIZE 256

static uint8_t usart_dma_rx_buffer[USART_DMA_RX_BUFFER_SIZE];
static volatile uint16_t usart_dma_rx_read_pos = 0;

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
  nvic_disable_irq(NVIC_USART2_IRQ);

  usart_disable(BLE_UART);
  usart_disable_rx_dma(BLE_UART);

  dma_disable_stream(DMA1, DMA_STREAM5);
  dma_stream_reset(DMA1, DMA_STREAM5);

  rcc_periph_clock_enable(RCC_USART2);
  rcc_periph_clock_enable(RCC_DMA1);
  rcc_periph_clock_enable(RCC_GPIOA);

  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO2 | GPIO3);
  gpio_set_af(GPIOA, GPIO_AF7, GPIO2 | GPIO3);
  // usart2 set
  usart_set_baudrate(BLE_UART, 115200);
  usart_set_databits(BLE_UART, 8);
  usart_set_stopbits(BLE_UART, USART_STOPBITS_1);
  usart_set_parity(BLE_UART, USART_PARITY_NONE);
  usart_set_flow_control(BLE_UART, USART_FLOWCONTROL_NONE);
  usart_set_mode(BLE_UART, USART_MODE_TX_RX);

  dma_set_peripheral_address(DMA1, DMA_STREAM5, (uint32_t)&USART_DR(BLE_UART));
  dma_set_memory_address(DMA1, DMA_STREAM5, (uint32_t)usart_dma_rx_buffer);
  dma_set_number_of_data(DMA1, DMA_STREAM5, USART_DMA_RX_BUFFER_SIZE);

  dma_set_transfer_mode(DMA1, DMA_STREAM5, DMA_SxCR_DIR_PERIPHERAL_TO_MEM);
  dma_disable_peripheral_increment_mode(DMA1, DMA_STREAM5);
  dma_enable_memory_increment_mode(DMA1, DMA_STREAM5);
  dma_set_peripheral_size(DMA1, DMA_STREAM5, DMA_SxCR_PSIZE_8BIT);
  dma_set_memory_size(DMA1, DMA_STREAM5, DMA_SxCR_MSIZE_8BIT);
  dma_set_priority(DMA1, DMA_STREAM5, DMA_SxCR_PL_VERY_HIGH);

  dma_channel_select(DMA1, DMA_STREAM5, DMA_SxCR_CHSEL_4);
  dma_enable_circular_mode(DMA1, DMA_STREAM5);

  memset((void *)usart_dma_rx_buffer, 0, USART_DMA_RX_BUFFER_SIZE);
  usart_dma_rx_read_pos = 0;

  ble_usart_irq_set();

  usart_enable(BLE_UART);
  usart_enable_rx_dma(BLE_UART);
  dma_enable_stream(DMA1, DMA_STREAM5);
}

void ble_usart_irq_set(void) {
  nvic_set_priority(NVIC_USART2_IRQ, 0);
  nvic_enable_irq(NVIC_USART2_IRQ);

  usart_enable_idle_interrupt(BLE_UART);

  usart_disable_rx_interrupt(BLE_UART);
}

void ble_usart_enable(void) { usart_enable(BLE_UART); }
void ble_usart_disable(void) { usart_disable(BLE_UART); }

void ble_usart_irq_enable(void) { usart_enable_idle_interrupt(BLE_UART); }
void ble_usart_irq_disable(void) { usart_disable_idle_interrupt(BLE_UART); }

void ble_usart_disable_dma(void) {
  usart_disable_rx_dma(BLE_UART);
  dma_disable_stream(DMA1, DMA_STREAM5);
}

void ble_usart_sendByte(uint8_t data) {
  usart_send_blocking(BLE_UART, data);
  while (!usart_get_flag(BLE_UART, USART_SR_TXE));
}

void ble_usart_send(uint8_t *buf, uint32_t len) {
  uint32_t i;
  for (i = 0; i < len; i++) {
    usart_send_blocking(BLE_UART, buf[i]);
    while (!usart_get_flag(BLE_UART, USART_SR_TXE));
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

extern trans_fifo ble_update_fifo;

void usart_process_dma_rx(void) {
  uint16_t dma_remaining = dma_get_number_of_data(DMA1, DMA_STREAM5);

  uint16_t write_pos =
      (USART_DMA_RX_BUFFER_SIZE - dma_remaining) % USART_DMA_RX_BUFFER_SIZE;

  uint16_t read_pos = usart_dma_rx_read_pos;

  if (write_pos == read_pos) {
    return;
  }

  uint16_t available = 0;
  if (write_pos > read_pos) {
    available = write_pos - read_pos;
  } else {
    available = USART_DMA_RX_BUFFER_SIZE - read_pos + write_pos;
  }

  uint16_t processed = 0;
  uint16_t current_pos = read_pos;

  while (processed < available) {
    if (available - processed < 2) {
      break;
    }
    uint8_t byte0 = usart_dma_rx_buffer[current_pos];
    uint8_t byte1 =
        usart_dma_rx_buffer[(current_pos + 1) % USART_DMA_RX_BUFFER_SIZE];

    if (byte0 == 0x0B && byte1 <= 100) {
      fifo_write_no_overflow(&ble_update_fifo,
                             usart_dma_rx_buffer + current_pos, 2);
      current_pos = (current_pos + 2) % USART_DMA_RX_BUFFER_SIZE;
      processed += 2;
      continue;
    }

    if (available - processed < 4) {
      break;
    }

    if (byte0 != 0x5A || byte1 != 0xA5) {
      current_pos = (current_pos + 1) % USART_DMA_RX_BUFFER_SIZE;
      processed++;
      continue;
    }

    uint8_t byte2 =
        usart_dma_rx_buffer[(current_pos + 2) % USART_DMA_RX_BUFFER_SIZE];
    uint8_t byte3 =
        usart_dma_rx_buffer[(current_pos + 3) % USART_DMA_RX_BUFFER_SIZE];
    uint16_t packet_len = ((uint16_t)byte2 << 8) | byte3;
    uint16_t total_packet_len = 4 + packet_len;

    if (total_packet_len > UART_PACKET_MAX_LEN || total_packet_len == 0) {
      current_pos = (current_pos + 1) % USART_DMA_RX_BUFFER_SIZE;
      processed++;
      continue;
    }

    if (available - processed < total_packet_len) {
      break;
    }

    uint8_t packet_buf[UART_PACKET_MAX_LEN];
    for (uint16_t i = 0; i < total_packet_len; i++) {
      packet_buf[i] =
          usart_dma_rx_buffer[(current_pos + i) % USART_DMA_RX_BUFFER_SIZE];
    }

    uint8_t xor = calXor(packet_buf, total_packet_len - 1);
    uint8_t received_xor = packet_buf[total_packet_len - 1];

    if (xor != received_xor) {
      current_pos = (current_pos + 1) % USART_DMA_RX_BUFFER_SIZE;
      processed++;
      continue;
    }

    ble_uart_poll(packet_buf);

    current_pos = (current_pos + total_packet_len) % USART_DMA_RX_BUFFER_SIZE;
    processed += total_packet_len;
  }

  usart_dma_rx_read_pos = current_pos;
}

void usart2_isr(void) {
  uint32_t isr = USART_SR(BLE_UART);
  volatile uint8_t temp;

  if (isr & USART_SR_IDLE) {
    temp = USART_DR(BLE_UART);
    (void)temp;
    usart_process_dma_rx();
  }

  if (isr & (USART_SR_ORE | USART_SR_FE | USART_SR_NE)) {
    temp = USART_DR(BLE_UART);
    (void)temp;
  }
}
