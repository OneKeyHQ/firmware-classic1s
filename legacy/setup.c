/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <libopencm3/cm3/mpu.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/rng.h>
#include <libopencm3/stm32/spi.h>

#include "flash.h"
#include "layout.h"
#include "memory.h"
#include "mi2c.h"
#include "oled.h"
#include "rng.h"
#include "si2c.h"
#include "sys.h"
#include "timer.h"
#include "usart.h"
#include "util.h"

#include "compatible.h"

uint32_t __stack_chk_guard;

static inline void __attribute__((noreturn)) fault_handler(const char *line1) {
  layoutDialogCenterAdapterEx(&bmp_icon_error, NULL, NULL, NULL, line1,
                              "detected.", "Please unplug", "the device.");

  shutdown();
}

void __attribute__((noreturn)) __stack_chk_fail(void) {
  fault_handler("Stack smashing");
}

void nmi_handler(void) {
  // Clock Security System triggered NMI
  if ((RCC_CIR & RCC_CIR_CSSF) != 0) {
    fault_handler("Clock instability");
  }
}

void hard_fault_handler(void) { fault_handler("Hard fault"); }

void mem_manage_handler(void) { fault_handler("Memory fault"); }

void setup(void) {
  // set SCB_CCR STKALIGN bit to make sure 8-byte stack alignment on exception
  // entry is in effect. This is not strictly necessary for the current Trezor
  // system. This is here to comply with guidance from section 3.3.3 "Binary
  // compatibility with other Cortex processors" of the ARM Cortex-M3 Processor
  // Technical Reference Manual. According to section 4.4.2 and 4.4.7 of the
  // "STM32F10xxx/20xxx/21xxx/L1xxxx Cortex-M3 programming manual", STM32F2
  // series MCUs are r2p0 and always have this bit set on reset already.

  // gd32f470
  extern void SystemInit(void);
  SystemInit();
  // enable GPIO clock - A (oled), B(oled), C (buttons)
  rcc_periph_clock_enable(RCC_GPIOA);
  rcc_periph_clock_enable(RCC_GPIOB);
  rcc_periph_clock_enable(RCC_GPIOC);

  // enable SPI clock
  rcc_periph_clock_enable(RCC_OLED_SPI);

  // enable RNG
  rcc_periph_clock_enable(RCC_RNG);
  RNG_CR |= RNG_CR_RNGEN;

  // to be extra careful and heed the STM32F205xx Reference manual,
  // Section 20.3.1 we don't use the first random number generated after setting
  // the RNGEN bit in setup
  random32();

  // enable CSS (Clock Security System)
  RCC_CR |= RCC_CR_CSSON;

  // set GPIO for buttons
  gpio_mode_setup(BTN_PORT, GPIO_MODE_INPUT, GPIO_PUPD_PULLUP,
                  BTN_PIN_YES | BTN_PIN_UP | BTN_PIN_DOWN);
  gpio_mode_setup(BTN_PORT_NO, GPIO_MODE_INPUT, GPIO_PUPD_NONE, BTN_PIN_NO);

  // set GPIO for usb_insert
  gpio_mode_setup(USB_INSERT_PORT, GPIO_MODE_INPUT, GPIO_PUPD_NONE,
                  USB_INSERT_PIN);
  // stm32 power control
  gpio_mode_setup(STM32_POWER_CTRL_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_PULLDOWN,
                  STM32_POWER_CTRL_PIN);
  // bluetooth power control
  gpio_mode_setup(BLE_POWER_CTRL_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_PULLDOWN,
                  BLE_POWER_CTRL_PIN);
  // combus
  gpio_mode_setup(GPIO_CMBUS_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_PULLDOWN,
                  GPIO_SI2C_CMBUS);
  SET_COMBUS_LOW();
  // bluetooth power control
  gpio_mode_setup(BLE_CONNECT_PORT, GPIO_MODE_INPUT, GPIO_PUPD_PULLDOWN,
                  BLE_CONNECT_PIN);
  ble_power_off();
  // se power
  gpio_mode_setup(SE_POWER_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,
                  SE_POWER_PIN);
  se_power_off();
  delay_ms(10);
  se_power_on();

  // use libopencm3 init oled
  gpio_mode_setup(OLED_DC_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, OLED_DC_PIN);
  gpio_mode_setup(OLED_RST_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,
                  OLED_RST_PIN);
  gpio_set_af(OLED_CS_PORT, GPIO_AF5, OLED_SCK_PIN | OLED_MOSI_PIN);
  gpio_mode_setup(OLED_CS_PORT, GPIO_MODE_AF, GPIO_PUPD_NONE,
                  OLED_SCK_PIN | OLED_MOSI_PIN);
  gpio_set_output_options(OLED_CS_PORT, GPIO_OTYPE_PP, GPIO_OSPEED_25MHZ,
                          OLED_SCK_PIN | OLED_MOSI_PIN);
  gpio_mode_setup(OLED_CS_PORT, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO0);
  gpio_set_output_options(OLED_CS_PORT, GPIO_OTYPE_PP, GPIO_OSPEED_25MHZ,
                          GPIO0);

  spi_init_master(OLED_SPI_BASE, SPI_CR1_BAUDRATE_FPCLK_DIV_8,
                  SPI_CR1_CPOL_CLK_TO_0_WHEN_IDLE,
                  SPI_CR1_CPHA_CLK_TRANSITION_1, SPI_CR1_DFF_8BIT,
                  SPI_CR1_MSBFIRST);

  spi_enable_ss_output(OLED_SPI_BASE);

  OLED_NSS_HIGH;

  spi_enable(OLED_SPI_BASE);

  // enable OTG_FS
  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_PULLUP, GPIO10);
  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO11 | GPIO12);
  gpio_set_af(GPIOA, GPIO_AF10, GPIO10 | GPIO11 | GPIO12);

  // enable OTG FS clock
  rcc_periph_clock_enable(RCC_OTGFS);
  // clear USB OTG_FS peripheral dedicated RAM
  memset_reg((void *)0x50020000, (void *)0x50020500, 0);
#if (_SUPPORT_DEBUG_UART_)
  usart_setup();
#endif
  ble_usart_init();
  i2c_slave_init_irq();

  // master i2c init
  vMI2CDRV_Init();
}

void setReboot(void) {
  ble_usart_irq_set();
  i2c_slave_init_irq();
}

void setupApp(void) {
  // for completeness, disable RNG peripheral interrupts for old bootloaders
  // that had enabled them in RNG control register (the RNG interrupt was never
  // enabled in the NVIC)
  RNG_CR &= ~RNG_CR_IE;
  // the static variables in random32 are separate between the bootloader and
  // firmware. therefore, they need to be initialized here so that we can be
  // sure to avoid dupes. this is to try to comply with STM32F205xx Reference
  // manual - Section 20.3.1: "Each subsequent generated random number has to be
  // compared with the previously generated number. The test fails if any two
  // compared numbers are equal (continuous random number generator test)."
  random32();

  // enable CSS (Clock Security System)
  RCC_CR |= RCC_CR_CSSON;

  // hotfix for old bootloader
  gpio_mode_setup(GPIOA, GPIO_MODE_INPUT, GPIO_PUPD_NONE, GPIO9);
  spi_init_master(
      SPI1, SPI_CR1_BAUDRATE_FPCLK_DIV_8, SPI_CR1_CPOL_CLK_TO_0_WHEN_IDLE,
      SPI_CR1_CPHA_CLK_TRANSITION_1, SPI_CR1_DFF_8BIT, SPI_CR1_MSBFIRST);

  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_PULLUP, GPIO10);
  gpio_set_af(GPIOA, GPIO_AF10, GPIO10);

  // change oled refresh frequency
  oledUpdateClk();
  gd32_flash_init();

  ble_usart_init();
}

void mpu_config_off(void) {
  mpu_setup_gd32(MPU_CONFIG_OFF);
  __asm__ volatile("dsb");
  __asm__ volatile("isb");
}

void mpu_config_bootloader(void) { mpu_setup_gd32(MPU_CONFIG_BOOT); }

// Never use in bootloader! Disables access to PPB (including MPU, NVIC, SCB)
void mpu_config_firmware(void) { mpu_setup_gd32(MPU_CONFIG_FIRM); }
