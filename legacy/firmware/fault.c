#include "fault_decode.h"

#include <stdint.h>

#include <libopencm3/stm32/dma.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/usart.h>

#include "../compatible.h"
#include "oled.h"
#include "sys.h"
#include "version.h"

extern uint8_t _heap_end[];
extern uint8_t _stack[];
extern uint8_t fault_emergency_stack_bottom[];
extern uint8_t fault_emergency_stack_top[];
extern void fault_terminal_halt(uint32_t preserve_start, uint32_t preserve_end)
    __attribute__((noreturn));

#define SCB_CFSR_ADDRESS  0xe000ed28U
#define SCB_HFSR_ADDRESS  0xe000ed2cU
#define SCB_MMFAR_ADDRESS 0xe000ed34U
#define SCB_BFAR_ADDRESS  0xe000ed38U
#define SCB_ICSR_ADDRESS  0xe000ed04U
#define SCB_VTOR_ADDRESS  0xe000ed08U
#define SCB_SHCSR_ADDRESS 0xe000ed24U
#define SCB_DFSR_ADDRESS  0xe000ed30U
#define SCB_AFSR_ADDRESS  0xe000ed3cU
#define XPSR_STACKALIGN_BIT (1U << 9)

static fault_report_t fault_report;
static char fault_rows[FAULT_DISPLAY_ROWS][FAULT_DISPLAY_COLS];
static const uint8_t fault_revision[] = SCM_REVISION;

volatile fault_snapshot_t fault_snapshot
    __attribute__((aligned(8), used));

static uint32_t fault_read_register(uint32_t address) {
  return *(volatile const uint32_t *)(uintptr_t)address;
}

static void fault_stop_rx_dma(void) {
  if ((RCC_APB1ENR & RCC_APB1ENR_USART2EN) != 0U) {
    USART_CR3(BLE_UART) &= ~USART_CR3_DMAR;
  }
  if ((RCC_AHB1ENR & RCC_AHB1ENR_DMA1EN) != 0U) {
    DMA1_S5CR &= ~DMA_SxCR_EN;
  }
  __asm__ volatile("dsb" ::: "memory");
}

static void fault_snapshot_begin(void) {
  fault_snapshot.magic = 0U;
  fault_snapshot.format_version = 0U;
  fault_snapshot.size = 0U;
  fault_snapshot.frame_address = 0U;
  fault_snapshot.frame_word_count = 0U;
  fault_snapshot.frame_expected_words = 0U;
  for (uint32_t word = 0U; word < FAULT_FRAME_MAX_WORDS; word++) {
    fault_snapshot.frame_words[word] = 0U;
  }
}

static void fault_snapshot_commit(void) {
  fault_snapshot.format_version = FAULT_SNAPSHOT_FORMAT_VERSION;
  fault_snapshot.size = sizeof(fault_snapshot);
  fault_snapshot.report = fault_report;
  __asm__ volatile("dsb" ::: "memory");
  fault_snapshot.magic = FAULT_SNAPSHOT_MAGIC;
}

static void fault_snapshot_copy(fault_snapshot_t *copy) {
  const volatile uint8_t *source =
      (const volatile uint8_t *)(const void *)&fault_snapshot;
  uint8_t *destination = (uint8_t *)(void *)copy;
  for (uint32_t byte = 0U; byte < sizeof(*copy); byte++) {
    destination[byte] = source[byte];
  }
}

static void fault_display_delay(void) {
  for (volatile uint32_t delay = 0x4000U; delay != 0U; delay--) {
    __asm__ volatile("nop");
  }
}

static void __attribute__((noreturn)) fault_request_reset(void) {
  volatile uint32_t *const aircr = (volatile uint32_t *)(uintptr_t)0xe000ed0cU;
  const uint32_t prigroup = *aircr & 0x700U;
  *aircr = prigroup | 0x05fa0004U;
  __asm__ volatile("dsb\n\tisb" ::: "memory");
  for (;;) {
  }
}

void __attribute__((noreturn, no_stack_protector, used)) fault_display_loop(
    void) {
  fault_snapshot_t snapshot;
  uint32_t page = 0U;
  uint32_t page_count;
  uint32_t nav_release_count = 0U;
  uint32_t nav_press_count = 0U;
  uint32_t nav_button = 0U;
  uint32_t power_release_count = 0U;
  uint32_t power_press_count = 0U;
  bool nav_armed = false;
  bool power_armed = false;

  fault_snapshot_copy(&snapshot);
  page_count = fault_snapshot_page_count(&snapshot);
  fault_snapshot_format_page(&snapshot, page, fault_rows);
  oledDrawFault(fault_rows);

  for (;;) {
    const bool up_pressed = gpio_get(BTN_PORT, BTN_PIN_UP) == 0U;
    const bool down_pressed = gpio_get(BTN_PORT, BTN_PIN_DOWN) == 0U;
    const bool power_pressed =
        gpio_get(BTN_POWER_PORT, BTN_POWER_PIN) != 0U;

    if (!power_pressed) {
      if (power_press_count != 0U) power_armed = false;
      if (power_release_count < 8U) power_release_count++;
      if (power_release_count == 8U) power_armed = true;
      power_press_count = 0U;
    } else if (power_armed) {
      power_release_count = 0U;
      if (power_press_count < 8U) power_press_count++;
      if (power_press_count == 8U) fault_request_reset();
    } else {
      power_release_count = 0U;
      power_press_count = 0U;
    }

    if (!up_pressed && !down_pressed) {
      if (nav_release_count < 8U) nav_release_count++;
      if (nav_release_count == 8U) nav_armed = true;
      nav_press_count = 0U;
      nav_button = 0U;
    } else if (up_pressed != down_pressed && nav_armed) {
      nav_release_count = 0U;
      const uint32_t button = up_pressed ? 1U : 2U;
      if (button != nav_button) {
        nav_button = button;
        nav_press_count = 1U;
      } else if (nav_press_count < 8U) {
        nav_press_count++;
      }
      if (nav_press_count == 8U) {
        if (button == 1U) {
          page = page == 0U ? page_count - 1U : page - 1U;
        } else {
          page = page + 1U == page_count ? 0U : page + 1U;
        }
        nav_armed = false;
        nav_release_count = 0U;
        nav_press_count = 0U;
        fault_snapshot_format_page(&snapshot, page, fault_rows);
        oledDrawFault(fault_rows);
      }
    } else {
      nav_armed = false;
      nav_release_count = 0U;
      nav_press_count = 0U;
      nav_button = 0U;
    }
    fault_display_delay();
  }
}

void __attribute__((noreturn)) fault_handler_main(uint32_t msp, uint32_t psp,
                                                   uint32_t exc_return,
                                                   uint32_t ipsr) {
  fault_report.capture.msp = msp;
  fault_report.capture.psp = psp;
  fault_report.capture.exc_return = exc_return;
  fault_report.capture.ipsr = ipsr;
  fault_report.capture.cfsr = fault_read_register(SCB_CFSR_ADDRESS);
  fault_report.capture.hfsr = fault_read_register(SCB_HFSR_ADDRESS);
  fault_report.capture.mmfar = fault_read_register(SCB_MMFAR_ADDRESS);
  fault_report.capture.bfar = fault_read_register(SCB_BFAR_ADDRESS);
  fault_report.capture.icsr = fault_read_register(SCB_ICSR_ADDRESS);
  fault_report.capture.vtor = fault_read_register(SCB_VTOR_ADDRESS);
  fault_report.capture.shcsr = fault_read_register(SCB_SHCSR_ADDRESS);
  fault_report.capture.dfsr = fault_read_register(SCB_DFSR_ADDRESS);
  fault_report.capture.afsr = fault_read_register(SCB_AFSR_ADDRESS);
  fault_stop_rx_dma();
  fault_report.frame_available = false;
  fault_report.raw_frame_available = false;
  fault_report.frame_status = FAULT_FRAME_EXC_RETURN;
  fault_report.firmware_version = ONEKEY_VERSION;
  fault_report.revision =
      ((uint32_t)fault_revision[0] << 24) |
      ((uint32_t)fault_revision[1] << 16) |
      ((uint32_t)fault_revision[2] << 8) | (uint32_t)fault_revision[3];
  fault_report.pc = 0;
  fault_report.lr = 0;
  fault_report.xpsr = 0;

  fault_snapshot_begin();

  const fault_stack_bounds_t bounds = {
      .stack_low = (uint32_t)(uintptr_t)_heap_end,
      .stack_high = (uint32_t)(uintptr_t)_stack,
      .emergency_low = (uint32_t)(uintptr_t)fault_emergency_stack_bottom,
      .emergency_high = (uint32_t)(uintptr_t)fault_emergency_stack_top,
  };
  fault_report.frame_status =
      fault_exception_frame_status(&fault_report.capture, &bounds);
  const uint32_t base_words =
      fault_exception_frame_words(&fault_report.capture);
  const uint32_t selected_sp = (exc_return & 4U) != 0U ? psp : msp;
  if (base_words != 0U) {
    fault_snapshot.frame_address = selected_sp;
    fault_snapshot.frame_expected_words = base_words;
  }
  if (base_words != 0U &&
      fault_exception_frame_readable(&fault_report.capture, &bounds,
                                     base_words)) {
    uint32_t core_frame[FAULT_FRAME_BASIC_WORDS];
    const volatile uint32_t *frame =
        (const volatile uint32_t *)(uintptr_t)selected_sp;
    for (uint32_t word = 0U; word < base_words; word++) {
      const uint32_t value = frame[word];
      fault_snapshot.frame_words[word] = value;
      if (word < FAULT_FRAME_BASIC_WORDS) core_frame[word] = value;
    }
    fault_snapshot.frame_word_count = base_words;
    fault_snapshot.frame_expected_words = base_words;
    if ((core_frame[7] & XPSR_STACKALIGN_BIT) != 0U) {
      fault_snapshot.frame_expected_words = base_words + 1U;
      if (fault_exception_frame_readable(&fault_report.capture, &bounds,
                                         base_words + 1U)) {
        fault_snapshot.frame_words[base_words] = frame[base_words];
        fault_snapshot.frame_word_count = base_words + 1U;
      } else if (fault_report.frame_status == FAULT_FRAME_OK) {
        fault_report.frame_status = FAULT_FRAME_STACK_PADDING;
      }
    }
    fault_report_set_frame(&fault_report, core_frame, &bounds);
  }

  fault_snapshot_commit();

  fault_report_format_rows(&fault_report, fault_rows);
  oledDrawFault(fault_rows);
  ble_power_off();
  se_power_off();
  fault_terminal_halt((uint32_t)(uintptr_t)&fault_snapshot,
                      (uint32_t)(uintptr_t)&fault_snapshot +
                          sizeof(fault_snapshot));
}
