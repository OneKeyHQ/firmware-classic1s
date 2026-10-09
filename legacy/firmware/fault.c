#include "fault_decode.h"

#include <stdint.h>

#include "oled.h"
#include "sys.h"
#include "version.h"

extern uint8_t _heap_end[];
extern uint8_t _stack[];
extern uint8_t fault_emergency_stack_bottom[];
extern uint8_t fault_emergency_stack_top[];
extern void fault_terminal_halt(void) __attribute__((noreturn));

#define SCB_CFSR_ADDRESS  0xe000ed28U
#define SCB_HFSR_ADDRESS  0xe000ed2cU
#define SCB_MMFAR_ADDRESS 0xe000ed34U
#define SCB_BFAR_ADDRESS  0xe000ed38U

static fault_report_t fault_report;
static char fault_rows[FAULT_DISPLAY_ROWS][FAULT_DISPLAY_COLS];
static const uint8_t fault_revision[] = SCM_REVISION;

static uint32_t fault_read_register(uint32_t address) {
  return *(volatile const uint32_t *)(uintptr_t)address;
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
  fault_report.frame_available = false;
  fault_report.frame_status = FAULT_FRAME_EXC_RETURN;
  fault_report.firmware_version = ONEKEY_VERSION;
  fault_report.revision =
      ((uint32_t)fault_revision[0] << 24) |
      ((uint32_t)fault_revision[1] << 16) |
      ((uint32_t)fault_revision[2] << 8) | (uint32_t)fault_revision[3];
  fault_report.pc = 0;
  fault_report.lr = 0;
  fault_report.xpsr = 0;

  const fault_stack_bounds_t bounds = {
      .stack_low = (uint32_t)(uintptr_t)_heap_end,
      .stack_high = (uint32_t)(uintptr_t)_stack,
      .emergency_low = (uint32_t)(uintptr_t)fault_emergency_stack_bottom,
      .emergency_high = (uint32_t)(uintptr_t)fault_emergency_stack_top,
  };
  fault_report.frame_status =
      fault_exception_frame_status(&fault_report.capture, &bounds);
  if (fault_report.frame_status == FAULT_FRAME_OK) {
    const uint32_t selected_sp =
        (exc_return & 4U) != 0U ? psp : msp;
    const uint32_t *frame = (const uint32_t *)(uintptr_t)selected_sp;
    fault_report_set_frame(&fault_report, frame, &bounds);
  }

  fault_report_format_rows(&fault_report, fault_rows);
  oledDrawFault(fault_rows);
  ble_power_off();
  se_power_off();
  fault_terminal_halt();
}
