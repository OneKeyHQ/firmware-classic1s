#ifndef ONEKEY_FIRMWARE_FAULT_DECODE_H
#define ONEKEY_FIRMWARE_FAULT_DECODE_H

#include <stdbool.h>
#include <stdint.h>

#define FAULT_DISPLAY_ROWS 8
#define FAULT_DISPLAY_COLS 24

typedef struct {
  uint32_t msp;
  uint32_t psp;
  uint32_t exc_return;
  uint32_t ipsr;
  uint32_t cfsr;
  uint32_t hfsr;
  uint32_t mmfar;
  uint32_t bfar;
} fault_capture_t;

typedef struct {
  uint32_t stack_low;
  uint32_t stack_high;
  uint32_t emergency_low;
  uint32_t emergency_high;
} fault_stack_bounds_t;

typedef enum {
  FAULT_FRAME_OK,
  FAULT_FRAME_EXC_RETURN,
  FAULT_FRAME_EXTENDED,
  FAULT_FRAME_STACK_STATUS,
  FAULT_FRAME_STACK_RANGE,
  FAULT_FRAME_STACK_PADDING,
  FAULT_FRAME_XPSR,
} fault_frame_status_t;

typedef struct {
  fault_capture_t capture;
  uint32_t pc;
  uint32_t lr;
  uint32_t xpsr;
  uint32_t revision;
  const char *firmware_version;
  fault_frame_status_t frame_status;
  bool frame_available;
} fault_report_t;

fault_frame_status_t fault_exception_frame_status(
    const fault_capture_t *capture, const fault_stack_bounds_t *bounds);
bool fault_exception_frame_valid(const fault_capture_t *capture,
                                 const fault_stack_bounds_t *bounds);
void fault_report_set_frame(fault_report_t *report, const uint32_t frame[8],
                            const fault_stack_bounds_t *bounds);
void fault_report_format_rows(const fault_report_t *report,
                              char rows[FAULT_DISPLAY_ROWS]
                                       [FAULT_DISPLAY_COLS]);

#endif
