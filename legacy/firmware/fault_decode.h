#ifndef ONEKEY_FIRMWARE_FAULT_DECODE_H
#define ONEKEY_FIRMWARE_FAULT_DECODE_H

#include <stdbool.h>
#include <stdint.h>

#define FAULT_DISPLAY_ROWS 8
#define FAULT_DISPLAY_COLS 24
#define FAULT_FRAME_BASIC_WORDS 8U
#define FAULT_FRAME_EXTENDED_WORDS 26U
#define FAULT_FRAME_MAX_WORDS 27U
#define FAULT_SNAPSHOT_FORMAT_VERSION 1U
#define FAULT_SNAPSHOT_MAGIC 0x46534e50U

typedef struct {
  uint32_t msp;
  uint32_t psp;
  uint32_t exc_return;
  uint32_t ipsr;
  uint32_t cfsr;
  uint32_t hfsr;
  uint32_t mmfar;
  uint32_t bfar;
  uint32_t icsr;
  uint32_t vtor;
  uint32_t shcsr;
  uint32_t dfsr;
  uint32_t afsr;
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
  bool raw_frame_available;
} fault_report_t;

typedef struct {
  uint32_t magic;
  uint32_t format_version;
  uint32_t size;
  uint32_t frame_address;
  uint32_t frame_word_count;
  uint32_t frame_expected_words;
  fault_report_t report;
  uint32_t frame_words[FAULT_FRAME_MAX_WORDS];
} fault_snapshot_t;

_Static_assert(sizeof(fault_snapshot_t) % sizeof(uint32_t) == 0U,
               "fault snapshot must be word-addressable");

uint32_t fault_exception_frame_words(const fault_capture_t *capture);
bool fault_exception_frame_readable(const fault_capture_t *capture,
                                    const fault_stack_bounds_t *bounds,
                                    uint32_t word_count);
fault_frame_status_t fault_exception_frame_status(
    const fault_capture_t *capture, const fault_stack_bounds_t *bounds);
bool fault_exception_frame_valid(const fault_capture_t *capture,
                                 const fault_stack_bounds_t *bounds);
void fault_report_set_frame(fault_report_t *report, const uint32_t frame[8],
                            const fault_stack_bounds_t *bounds);
void fault_report_format_rows(const fault_report_t *report,
                              char rows[FAULT_DISPLAY_ROWS]
                                       [FAULT_DISPLAY_COLS]);
uint32_t fault_snapshot_page_count(const fault_snapshot_t *snapshot);
void fault_snapshot_format_page(const fault_snapshot_t *snapshot,
                                uint32_t page,
                                char rows[FAULT_DISPLAY_ROWS]
                                         [FAULT_DISPLAY_COLS]);

#endif
