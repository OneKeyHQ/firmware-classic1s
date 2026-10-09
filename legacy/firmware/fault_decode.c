#include "fault_decode.h"

#include <stddef.h>

#define EXC_RETURN_HANDLER_MSP 0xfffffff1U
#define EXC_RETURN_THREAD_MSP  0xfffffff9U
#define EXC_RETURN_THREAD_PSP  0xfffffffdU
#define EXC_RETURN_HANDLER_MSP_EXTENDED 0xffffffe1U
#define EXC_RETURN_THREAD_MSP_EXTENDED  0xffffffe9U
#define EXC_RETURN_THREAD_PSP_EXTENDED  0xffffffedU

#define CFSR_MM_IACCVIOL       (1U << 0)
#define CFSR_MM_DACCVIOL       (1U << 1)
#define CFSR_MM_MUNSTKERR      (1U << 3)
#define CFSR_MM_MSTKERR        (1U << 4)
#define CFSR_MM_MLSPERR        (1U << 5)
#define CFSR_MM_MMARVALID      (1U << 7)
#define CFSR_BF_IBUSERR        (1U << 8)
#define CFSR_BF_PRECISERR      (1U << 9)
#define CFSR_BF_IMPRECISERR    (1U << 10)
#define CFSR_BF_UNSTKERR       (1U << 11)
#define CFSR_BF_STKERR         (1U << 12)
#define CFSR_BF_LSPERR         (1U << 13)
#define CFSR_BF_BFARVALID      (1U << 15)
#define CFSR_UF_UNDEFINSTR     (1U << 16)
#define CFSR_UF_INVSTATE       (1U << 17)
#define CFSR_UF_INVPC          (1U << 18)
#define CFSR_UF_NOCP           (1U << 19)
#define CFSR_UF_UNALIGNED      (1U << 24)
#define CFSR_UF_DIVBYZERO      (1U << 25)

#define HFSR_VECTTBL           (1U << 1)
#define HFSR_FORCED            (1U << 30)
#define HFSR_DEBUGEVT          (1U << 31)

#define XPSR_T_BIT             (1U << 24)
#define XPSR_STACKALIGN_BIT    (1U << 9)
#define XPSR_IPSR_MASK         0x1ffU
#define FRAME_WORDS            8U
#define FRAME_BYTES            (FRAME_WORDS * sizeof(uint32_t))
#define STACK_FRAME_FAULTS                                                    \
  (CFSR_MM_MUNSTKERR | CFSR_MM_MSTKERR | CFSR_MM_MLSPERR |                  \
   CFSR_BF_UNSTKERR | CFSR_BF_STKERR | CFSR_BF_LSPERR)

static bool exc_return_valid(uint32_t exc_return) {
  return exc_return == EXC_RETURN_HANDLER_MSP ||
         exc_return == EXC_RETURN_THREAD_MSP ||
         exc_return == EXC_RETURN_THREAD_PSP;
}

static bool exc_return_extended(uint32_t exc_return) {
  return exc_return == EXC_RETURN_HANDLER_MSP_EXTENDED ||
         exc_return == EXC_RETURN_THREAD_MSP_EXTENDED ||
         exc_return == EXC_RETURN_THREAD_PSP_EXTENDED;
}

static uint32_t selected_stack_pointer(const fault_capture_t *capture) {
  return (capture->exc_return & 4U) != 0U ? capture->psp : capture->msp;
}

static bool range_contains(uint32_t start, uint32_t end, uint32_t value,
                           uint32_t length) {
  if (start > end || value < start || value > end ||
      length > end - value) {
    return false;
  }
  return true;
}

static bool ranges_overlap(uint32_t first_start, uint32_t first_end,
                           uint32_t second_start, uint32_t second_end) {
  return first_start < second_end && second_start < first_end;
}

fault_frame_status_t fault_exception_frame_status(
    const fault_capture_t *capture, const fault_stack_bounds_t *bounds) {
  if (capture == NULL || bounds == NULL) return FAULT_FRAME_EXC_RETURN;
  if (exc_return_extended(capture->exc_return)) return FAULT_FRAME_EXTENDED;
  if (!exc_return_valid(capture->exc_return)) return FAULT_FRAME_EXC_RETURN;
  if ((capture->cfsr & STACK_FRAME_FAULTS) != 0U) {
    return FAULT_FRAME_STACK_STATUS;
  }

  const uint32_t sp = selected_stack_pointer(capture);
  if ((sp & 3U) != 0U ||
      !range_contains(bounds->stack_low, bounds->stack_high, sp,
                      FRAME_BYTES)) {
    return FAULT_FRAME_STACK_RANGE;
  }

  if (bounds->emergency_low > bounds->emergency_high ||
      ranges_overlap(sp, sp + FRAME_BYTES, bounds->emergency_low,
                     bounds->emergency_high)) {
    return FAULT_FRAME_STACK_RANGE;
  }
  return FAULT_FRAME_OK;
}

bool fault_exception_frame_valid(const fault_capture_t *capture,
                                 const fault_stack_bounds_t *bounds) {
  return fault_exception_frame_status(capture, bounds) == FAULT_FRAME_OK;
}

void fault_report_set_frame(fault_report_t *report, const uint32_t frame[8],
                            const fault_stack_bounds_t *bounds) {
  if (report == NULL || frame == NULL || bounds == NULL) return;

  report->lr = frame[5];
  report->pc = frame[6];
  report->xpsr = frame[7];
  const uint32_t stacked_ipsr = report->xpsr & XPSR_IPSR_MASK;
  const bool returns_to_handler =
      report->capture.exc_return == EXC_RETURN_HANDLER_MSP;
  if ((report->xpsr & XPSR_T_BIT) == 0U ||
      (returns_to_handler && stacked_ipsr == 0U) ||
      (!returns_to_handler && stacked_ipsr != 0U)) {
    report->frame_available = false;
    report->frame_status = FAULT_FRAME_XPSR;
    return;
  }
  if ((report->xpsr & XPSR_STACKALIGN_BIT) != 0U &&
      !range_contains(bounds->stack_low, bounds->stack_high,
                      selected_stack_pointer(&report->capture),
                      FRAME_BYTES + sizeof(uint32_t))) {
    report->frame_available = false;
    report->frame_status = FAULT_FRAME_STACK_PADDING;
    return;
  }
  report->frame_available = true;
}

static void row_clear(char row[FAULT_DISPLAY_COLS]) {
  for (uint32_t i = 0; i < FAULT_DISPLAY_COLS; i++) row[i] = '\0';
}

static void row_append(char row[FAULT_DISPLAY_COLS], uint32_t *position,
                       const char *text) {
  while (*text != '\0' && *position < FAULT_DISPLAY_COLS - 1U) {
    row[(*position)++] = *text++;
  }
}

static void row_hex(char row[FAULT_DISPLAY_COLS], uint32_t *position,
                    uint32_t value, bool valid) {
  static const char digits[] = "0123456789ABCDEF";
  if (!valid) {
    row_append(row, position, "--------");
    return;
  }
  for (int shift = 28; shift >= 0 && *position < FAULT_DISPLAY_COLS - 1U;
       shift -= 4) {
    row[(*position)++] = digits[(value >> shift) & 0x0fU];
  }
}

static const char *frame_status_text(fault_frame_status_t status) {
  switch (status) {
    case FAULT_FRAME_OK:
      return "";
    case FAULT_FRAME_EXC_RETURN:
      return "EXCRET";
    case FAULT_FRAME_EXTENDED:
      return "FPFRAME";
    case FAULT_FRAME_STACK_STATUS:
      return "STKFLAG";
    case FAULT_FRAME_STACK_RANGE:
      return "SP:RANGE";
    case FAULT_FRAME_STACK_PADDING:
      return "STKPAD";
    case FAULT_FRAME_XPSR:
      return "XPSR";
    default:
      return "FRAME?";
  }
}

static const char *hard_forced_reason(uint32_t cfsr) {
  if ((cfsr & CFSR_MM_MSTKERR) != 0U) return "H:M-STK";
  if ((cfsr & CFSR_MM_MUNSTKERR) != 0U) return "H:M-UNSTK";
  if ((cfsr & CFSR_MM_MLSPERR) != 0U) return "H:M-LSP";
  if ((cfsr & CFSR_BF_STKERR) != 0U) return "H:B-STK";
  if ((cfsr & CFSR_BF_UNSTKERR) != 0U) return "H:B-UNSTK";
  if ((cfsr & CFSR_BF_LSPERR) != 0U) return "H:B-LSP";
  if ((cfsr & CFSR_BF_IMPRECISERR) != 0U) return "H:B-IMPR";
  if ((cfsr & CFSR_BF_PRECISERR) != 0U) return "H:B-PREC";
  if ((cfsr & CFSR_BF_IBUSERR) != 0U) return "H:B-IBUS";
  if ((cfsr & CFSR_MM_IACCVIOL) != 0U) return "H:M-IACC";
  if ((cfsr & CFSR_MM_DACCVIOL) != 0U) return "H:M-DACC";
  if ((cfsr & CFSR_UF_UNDEFINSTR) != 0U) return "H:U-UNDEF";
  if ((cfsr & CFSR_UF_INVSTATE) != 0U) return "H:U-STATE";
  if ((cfsr & CFSR_UF_INVPC) != 0U) return "H:U-INVPC";
  if ((cfsr & CFSR_UF_NOCP) != 0U) return "H:U-NOCP";
  if ((cfsr & CFSR_UF_UNALIGNED) != 0U) return "H:U-UNALIGN";
  if ((cfsr & CFSR_UF_DIVBYZERO) != 0U) return "H:U-DIV0";
  return "H:FORCED";
}

static const char *fault_reason(const fault_capture_t *capture) {
  const uint32_t cfsr = capture->cfsr;
  switch (capture->ipsr) {
    case 3:
      if ((capture->hfsr & HFSR_VECTTBL) != 0U) return "H:VECTTBL";
      if ((capture->hfsr & HFSR_FORCED) != 0U) {
        return hard_forced_reason(cfsr);
      }
      if ((capture->hfsr & HFSR_DEBUGEVT) != 0U) return "H:DEBUG";
      return "H:UNKNOWN";
    case 4:
      if ((cfsr & CFSR_MM_MSTKERR) != 0U) return "M:STK";
      if ((cfsr & CFSR_MM_MUNSTKERR) != 0U) return "M:UNSTK";
      if ((cfsr & CFSR_MM_MLSPERR) != 0U) return "M:LSP";
      if ((cfsr & CFSR_MM_IACCVIOL) != 0U) return "M:IACC";
      if ((cfsr & CFSR_MM_DACCVIOL) != 0U) return "M:DACC";
      return "M:UNKNOWN";
    case 5:
      if ((cfsr & CFSR_BF_STKERR) != 0U) return "B:STK";
      if ((cfsr & CFSR_BF_UNSTKERR) != 0U) return "B:UNSTK";
      if ((cfsr & CFSR_BF_LSPERR) != 0U) return "B:LSP";
      if ((cfsr & CFSR_BF_IMPRECISERR) != 0U) return "B:IMPRECISE";
      if ((cfsr & CFSR_BF_IBUSERR) != 0U) return "B:IBUS";
      if ((cfsr & CFSR_BF_PRECISERR) != 0U) return "B:PRECISE";
      return "B:UNKNOWN";
    case 6:
      if ((cfsr & CFSR_UF_UNDEFINSTR) != 0U) return "U:UNDEF";
      if ((cfsr & CFSR_UF_INVSTATE) != 0U) return "U:INVSTATE";
      if ((cfsr & CFSR_UF_INVPC) != 0U) return "U:INVPC";
      if ((cfsr & CFSR_UF_NOCP) != 0U) return "U:NOCP";
      if ((cfsr & CFSR_UF_UNALIGNED) != 0U) return "U:UNALIGN";
      if ((cfsr & CFSR_UF_DIVBYZERO) != 0U) return "U:DIV0";
      return "U:UNKNOWN";
    default:
      return "?:UNKNOWN";
  }
}

void fault_report_format_rows(const fault_report_t *report,
                              char rows[FAULT_DISPLAY_ROWS]
                                       [FAULT_DISPLAY_COLS]) {
  if (report == NULL || rows == NULL) return;
  for (uint32_t row = 0; row < FAULT_DISPLAY_ROWS; row++) row_clear(rows[row]);

  uint32_t position = 0;
  row_append(rows[0], &position, fault_reason(&report->capture));

  const bool imprecise = (report->capture.cfsr & CFSR_BF_IMPRECISERR) != 0U;
  position = 0;
  row_append(rows[1], &position, imprecise ? "P~" : "PC");
  row_hex(rows[1], &position, report->pc, report->frame_available);
  row_append(rows[1], &position, " LR");
  row_hex(rows[1], &position, report->lr, report->frame_available);

  position = 0;
  row_append(rows[2], &position, "MS");
  row_hex(rows[2], &position, report->capture.msp, true);
  row_append(rows[2], &position, " PS");
  row_hex(rows[2], &position, report->capture.psp, true);

  position = 0;
  row_append(rows[3], &position, "CF");
  row_hex(rows[3], &position, report->capture.cfsr, true);
  row_append(rows[3], &position, " HF");
  row_hex(rows[3], &position, report->capture.hfsr, true);

  position = 0;
  row_append(rows[4], &position, "BF");
  row_hex(rows[4], &position, report->capture.bfar,
          (report->capture.cfsr & CFSR_BF_BFARVALID) != 0U);
  row_append(rows[4], &position, " MF");
  row_hex(rows[4], &position, report->capture.mmfar,
          (report->capture.cfsr & CFSR_MM_MMARVALID) != 0U);

  position = 0;
  row_append(rows[5], &position, "EX");
  row_hex(rows[5], &position, report->capture.exc_return, true);
  if (report->frame_status != FAULT_FRAME_OK) {
    row_append(rows[5], &position, " ");
    row_append(rows[5], &position, frame_status_text(report->frame_status));
  }
  position = 0;
  row_append(rows[6], &position, "FW");
  row_append(rows[6], &position,
             report->firmware_version != NULL ? report->firmware_version : "?");
  row_append(rows[6], &position, " RV");
  row_hex(rows[6], &position, report->revision, true);
  position = 0;
  row_append(rows[7], &position, "Photo; power:restart");
}
