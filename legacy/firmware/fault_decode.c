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
#define FRAME_BYTES            (FAULT_FRAME_BASIC_WORDS * sizeof(uint32_t))
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

uint32_t fault_exception_frame_words(const fault_capture_t *capture) {
  if (capture == NULL) return 0U;
  if (exc_return_valid(capture->exc_return)) return FAULT_FRAME_BASIC_WORDS;
  if (exc_return_extended(capture->exc_return)) {
    return FAULT_FRAME_EXTENDED_WORDS;
  }
  return 0U;
}

bool fault_exception_frame_readable(const fault_capture_t *capture,
                                    const fault_stack_bounds_t *bounds,
                                    uint32_t word_count) {
  if (capture == NULL || bounds == NULL || word_count == 0U ||
      word_count > FAULT_FRAME_MAX_WORDS ||
      fault_exception_frame_words(capture) == 0U) {
    return false;
  }

  const uint32_t sp = selected_stack_pointer(capture);
  const uint32_t bytes = word_count * sizeof(uint32_t);
  if ((sp & 3U) != 0U ||
      !range_contains(bounds->stack_low, bounds->stack_high, sp, bytes) ||
      bounds->emergency_low > bounds->emergency_high) {
    return false;
  }
  return !ranges_overlap(sp, sp + bytes, bounds->emergency_low,
                         bounds->emergency_high);
}

fault_frame_status_t fault_exception_frame_status(
    const fault_capture_t *capture, const fault_stack_bounds_t *bounds) {
  if (capture == NULL || bounds == NULL) return FAULT_FRAME_EXC_RETURN;
  if (exc_return_extended(capture->exc_return)) return FAULT_FRAME_EXTENDED;
  if (!exc_return_valid(capture->exc_return)) return FAULT_FRAME_EXC_RETURN;
  if ((capture->cfsr & STACK_FRAME_FAULTS) != 0U) {
    return FAULT_FRAME_STACK_STATUS;
  }

  if (!fault_exception_frame_readable(capture, bounds,
                                      FAULT_FRAME_BASIC_WORDS)) {
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

  report->frame_available = false;
  report->raw_frame_available = false;
  report->lr = frame[5];
  report->pc = frame[6];
  report->xpsr = frame[7];
  report->raw_frame_available = true;
  if (report->frame_status != FAULT_FRAME_OK) return;

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

static void row_u32(char row[FAULT_DISPLAY_COLS], uint32_t *position,
                    uint32_t value) {
  char digits[10];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U && count < sizeof(digits));
  while (count != 0U && *position < FAULT_DISPLAY_COLS - 1U) {
    row[(*position)++] = digits[--count];
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
  if (report->frame_status != FAULT_FRAME_OK) {
    row_append(rows[0], &position, " ");
    row_append(rows[0], &position, frame_status_text(report->frame_status));
  }

  const bool imprecise = (report->capture.cfsr & CFSR_BF_IMPRECISERR) != 0U;
  position = 0;
  const bool raw_frame = report->raw_frame_available;
  row_append(rows[1], &position,
             report->frame_available ? (imprecise ? "P~" : "PC") : "RP");
  row_hex(rows[1], &position, report->pc, raw_frame);
  row_append(rows[1], &position, report->frame_available ? " LR" : " RL");
  row_hex(rows[1], &position, report->lr, raw_frame);

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
  row_append(rows[5], &position, " XP");
  row_hex(rows[5], &position, report->xpsr, raw_frame);
  position = 0;
  row_append(rows[6], &position, "FW");
  row_append(rows[6], &position,
             report->firmware_version != NULL ? report->firmware_version : "?");
  row_append(rows[6], &position, " RV");
  row_hex(rows[6], &position, report->revision, true);
  position = 0;
  row_append(rows[7], &position, "Photo; power:restart");
}

static bool snapshot_valid(const fault_snapshot_t *snapshot) {
  return snapshot != NULL && snapshot->magic == FAULT_SNAPSHOT_MAGIC &&
         snapshot->format_version == FAULT_SNAPSHOT_FORMAT_VERSION &&
         snapshot->size == sizeof(*snapshot) &&
         snapshot->frame_word_count <= FAULT_FRAME_MAX_WORDS &&
         snapshot->frame_expected_words <= FAULT_FRAME_MAX_WORDS;
}

static void format_footer(char row[FAULT_DISPLAY_COLS], uint32_t page,
                          uint32_t pages) {
  row_clear(row);
  uint32_t position = 0U;
  row_u32(row, &position, page + 1U);
  row_append(row, &position, "/");
  row_u32(row, &position, pages);
  row_append(row, &position, " UP/DN PWR:reset");
}

uint32_t fault_snapshot_page_count(const fault_snapshot_t *snapshot) {
  if (!snapshot_valid(snapshot)) return 1U;
  if (snapshot->frame_word_count <= FAULT_FRAME_BASIC_WORDS) return 3U;
  return 3U +
         (snapshot->frame_word_count - FAULT_FRAME_BASIC_WORDS + 9U) / 10U;
}

static void format_core_page(const fault_snapshot_t *snapshot,
                             char rows[FAULT_DISPLAY_ROWS]
                                      [FAULT_DISPLAY_COLS]) {
  const fault_report_t *report = &snapshot->report;
  uint32_t position = 0U;
  row_append(rows[0], &position,
             report->frame_available ? "CORE VALID FW" : "CORE RAW FW");
  row_append(rows[0], &position,
             report->firmware_version != NULL ? report->firmware_version : "?");
  for (uint32_t pair = 0U; pair < 4U; pair++) {
    const uint32_t row = pair + 1U;
    const uint32_t first = pair * 2U;
    static const char *const names[8] = {"R0", "R1", "R2", "R3",
                                         "R12", "LR", "PC", "XP"};
    position = 0U;
    row_append(rows[row], &position, names[first]);
    row_hex(rows[row], &position, snapshot->frame_words[first],
            snapshot->frame_word_count > first);
    row_append(rows[row], &position, " ");
    row_append(rows[row], &position, names[first + 1U]);
    row_hex(rows[row], &position, snapshot->frame_words[first + 1U],
            snapshot->frame_word_count > first + 1U);
  }
  position = 0U;
  row_append(rows[5], &position, "SP");
  row_hex(rows[5], &position, snapshot->frame_address,
          snapshot->frame_word_count != 0U);
  position = 0U;
  row_append(rows[6], &position, "N");
  row_u32(rows[6], &position, snapshot->frame_word_count);
  row_append(rows[6], &position, "/");
  row_u32(rows[6], &position, snapshot->frame_expected_words);
  row_append(rows[6], &position,
             report->frame_available ? " VALID" : " RAW");
}

static void format_status_page(const fault_snapshot_t *snapshot,
                               char rows[FAULT_DISPLAY_ROWS]
                                        [FAULT_DISPLAY_COLS]) {
  const fault_capture_t *capture = &snapshot->report.capture;
  uint32_t position = 0U;
  row_append(rows[0], &position, "STATUS RV");
  row_hex(rows[0], &position, snapshot->report.revision, true);
  position = 0U;
  row_append(rows[1], &position, "VT");
  row_hex(rows[1], &position, capture->vtor, true);
  row_append(rows[1], &position, " IC");
  row_hex(rows[1], &position, capture->icsr, true);
  position = 0U;
  row_append(rows[2], &position, "SH");
  row_hex(rows[2], &position, capture->shcsr, true);
  row_append(rows[2], &position, " DF");
  row_hex(rows[2], &position, capture->dfsr, true);
  position = 0U;
  row_append(rows[3], &position, "AF");
  row_hex(rows[3], &position, capture->afsr, true);
  row_append(rows[3], &position, " IP");
  row_hex(rows[3], &position, capture->ipsr, true);
  position = 0U;
  row_append(rows[4], &position, "BF");
  row_hex(rows[4], &position, capture->bfar, true);
  row_append(rows[4], &position,
             (capture->cfsr & CFSR_BF_BFARVALID) != 0U ? " V1" : " V0");
  position = 0U;
  row_append(rows[5], &position, "MF");
  row_hex(rows[5], &position, capture->mmfar, true);
  row_append(rows[5], &position,
             (capture->cfsr & CFSR_MM_MMARVALID) != 0U ? " V1" : " V0");
  position = 0U;
  row_append(rows[6], &position, "FW");
  row_append(rows[6], &position,
             snapshot->report.firmware_version != NULL
                 ? snapshot->report.firmware_version
                 : "?");
}

static void format_raw_page(const fault_snapshot_t *snapshot,
                            uint32_t first,
                            char rows[FAULT_DISPLAY_ROWS]
                                     [FAULT_DISPLAY_COLS]) {
  uint32_t position = 0U;
  uint32_t last = snapshot->frame_word_count - 1U;
  if (last > first + 9U) last = first + 9U;
  row_append(rows[0], &position, "RAW ");
  row_u32(rows[0], &position, first);
  row_append(rows[0], &position, "-");
  row_u32(rows[0], &position, last);
  row_append(rows[0], &position, " FW");
  row_append(rows[0], &position,
             snapshot->report.firmware_version != NULL
                 ? snapshot->report.firmware_version
                 : "?");
  for (uint32_t pair = 0U; pair < 5U; pair++) {
    const uint32_t index = first + pair * 2U;
    position = 0U;
    if (index < snapshot->frame_word_count) {
      row_u32(rows[pair + 1U], &position, index);
      row_hex(rows[pair + 1U], &position, snapshot->frame_words[index], true);
    }
    if (index + 1U < snapshot->frame_word_count) {
      row_append(rows[pair + 1U], &position, " ");
      row_u32(rows[pair + 1U], &position, index + 1U);
      row_hex(rows[pair + 1U], &position, snapshot->frame_words[index + 1U],
              true);
    }
  }
}

void fault_snapshot_format_page(const fault_snapshot_t *snapshot,
                                uint32_t page,
                                char rows[FAULT_DISPLAY_ROWS]
                                         [FAULT_DISPLAY_COLS]) {
  if (rows == NULL) return;
  for (uint32_t row = 0U; row < FAULT_DISPLAY_ROWS; row++) row_clear(rows[row]);
  const uint32_t pages = fault_snapshot_page_count(snapshot);
  if (!snapshot_valid(snapshot)) {
    uint32_t position = 0U;
    row_append(rows[0], &position, "Snapshot unavailable");
    format_footer(rows[7], 0U, 1U);
    return;
  }
  if (page >= pages) page = 0U;
  if (page == 0U) {
    fault_report_format_rows(&snapshot->report, rows);
  } else if (page == 1U) {
    format_core_page(snapshot, rows);
  } else if (page == 2U) {
    format_status_page(snapshot, rows);
  } else {
    format_raw_page(snapshot, FAULT_FRAME_BASIC_WORDS + (page - 3U) * 10U,
                    rows);
  }
  format_footer(rows[7], page, pages);
}
