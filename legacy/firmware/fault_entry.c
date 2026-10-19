#include <stdint.h>

enum { FAULT_EMERGENCY_STACK_SIZE = 2048 };

uint8_t fault_emergency_stack[FAULT_EMERGENCY_STACK_SIZE]
    __attribute__((aligned(8), section(".bss.fault_stack"), used));

// Preserve the exact linker-visible stack bounds used by fault.c and the RAM
// budget checker without moving the allocation out of this C translation unit.
__asm__(
    ".global fault_emergency_stack_bottom\n"
    "fault_emergency_stack_bottom = fault_emergency_stack\n"
    ".global fault_emergency_stack_top\n"
    "fault_emergency_stack_top = fault_emergency_stack + 2048\n");

// These naked handlers and the terminal halt path must remain one basic asm
// block with no C statements: the active stack may be corrupt or cleared.
#define DEFINE_FAULT_ENTRY(name)                                           \
  __attribute__((naked, no_stack_protector, noreturn)) void name(void) {   \
    __asm volatile(                                                        \
        "mrs r0, msp\n"                                                   \
        "mrs r1, psp\n"                                                   \
        "mov r2, lr\n"                                                    \
        "mrs r3, ipsr\n"                                                  \
        "cpsid i\n"                                                       \
        "cpsid f\n"                                                       \
        "ldr r12, =fault_emergency_stack_top\n"                          \
        "mov sp, r12\n"                                                   \
        "b fault_handler_main\n");                                       \
  }

DEFINE_FAULT_ENTRY(hard_fault_handler_impl)
DEFINE_FAULT_ENTRY(mem_manage_handler_impl)
DEFINE_FAULT_ENTRY(bus_fault_handler)
DEFINE_FAULT_ENTRY(usage_fault_handler)

__attribute__((naked, no_stack_protector, noreturn)) void
fault_terminal_halt(uint32_t preserve_start __attribute__((unused)),
                    uint32_t preserve_end __attribute__((unused))) {
  __asm volatile(
      "cpsid i\n"
      "cpsid f\n"
      "mov r4, r0\n"
      "mov r5, r1\n"
      "ldr r0, =_ram_start\n"
      "ldr r1, =_ram_end\n"
      "movs r2, #0\n"
      ".L_fault_clear_main_ram:\n"
      "cmp r0, r1\n"
      "bcs .L_fault_clear_ccm_setup\n"
      "cmp r0, r4\n"
      "bcc .L_fault_clear_main_ram_word\n"
      "cmp r0, r5\n"
      "bcs .L_fault_clear_main_ram_word\n"
      "adds r0, #4\n"
      "b .L_fault_clear_main_ram\n"
      ".L_fault_clear_main_ram_word:\n"
      "str r2, [r0], #4\n"
      "b .L_fault_clear_main_ram\n"
      ".L_fault_clear_ccm_setup:\n"
      "ldr r0, =0x10000000\n"
      "ldr r1, =0x10010000\n"
      ".L_fault_clear_ccm:\n"
      "cmp r0, r1\n"
      "bcs .L_fault_halt\n"
      "str r2, [r0], #4\n"
      "b .L_fault_clear_ccm\n"
      ".L_fault_halt:\n"
      "movs r0, #0\n"
      "mov r1, r0\n"
      "mov r2, r0\n"
      "mov r3, r0\n"
      "mov r4, r0\n"
      "mov r5, r0\n"
      "mov r6, r0\n"
      "mov r7, r0\n"
      "mov r8, r0\n"
      "mov r9, r0\n"
      "mov r10, r0\n"
      "mov r11, r0\n"
      "mov r12, r0\n"
      "mov lr, r0\n"
      "ldr r12, =fault_emergency_stack_top\n"
      "mov sp, r12\n"
      "b fault_display_loop\n");
}
