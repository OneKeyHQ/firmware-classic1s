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
fault_terminal_halt(void) {
  __asm volatile(
      "cpsid i\n"
      "cpsid f\n"
      "ldr r0, =_ram_start\n"
      "ldr r1, =_ram_end\n"
      "movs r2, #0\n"
      ".L_fault_clear_main_ram:\n"
      "cmp r0, r1\n"
      "bcs .L_fault_clear_ccm_setup\n"
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
      "mov sp, r0\n"
      "ldr r0, =0x40020010\n"
      "movs r2, #0\n"
      "movs r4, #0\n"
      ".L_fault_wait_release:\n"
      "ldr r1, [r0]\n"
      "tst r1, #2\n"
      "bne .L_fault_release_reset\n"
      "adds r2, #1\n"
      "cmp r2, #8\n"
      "bcs .L_fault_wait_press_init\n"
      "b .L_fault_debounce_delay\n"
      ".L_fault_release_reset:\n"
      "movs r2, #0\n"
      "b .L_fault_debounce_delay\n"
      ".L_fault_wait_press_init:\n"
      "movs r2, #0\n"
      "movs r4, #1\n"
      ".L_fault_wait_press:\n"
      "ldr r1, [r0]\n"
      "tst r1, #2\n"
      "beq .L_fault_press_reset\n"
      "adds r2, #1\n"
      "cmp r2, #8\n"
      "bcs .L_fault_request_reset\n"
      "b .L_fault_debounce_delay\n"
      ".L_fault_press_reset:\n"
      "movs r2, #0\n"
      ".L_fault_debounce_delay:\n"
      "movw r3, #0x4000\n"
      ".L_fault_debounce_delay_loop:\n"
      "subs r3, #1\n"
      "bne .L_fault_debounce_delay_loop\n"
      "cmp r4, #0\n"
      "beq .L_fault_wait_release\n"
      "b .L_fault_wait_press\n"
      ".L_fault_request_reset:\n"
      "ldr r0, =0xe000ed0c\n"
      "ldr r1, [r0]\n"
      "and r1, r1, #0x700\n"
      "ldr r3, =0x05fa0004\n"
      "orr r1, r1, r3\n"
      "str r1, [r0]\n"
      "dsb\n"
      "isb\n"
      ".L_fault_reset_wait:\n"
      "b .L_fault_reset_wait\n");
}
