  .syntax unified
  .thumb

  // This stack is used only after a configurable fault has occurred.  The
  // exception handlers below must not use the potentially damaged task stack.
  .section .bss.fault_stack, "aw", %nobits
  .align 3
  .global fault_emergency_stack_bottom
fault_emergency_stack_bottom:
  .space 2048
  .global fault_emergency_stack_top
fault_emergency_stack_top:
  .previous

  .text

  .global memset_reg
  .type memset_reg, STT_FUNC
memset_reg:
  // call with the following (note that the arguments are not validated prior to use):
  // r0 - address of first word to write (inclusive)
  // r1 - address of first word following the address in r0 to NOT write (exclusive)
  // r2 - word value to be written
  // both addresses in r0 and r1 needs to be divisible by 4!
  .L_loop_begin:
    str r2, [r0], 4 // store the word in r2 to the address in r0, post-indexed
    cmp r0, r1
  bne .L_loop_begin
  bx lr

  .global reset_handler
  .type reset_handler, STT_FUNC
reset_handler:

// We need to perform VTOR setup case an old bootloader (<1.8.0)
// is starting the new firmware, these will be set incorrectly.

// To make development easier, set only if we are in privileged
// mode. This resolves annoying combinations of PRODUCTION
// settings for bootloader and FW.
// Normally only signed firmware will let bootloader start FW
// in privileged mode (PRODUCTION=1 variants with signed everything).
// But with devel bootloader we let FW start in privileged mode
// and let's do the check if we can set VTOR without fault

  // These two instructions are just for debug testing how unprivileged
  // FW is handled
  //mov r0, 1
  //msr control, r0  // set unprivileged

  ldr sp, =_stack  // setup stack

  // are we privileged? if so, fix VTOR, otherwise skip
  mrs r3, control
  and r3, r3, #1
  cmp r3, #1
  beq .setup_as_unprivileged

  ldr r0, =0xE000ED08  // r0 = VTOR address
  ldr r1, =0x08010400  // r1 = FLASH_APP_START
  str r1, [r0]         // assign
  dsb
  isb

  .setup_as_unprivileged:
  // Preserve data across soft reset - load from fixed address before RAM clear
  ldr r0, =_preserved_reset_data_addr  // Address for preserved data (defined in linker script)
  ldr r11, [r0]        // r11 = preserve value in register (survives RAM clear)

  ldr r0, =_ram_start // r0 - point to beginning of SRAM
  ldr r1, =_ram_end   // r1 - point to byte after the end of SRAM
  ldr r2, =0          // r2 - the byte-sized value to be written
  bl memset_reg

  // Restore preserved data after RAM clear 
  ldr r0, =_preserved_reset_data_addr  // Address for preserved data
  str r11, [r0]        // Store preserved value back to memory        

  // copy .data section from flash to SRAM
  ldr r0, =_data          // dst addr
  ldr r1, =_data_loadaddr // src addr
  ldr r2, =_data_size     // length in bytes
  bl memcpy

  // enter the application code
  bl main

  // shutdown if the application code returns
  b shutdown

  .global shutdown
  .type shutdown, STT_FUNC
shutdown:
  cpsid f
  ldr r0, =0
  mov r1, r0
  mov r2, r0
  mov r3, r0
  mov r4, r0
  mov r5, r0
  mov r6, r0
  mov r7, r0
  mov r8, r0
  mov r9, r0
  mov r10, r0
  mov r11, r0
  mov r12, r0
  ldr lr, =0xffffffff
  ldr r0, =_ram_start
  ldr r1, =_ram_end
  // set to value in r2
  bl memset_reg
  b sys_shutdown // loop forever

  .ltorg // dump literal pool (for the ldr ...,=... commands above)

  .global sv_call_handler
  .type sv_call_handler, STT_FUNC

sv_call_handler:
  tst lr, #4
  ite eq
  mrseq r0, msp
  mrsne r0, psp
  b svc_handler_main

  // Save both post-exception stack pointers, EXC_RETURN and IPSR before using
  // any stack.  fault_handler_main validates the selected exception frame
  // before it dereferences it.
  .macro fault_entry name
  .global \name
  .type \name, STT_FUNC
  .thumb_func
\name:
  mrs r0, msp
  mrs r1, psp
  mov r2, lr
  mrs r3, ipsr
  cpsid i
  cpsid f
  ldr r12, =fault_emergency_stack_top
  mov sp, r12
  b fault_handler_main
  .endm

  fault_entry hard_fault_handler_impl
  fault_entry mem_manage_handler_impl
  fault_entry bus_fault_handler
  fault_entry usage_fault_handler

  // Do not return to normal shutdown here: it clears the OLED and resets the
  // device.  Once the diagnostic has been rendered, erase both RAM banks
  // without making another call or relying on a valid stack, then wait for
  // an explicit local restart request.
  .global fault_terminal_halt
  .type fault_terminal_halt, STT_FUNC
  .thumb_func
fault_terminal_halt:
  cpsid i
  cpsid f
  ldr r0, =_ram_start
  ldr r1, =_ram_end
  movs r2, #0
.L_fault_clear_main_ram:
  cmp r0, r1
  bcs .L_fault_clear_ccm_setup
  str r2, [r0], #4
  b .L_fault_clear_main_ram
.L_fault_clear_ccm_setup:
  ldr r0, =0x10000000
  ldr r1, =0x10010000
.L_fault_clear_ccm:
  cmp r0, r1
  bcs .L_fault_halt
  str r2, [r0], #4
  b .L_fault_clear_ccm
.L_fault_halt:
  // The diagnostic page is now in OLED RAM and both SRAM banks have been
  // cleared.  Do not return to damaged firmware; wait for a released PA1 and
  // then a new debounced power-key press to request a clean system reset.
  movs r0, #0
  mov r1, r0
  mov r2, r0
  mov r3, r0
  mov r4, r0
  mov r5, r0
  mov r6, r0
  mov r7, r0
  mov r8, r0
  mov r9, r0
  mov r10, r0
  mov r11, r0
  mov r12, r0
  mov lr, r0
  mov sp, r0

  // PA1 is the power key and is active high.  Sample a stable release first
  // so the fault-time key state cannot immediately restart the device.
  ldr r0, =0x40020010  // GPIOA_IDR
  movs r2, #0
  movs r4, #0  // 0 = release phase, 1 = new-press phase
.L_fault_wait_release:
  ldr r1, [r0]
  tst r1, #2
  bne .L_fault_release_reset
  adds r2, #1
  cmp r2, #8
  bcs .L_fault_wait_press_init
  b .L_fault_debounce_delay
.L_fault_release_reset:
  movs r2, #0
  b .L_fault_debounce_delay

.L_fault_wait_press_init:
  movs r2, #0
  movs r4, #1
.L_fault_wait_press:
  ldr r1, [r0]
  tst r1, #2
  beq .L_fault_press_reset
  adds r2, #1
  cmp r2, #8
  bcs .L_fault_request_reset
  b .L_fault_debounce_delay
.L_fault_press_reset:
  movs r2, #0
.L_fault_debounce_delay:
  // Keep each sample apart without a timer, stack, or peripheral call.
  movw r3, #0x4000
.L_fault_debounce_delay_loop:
  subs r3, #1
  bne .L_fault_debounce_delay_loop
  cmp r4, #0
  beq .L_fault_wait_release
  b .L_fault_wait_press

.L_fault_request_reset:
  // Preserve only PRIGROUP, supply VECTKEY, and request reset.  DSB/ISB make
  // the reset request visible before the intentional fatal wait resumes.
  ldr r0, =0xe000ed0c  // SCB_AIRCR
  ldr r1, [r0]
  and r1, r1, #0x700
  ldr r3, =0x05fa0004  // VECTKEY | SYSRESETREQ
  orr r1, r1, r3
  str r1, [r0]
  dsb
  isb
.L_fault_reset_wait:
  b .L_fault_reset_wait

  .end
