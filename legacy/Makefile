ifneq ($(EMULATOR),1)
OBJS += setup.o
OBJS += timer.o
endif

OBJS += buttons.o
OBJS += common.o
ifeq ($(EMULATOR),1)
OBJS += flash.o
OBJS += memory.o
endif
OBJS += fw_signatures.o
OBJS += gen/bitmaps.o
OBJS += gen/fonts.o
OBJS += layout.o
OBJS += oled.o
OBJS += random_delays.o
OBJS += rng.o

ifneq ($(EMULATOR),1)
OBJS += setup.o
OBJS += sys.o
OBJS += si2c.o
OBJS += usart.o
OBJS += nordic_dfu.o
OBJS += ble.o
OBJS += trans_fifo.o

OBJS += gd32_hard/memory_gd32.o
OBJS += gd32_hard/flash_gd32.o
OBJS += gd32_hard/system_gd32f470.o

OBJS += segger_rtt/SEGGER_RTT.o
OBJS += segger_rtt/SEGGER_RTT_printf.o
OBJS += segger_rtt/rtt_log.o

OBJS += mi2c.o
OBJS += thd89.o
endif

OBJS += util.o
OBJS += supervise.o
OBJS += usb21_standard.o
OBJS += usb_standard.o
OBJS += util.o
OBJS += webusb.o
OBJS += winusb.o

OBJS += gen/bitmaps.o
OBJS += gen/fonts.o
OBJS += gen/prompt.o

libtrezor.a: $(OBJS)

include Makefile.include

libtrezor.a:
	@printf "  AR      $@\n"
	$(Q)$(AR) rcs $@ $^

.PHONY: vendor build_unix test_emu test_emu_ui test_emu_ui_record \
        flash_firmware_jlink flash_bootloader_jlink

vendor:
	git submodule update --init --recursive

build_unix: ## build unix port
	./script/setup
	EMULATOR=1 DEBUG_LINK=1 ./script/cibuild

test_emu: ## run integration tests
	./script/test $(TESTOPTS)

test_emu_ui: ## run ui integration tests
	./script/test --ui=test --ui-check-missing $(TESTOPTS)

test_emu_ui_record: ## record and hash screens for ui integration tests
	./script/test --ui=record --ui-check-missing $(TESTOPTS)

flash_firmware_jlink:
	JLinkExe -nogui 1 -commanderscript firmware/firmware_flash.jlink

flash_bootloader_jlink:
	JLinkExe -nogui 1 -commanderscript bootloader/bootloader_flash.jlink

cl:
	./script/setup

build_emu:
	export EMULATOR=1 DEBUG_LINK=0 && ./script/cibuild

# buf:
# 	export EMULATOR=0 DEBUG_LINK=0 PRODUCTION=0 BOOTLOADER_QA=1 && ./script/cibuild
	