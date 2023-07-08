BOOTLOADER0 = 1
BOOT_BUILD_VERSION=$(shell ../../tools/version.sh version.h)
BOOT_BUILD_DATE=$(shell date "+%m%d")
BUILD_COMMIT=$(shell git rev-parse HEAD | cut -c1-7)
NAME  = bootloader-board

OBJS += startup.o
OBJS += bootloader.o
OBJS += ../vendor/trezor-crypto/memzero.small.o

OPTFLAGS ?= -Os
include ../Makefile.include

bootloader0.bin: $(NAME).bin
	./firmware_align.py $< $@

all: bootloader0.bin
