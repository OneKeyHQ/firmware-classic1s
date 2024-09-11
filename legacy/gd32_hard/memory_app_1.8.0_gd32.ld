/* GD32F470VK - 3072K Flash, 256K RAM */
/* program starts at 0x08010400 */
MEMORY
{
	rom (rx) : ORIGIN = 0x08010000, LENGTH = 3072K - 320K
	ram (rwx) : ORIGIN = 0x20000000, LENGTH = 192K
	ram1 (rwx) : ORIGIN = 0x10000000, LENGTH = 64K
}
SECTIONS
{
	.confidential (NOLOAD) : {
		*(confidential)
		ASSERT ((SIZEOF(.confidential) <= 32K), "Error: Confidential section too big!");
	} >ram
	
	/* C++ Static constructors/destructors, also used for __attribute__
	 * ((constructor)) and the likes */
	.messages_segment (NOLOAD) : {
		. = ALIGN(4);
		__messages_segment_array_start = .;
		KEEP (*(.secMessageSection))
		KEEP (*(.secMessageSection*))
		__messages_segment_array_end = .;
		ASSERT ((SIZEOF(.messages_segment) + 16 <= LENGTH(ram1)), "Error: Messages segment too big!");
	}>ram1

	.header : ALIGN(4) {
		KEEP(*(.header));
	} >rom AT>rom
}

INCLUDE cortex-m-generic.ld

_codelen = SIZEOF(.text) + SIZEOF(.data) + SIZEOF(.ARM.exidx);
ASSERT((end + 100K <= ORIGIN(ram) + LENGTH(ram)), "Error: not enough space for stack!");
_ram_start = ORIGIN(ram);
_ram_end = ORIGIN(ram) + LENGTH(ram);
_stay_in_bootloader_flag_addr = ABSOLUTE(0x20010000);
_stack = _ram_end - 8;
__stack_chk_guard = _ram_end - 8;
system_millis = _ram_end - 4;

_data_size = SIZEOF(.data);
