MEMORY
{
	ram  (wxa) : ORIGIN = 0x80200000, LENGTH = 128M
}

PHDRS
{
	text PT_LOAD;
	data PT_LOAD;
	bss PT_LOAD;
}

SECTIONS
{
	.text : {
		. = ALIGN(4096);
		PROVIDE(_text_start = .);
		*(.text._start)
		*(.text .text.*)
		*(.text.init)
		PROVIDE(_text_end = .);
		*(.boot)
		*(.init)
		*(.trap)
		. = ALIGN(4096);
		*(.scratch)
	} > ram AT>ram :text

	PROVIDE(_global_pointer = .);

	.rodata : {
		. = ALIGN(4096);
		PROVIDE(_rodata_start = .);
		*(.rodata .rodata.*)
		PROVIDE(_rodata_end = .);
	} > ram AT>ram :text

	.data : {
		. = ALIGN(4096);
		PROVIDE(_data_start = .);
		*(.sdata .sdata.*)
		*(.data .data.*)
		PROVIDE(_data_end = .);
	} > ram AT>ram :data

	.bss : {
		. = ALIGN(4096);
		PROVIDE(_bss_start = .);
		*(.sbss .sbss.*)
		*(.bss .bss.*)
		PROVIDE(_bss_end = .);
	} > ram AT>ram :bss
        . = ALIGN(4096);
	PROVIDE(_stack_start = .);

	PROVIDE(_memory_start = ORIGIN(ram));

	PROVIDE(_stack_end = _stack_start + 0x80000);
	PROVIDE(_memory_end = ORIGIN(ram) + LENGTH(ram));

	PROVIDE(_heap_start = _stack_end);
	PROVIDE(_heap_size = _memory_end - _heap_start);

	/DISCARD/ : { *(.eh_frame) }
}
