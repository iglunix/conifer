SECTIONS
{
	. = 0x80200000;
	.text : {
		*(.text._start)
		*(.text)
	}
	.rodata : {
		*(.rodata .rodata.*)
	}
	.data : {
		*(.data .data.*)
		*(.sdata .sdata.*)
	}
	.bss : {
		*(.bss .bss.*)
		*(.sbss .sbss.*)
	}
}
