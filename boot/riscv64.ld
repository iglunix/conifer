SECTIONS
{
	. = 0x80000000;
	. = 0x80020000;
	.text : {
		*(.text._start)
		*(.text)
	}
	. = ALIGN(0x1000);
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
