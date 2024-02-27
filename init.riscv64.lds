SECTIONS
{
	. = 0x0;
	.text._start : {
		*(.text._tramp)
		*(.text._start)
	}

	.text : {
		*(.eh_frame)
		*(.rodata .rodata.*)
		*(.text .text.*)
	}

	. = ALIGN(4096);
	.data._init : {
		*(.data._init)
	}
	. = ALIGN(4096);
	.data : {
		*(.data .data.*)
	}
}

