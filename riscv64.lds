SECTIONS
{
	. = 0xffffffc000000000;
	. = 0xffffffffc0000000;
	PROVIDE(krnl_start = .);
	.text._start : {
		*(.text._start)
	}

	.text : {
		*(.rodata .rodata.*)
		*(.text .text.*)
	}

	PROVIDE(krnl_text_end = .);
	PROVIDE(krnl_text_size = krnl_text_end - krnl_start);

	. = ALIGN(4096);
	.data._init : {
		*(.data._init)
	}
	. = ALIGN(4096);
	.data : {
		*(.data .data.*)
	}

	PROVIDE(krnl_end = .);
	PROVIDE(krnl_data_size = krnl_end - krnl_text_end);
	PROVIDE(krnl_size = krnl_end - krnl_start);
}

