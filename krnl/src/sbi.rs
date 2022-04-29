pub fn console_putchar(c: u8) {
    unsafe {
        core::arch::asm!(
            "   li a6, 0x0
                li a7, 0x1
                ecall
                 ", in("a0") c, out("a6") _, out("a7") _);
    }
}
