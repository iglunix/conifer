#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::eprintln!("{}", info);
    unsafe {
        core::arch::asm!(
            "
                li a7, 0x53525354
                li a6, 0
                li a0, 0
                li a1, 0
                ecall
            ", options(noreturn)
        )
    }
}
