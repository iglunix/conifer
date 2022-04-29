#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::eprintln!("{}", info);
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
