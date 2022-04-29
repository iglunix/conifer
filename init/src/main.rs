#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
fn _start() {
    let call = 93;
    unsafe { core::arch::asm!("ecall", in("a7") call) }
}
