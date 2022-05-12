pub const INIT_ELF: &[u8] = include_bytes!("../../init.elf");

#[repr(align(4096))]
#[link_section = ".init"]
pub fn init_fn() {
    let hello = b"Hello, World!\n";
    unsafe {
        core::arch::asm!("ecall", in("a0") 1, in("a1") hello, in("a2") hello.len(), in("a7") 64);
    }
    let call = 93;
    let code = 0;
    unsafe { core::arch::asm!("ecall", in("a0") code, in("a7") call) };
}
