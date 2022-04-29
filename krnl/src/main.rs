#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(asm_sym)]
#![feature(fn_align)]

mod boot;
mod panic;
mod sbi;
mod init;
mod elf;
mod earlycon;
mod trap;
// mod syscall;

fn main() {
    eprintln!("====================");
    eprintln!("Conifer Micro-Kernel");
    eprintln!("====================");
    unsafe { elf::Elf::new(init::INIT_ELF.as_ptr()) };
}
