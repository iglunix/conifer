#![no_std]

fn console_putchar(c: u8) {
    unsafe {
        core::arch::asm!(
            "   li a6, 0x0
                li a7, 0x1
                ecall
                 ", in("a0") c, out("a6") _, out("a7") _);
    }
}

pub fn write_str(msg: &str) {
    msg.bytes().for_each(console_putchar);
}

struct EarlyCon();

impl core::fmt::Write for EarlyCon {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_str(s);
        Ok(())
    }
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    EarlyCon().write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprint {
    () => ();
    ($($arg:tt)*) => ($crate::print!("\x1B[91m{}\x1B[0m", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ($crate::eprint!("{}\n", format_args!($($arg)*)));
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    eprintln!("{}", info);
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
