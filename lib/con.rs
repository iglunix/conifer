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

#[repr(C)]
#[derive(Debug)]
struct Frame {
    fp: *const Frame,
    ra: usize,
}

impl Frame {
    pub unsafe fn unwind(&self, idx: usize) {
        // let krnl_elf = elf::Elf::new(KRNL_ELF_ADDR as *const u8);

        if self.fp as usize > 0xffffff0000000000 {
            eprintln!("{:x}", self.ra);
            // let sym = find_symbol(self.ra);
            // let sym = rustc_demangle::demangle(sym);
            // eprintln!("{:>4}: {}", idx, sym);
            // eprintln!("             at {:x}", self.ra);
            (*self.fp.offset(-1)).unwind(idx + 1)
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("csrw sie, x0");
        eprintln!("{}", info);
        let fp;
        let pc;
        core::arch::asm!(
            "auipc {}, 0
             mv {}, fp", out(reg) pc, out(reg) fp);
        let fp = Frame { fp, ra: pc };
        fp.unwind(0);
        loop {
            core::arch::asm!("wfi");
        }
    }
}
