#![no_std]
#![no_main]
#![feature(asm_sym)]
#![feature(naked_functions)]

struct PanicPrinter();
impl core::fmt::Write for PanicPrinter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print(s);

        Ok(())
    }
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    PanicPrinter().write_fmt(args).unwrap();
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
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print("ERROR: init panic!\n");
    eprintln!("{}", _info);
    exit(0);
}

fn print(s: &str) {
    let len = s.as_bytes().len();
    let ptr = s.as_ptr();
    unsafe {
        core::arch::asm!("ecall", in("a0") 1, in("a1") ptr, in("a2") len, in("a7") 64);
    }
}

fn exit(code: usize) -> ! {
    unsafe { core::arch::asm!("ecall", in("a0") code, in("a7") 93, options(noreturn)) }
}

#[no_mangle]
#[naked]
unsafe extern "C" fn _start() {
    core::arch::asm!(
        "mv a0, sp
         andi sp, sp, -16
         tail {}",
         sym entry, options(noreturn));
}

unsafe extern "C" fn entry(sp: *const usize) {
    let c = *sp;
    let v = sp.offset(1) as *const *const u8;
    let s = *v;
    let mut len = 0;
    while *s.offset(len as isize) != b'\0' {
        len += 1;
    }
    let s = core::slice::from_raw_parts(s, len);
    let s = core::str::from_utf8(s).unwrap();
    println!("argv0: {}", s);
    let p = v.offset(c as isize) as *const u8;
    println!("argp: {:p}", p);
    let mut len = 1;
    while *p.offset(len as isize) != b'\0' {
        len += 1;
    }
    println!("p0 len: {}", len);
    
    for _ in 0..c {
        print("Hello, World!\n");
    }
    exit(0);
}
