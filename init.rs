#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(vec_push_within_capacity)]
#![feature(fn_align)]

extern crate alloc;
use alloc::vec::Vec;

mod panic_alloc {
    struct PanicAllocator;
    use alloc::alloc::GlobalAlloc;
    use alloc::alloc::Layout;
    unsafe impl GlobalAlloc for PanicAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            panic!("Must use allocator_api");
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            panic!("Must use allocator api");
        }
    }
    #[global_allocator]
    static GLOBAL: PanicAllocator = PanicAllocator;
}

#[naked]
#[no_mangle]
#[link_section = ".text._start"]
#[repr(align(4096))]
unsafe extern "C" fn _start() {
    core::arch::asm!(
        "nop",
        ".align 11",
        "1:",
        "nop",
        "j 1b",
        ".align 12",
        "addi sp, sp, -16",
        "tail {}",
        sym rust_start,
        options(noreturn)
    );
}
fn write_str(s: &str) {
    fn write_vals(vals: [usize; 6]) {
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a0") 0,
                in("a1") vals[0],
                in("a2") vals[1],
                in("a3") vals[2],
                in("a4") vals[3],
                in("a5") vals[4],
                in("a6") vals[5],
                in("a7") -1,
            );
        }
    }
    let mut idx = 0;
    let mut vals = [0; 6];
    let mut shift = 0;
    for b in s.bytes() {
        vals[idx] |= (b as usize) << shift;

        shift += 8;

        if shift == 64 {
            shift = 0;
            idx += 1;
        }

        if idx == 5 {
            idx = 0;
            write_vals(vals);
            vals = [0; 6];
        }
    }

    if idx != 0 || shift != 0 {
        write_vals(vals);
    }
}

#[inline(never)]
fn linux_sys_exit_group() {
    unsafe {
        //core::arch::asm!("ecall", in("a7") 94);
        core::arch::asm!("c.slli a7, 2", "c.jalr a7", in("a7") 94);
    }
}

fn switch(interval: usize) {

}

const PAGE_SIZE: usize = 0x1000;
const PAGE_SHIFT: usize = 12;

#[repr(transparent)]
struct CapAddr(usize);

#[repr(transparent)]
struct NullCap(CapAddr);

#[repr(transparent)]
struct MemCap(CapAddr);

impl MemCap {
	const SPLIT: 1;
	
	fn split(self, line: usize, dest: NullCap) -> (Self, Self) {
		
	}
}

extern "C" fn rust_start(fdt: usize) {
    eprintln!("Hello, World!");
    println!("Hay, Bitches!");
    eprintln!("fdt: {:x}", fdt);
    let init_mem = 

    // TODO: page frame allocator

    // TODO: create a new thread
    // switch to that thread

    // linux_sys_exit_group();
    // let mut v = Vec::<u8>::new();
    // v.try_reserve(1).unwrap();
    // v.push_within_capacity(1).unwrap();
    // eprintln!("{:?}", v);
    loop {}
}

pub struct Con;

impl core::fmt::Write for Con {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_str(s);
        Ok(())
    }
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    Con.write_fmt(args).unwrap();
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
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    eprintln!("{}", info);
    loop {}
}
