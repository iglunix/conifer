#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(vec_push_within_capacity)]
#![feature(fn_align)]
mod abi;

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
fn syscall(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a7: abi::Syscall,
) -> Result<(), abi::SysError> {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "ecall",
            lateout("a0") ret,
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            in("a7") -(a7.0 as isize),
            clobber_abi("C")
        );
    }
    match ret {
        0 => Ok(()),
        e => Err(unsafe { core::mem::transmute(e) }),
    }
}

#[inline(never)]
fn linux_sys_exit_group() {
    unsafe {
        //core::arch::asm!("ecall", in("a7") 94);
        core::arch::asm!("c.slli a7, 2", "c.jalr a7", in("a7") 94);
    }
}

fn switch(interval: usize) {}

const PAGE_SIZE: usize = 0x1000;
const PAGE_SHIFT: usize = 12;

#[repr(transparent)]
struct CapAddr(usize);

#[repr(transparent)]
struct NullCap(CapAddr);

#[repr(transparent)]
struct MemCap(CapAddr);

#[repr(transparent)]
struct TaskCap(CapAddr);

impl MemCap {
    const SPLIT: usize = 3;

    fn split(self, dest: NullCap, line: usize) -> Result<(Self, Self), abi::SysError> {
        syscall(self.0 .0, dest.0 .0, line, 0, 0, 0, abi::Syscall::MemSplit)?;
        Ok((self, MemCap(dest.0)))
    }
}

fn cap_id(addr: usize) {
    syscall(addr, 0, 0, 0, 0, 0, abi::Syscall::CapIdentify);
}

impl TaskCap {
    fn map_mem(
        &self,
        mem: MemCap,
        addr: usize,
        level: usize,
        prot: abi::Prot,
    ) -> Result<NullCap, abi::SysError> {
        syscall(
            self.0 .0,
            mem.0 .0,
            addr,
            level,
            prot as usize,
            0,
            abi::Syscall::TaskMapMem,
        )
        .map(|_| NullCap(mem.0))
    }

    fn unmap_mem(&self, mem: NullCap, addr: usize, level: usize) -> Result<MemCap, abi::SysError> {
        syscall(
            self.0 .0,
            mem.0 .0,
            addr,
            level,
            0,
            0,
            abi::Syscall::TaskUnmapMem,
        )
        .map(|_| MemCap(mem.0))
    }

    fn map_cap(&self, mem: MemCap, addr: usize, level: usize) {
        todo!();
    }

    fn unmap_cap(&self, mem: NullCap, addr: usize, level: usize) -> MemCap {
        todo!();
    }
}

#[derive(Debug)]
struct FdtHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

impl FdtHeader {
    unsafe fn parse_from(ptr: *const u32) -> Self {
        Self {
            magic: u32::from_be(core::ptr::read(ptr)),
            totalsize: u32::from_be(core::ptr::read(ptr.add(1))),
            off_dt_struct: u32::from_be(core::ptr::read(ptr.add(2))),
            off_dt_strings: u32::from_be(core::ptr::read(ptr.add(3))),
            off_mem_rsvmap: u32::from_be(core::ptr::read(ptr.add(4))),
            version: u32::from_be(core::ptr::read(ptr.add(5))),
            last_comp_version: u32::from_be(core::ptr::read(ptr.add(6))),
            size_dt_strings: u32::from_be(core::ptr::read(ptr.add(7))),
            size_dt_struct: u32::from_be(core::ptr::read(ptr.add(8))),
        }
    }
}

unsafe fn parse_initial_total_size(ptr: *const ()) -> u32 {
    u32::from_be(core::ptr::read((ptr as *const u32).add(1)))
}

fn parse_fdt(fdt_raw: &[u8]) {
	let magic: &[u8; 4] = fdt_raw[0..4].try_into().unwrap();
	let magic = u32::from_be_bytes(magic.clone());
	eprintln!("{:x}", magic);
	let off_dt_struct: &[u8; 4] = fdt_raw[8..12].try_into().unwrap();
	let off_dt_struct = u32::from_be_bytes(off_dt_struct.clone()) as usize;
	eprintln!("off_dt_struct: {}", off_dt_struct);
	let off_dt_strings: &[u8; 4] = fdt_raw[12..16].try_into().unwrap();
	let off_dt_strings = u32::from_be_bytes(off_dt_strings.clone()) as usize;
	eprintln!("off_dt_strings: {}", off_dt_strings);
	let size_dt_strings: &[u8; 4] = fdt_raw[32..36].try_into().unwrap();
	let size_dt_strings = u32::from_be_bytes(size_dt_strings.clone()) as usize;
	eprintln!("size_dt_strings: {}", size_dt_strings);
	let size_dt_struct: &[u8; 4] = fdt_raw[36..40].try_into().unwrap();
	let size_dt_struct = u32::from_be_bytes(size_dt_struct.clone()) as usize;
	eprintln!("size_dt_struct: {}", size_dt_struct);

	const FDT_BEGIN_NODE: u32 = 0x0000_0001;
	const FDT_END_NODE: u32 = 0x0000_0002;
	const FDT_PROP: u32 = 0x0000_0003;
	const FDT_NOP: u32 = 0x0000_0004;
	const FDT_END: u32 = 0x0000_0009;

	let mut i = off_dt_struct;
	let mut depth = 0;
	while {
		if (i % 4) != 0 {
			panic!("not aligned");
		}

		if i >= (off_dt_struct + size_dt_struct) {
			panic!("out of bounds");
		}
		let a: &[u8; 4] = fdt_raw[i..i + 4].try_into().unwrap();
		let a = u32::from_be_bytes(a.clone());
		i += 4;
		match a {
			FDT_BEGIN_NODE => {
				for i in 0..depth {
					print!("=")
				}
				print!("= begin ");
				while fdt_raw[i] != 0 {
					print!("{}", char::from_u32(fdt_raw[i] as u32).unwrap());
					i+=1;
				}
				i+=1;
				println!();
				while (i%4) != 0 {
					if (fdt_raw[i] != 0) {
						panic!();
					}
					i += 1;
				}
				depth += 1;
				true
			}
			FDT_END_NODE => {
				depth -= 1;
				for i in 0..depth {
					print!("=")
				}
				println!("= end");
				depth != 0
			}
			FDT_PROP => {
				let len: &[u8; 4] = fdt_raw[i..i+4].try_into().unwrap();
				let len = u32::from_be_bytes(len.clone());
				i += 4;
				let nameoff: &[u8; 4] = fdt_raw[i..i+4].try_into().unwrap();
				let nameoff = u32::from_be_bytes(nameoff.clone());
				i += 4;
				for i in 0..depth {
					print!("=")
				}
				print!("= prop {} ", len);
				let mut j = off_dt_strings + nameoff as usize;
				while {
					if j >= (off_dt_strings + size_dt_strings) {
						panic!();
					}
					fdt_raw[j] != 0
				} {
					print!("{}", char::from_u32(fdt_raw[j] as u32).unwrap());
					j += 1;
				}
				println!("{:x?}", &fdt_raw[i..(i+len as usize)]);

				i += len as usize;
				while (i%4) != 0 {
					i += 1;
				}
				true
			}
			FDT_NOP => true,
			FDT_END => false,
			v => {
				println!("parse failed: {}:{:x}", i, v);
				eprintln!("{:x?}", &fdt_raw[i-4..i+4]);
				true
			}
		}
	} {}
}

extern "C" fn rust_start(fdt: usize) {
    eprintln!("Hello, World!");
    println!("Hay, Bitches!");
    use core::fmt::Write;
    Con(0).write_str("Sup!\n").unwrap();
    let task = TaskCap(CapAddr(1));
    eprintln!("fdt: {:x}", fdt);
    let init_mem = MemCap(CapAddr(2));
    let rest_mem = NullCap(CapAddr(3));
    let (init_mem, rest_mem) = init_mem.split(rest_mem, fdt).unwrap();
    let fdt_start_mem = NullCap(CapAddr(4));
    let (fdt_start_mem, rest_mem) = rest_mem.split(fdt_start_mem, PAGE_SIZE).unwrap();

    cap_id(0);
    cap_id(1);
    cap_id(2);
    cap_id(3);
    cap_id(4);
    let mut rest_mem = rest_mem;
    let fdt = unsafe {
        let null_cap = task
            .map_mem(fdt_start_mem, 0x200000 - 4096, 52, abi::Prot::Read)
            .unwrap();
        let ptr = (0x200000 - 4096) as *const ();
        let size = parse_initial_total_size(ptr) as usize;
        println!("{}", size);
        let size_aligned = (size + 4096) & !(4095);
        println!("{}", size_aligned);
        let mem_cap = task.unmap_mem(null_cap, 0x200000 - 4096, 52).unwrap();
        let mut null_cap = task
            .map_mem(mem_cap, 0x200000 - size_aligned, 52, abi::Prot::Read)
            .unwrap();
        let mut written = PAGE_SIZE;
        while written < size_aligned {
            let (fdt_page, rest) = rest_mem.split(null_cap, PAGE_SIZE).unwrap();
            rest_mem = rest;
            null_cap = task
                .map_mem(
                    fdt_page,
                    0x200000 - size_aligned + written,
                    52,
                    abi::Prot::Read,
                )
                .unwrap();
            written += 4096
        }
        let ptr = (0x200000 - size_aligned) as *const () as *const u8;
        eprintln!("mapped whole fdt at addr {:p}", ptr);
        core::slice::from_raw_parts(ptr, size)
    };

    parse_fdt(fdt);
    panic!();

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

pub struct Con(usize);

impl core::fmt::Write for Con {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        fn write_vals(cap: usize, vals: [usize; 5]) -> core::fmt::Result {
            unsafe {
                syscall(
                    cap,
                    vals[0],
                    vals[1],
                    vals[2],
                    vals[3],
                    vals[4],
                    abi::Syscall::ConWrite,
                )
                .or(Err(core::fmt::Error))
            }
        }
        let mut idx = 0;
        let mut vals = [0; 5];
        let mut shift = 0;
        for b in s.bytes() {
            vals[idx] |= (b as usize) << shift;

            shift += 8;

            if shift == 64 {
                shift = 0;
                idx += 1;
            }

            if idx == 4 {
                idx = 0;
                write_vals(self.0, vals)?;
                vals = [0; 5];
            }
        }

        if idx != 0 || shift != 0 {
            write_vals(self.0, vals)?;
        }
        Ok(())
    }
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    Con(0).write_fmt(args).unwrap();
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
