#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(vec_push_within_capacity)]
#![feature(fn_align)]
mod abi;
mod fdt;

extern crate alloc;
use alloc::vec::Vec;
use fdt::Fdt;

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
    core::arch::naked_asm!(
        "nop",
        ".align 11",
        "1:",
        "nop",
        "j 1b",
        ".align 12",
        "addi sp, sp, -16",
        "tail {}",
        sym rust_start,
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

unsafe fn parse_initial_total_size(ptr: *const ()) -> u32 {
    u32::from_be(core::ptr::read((ptr as *const u32).add(1)))
}

extern "C" fn rust_start(fdt: usize) {
    eprintln!("Hello, World!");
    println!("Beep Boop, I'm a computer!");
    use core::fmt::Write;
    Con.write_str("Sup!\n").unwrap();
    let task = TaskCap(CapAddr(0));
    eprintln!("fdt: {:x}", fdt);
    let init_mem = MemCap(CapAddr(1));
    let rest_mem = NullCap(CapAddr(2));
    // the fdt address is 8 bytes aligned (according to the device tree spec)
    // thus the totalsize and magic will not stradle two pages since they are
    // both 4 byte fields
    let fdt_aligned_base = fdt & !(PAGE_SIZE - 1);
    let fdt_aligned_offset = fdt & (PAGE_SIZE - 1);
    eprintln!("rest_mem:");
    cap_id(3);
    eprintln!("init_mem:");
    cap_id(2);
    let (init_mem, rest_mem) = init_mem.split(rest_mem, fdt_aligned_base).unwrap();
    let fdt_start_mem = NullCap(CapAddr(3));
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
        println!("eee");
        let ptr = ((0x200000 - 4096) as *const ()).byte_add(fdt_aligned_offset);
        let size = parse_initial_total_size(ptr) as usize;
        println!("{}", size);
        let size_aligned = (size + fdt_aligned_offset + 4096) & !(4095);
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
        let ptr =
            ((0x200000 - size_aligned) as *const ()).byte_add(fdt_aligned_offset) as *const u8;
        eprintln!("mapped whole fdt at addr {:p}", ptr);
        core::slice::from_raw_parts(ptr, size)
    };

    let fdt = Fdt::new(fdt);
    eprintln!("{:#?}", fdt);
    /*
    for mem in fdt.root().get_all("memory") {
        println!("{:#?}", mem);
    }
    let chosen = fdt.chosen();
    eprintln!("{:#?}", chosen);
    let reserved = fdt.get_node("/reserved-memory").unwrap();
    eprintln!("{:#?}", reserved);
    for node in reserved.nodes() {
        println!("{:#?}", node);
        let reg = node.get_prop("reg").unwrap();
        let a: &[u8; 8] = reg[0..8].try_into().unwrap();
        let a = usize::from_be_bytes(a.clone());
        let b: &[u8; 8] = reg[8..16].try_into().unwrap();
        let b = usize::from_be_bytes(b.clone());
        println!("{:16x?}", a);
        println!("{:16x?}", b);
    }
    */
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

pub struct Con;

impl core::fmt::Write for Con {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        fn write_vals(vals: [usize; 6]) -> core::fmt::Result {
            unsafe {
                syscall(
                    vals[0],
                    vals[1],
                    vals[2],
                    vals[3],
                    vals[4],
                    vals[5],
                    abi::Syscall::ConWrite,
                )
                .or(Err(core::fmt::Error))
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

            if idx == 4 {
                idx = 0;
                write_vals(vals)?;
                vals = [0; 6];
            }
        }

        if idx != 0 || shift != 0 {
            write_vals(vals)?;
        }
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

struct CapAlloc {
    brk: usize,
}

enum AllocError {}

impl CapAlloc {
    fn map_more(inc: usize) {}

    fn map_less(dec: usize) {}
}

/*
struct PageVec<T> {
    ptr: NonZero<T>,
    capacity: usize,
    len: usize
}

impl PageVec<T> {
    fn try_push(&mut self, t: T) -> Result<(), ()> {
        if self.len < self.capacity {
            unsafe {
                ptr.add(self.len).write(t);
            }
            self.len += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    fn grow(&mut self, mem: MemCap) {

    }

    fn shrink(&mut self) -> MemCap {

    }
}

struct CapHeap {
    let free_list: PageVec<usize>
}

impl CapHeap {
    fn alloc(&mut self) -> NullCap {

    }
}
*/

// struct PageAlloc<'a> {
// }

// given a list of regions
// split regions up into power of two sections
// initialise seperate buddys for each section
// have agregate allocator object
