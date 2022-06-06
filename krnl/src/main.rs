#![no_std]
#![no_main]
#![feature(asm_sym)]
#![feature(naked_functions)]
#![feature(fn_align)]
#![feature(core_intrinsics)]
#![feature(default_alloc_error_handler)]

#[macro_use]
extern crate earlycon;
extern crate elf;
extern crate fdt;

#[macro_use]
extern crate alloc;

mod heap;
mod mmu;
mod proc;
mod sys;
mod trap;

pub const INIT_ELF: &[u8] = include_bytes!("../../init.elf");
pub const KMEM_OFFSET: usize = 0xffffffe000000000;
pub const UMAP_OFFSET: usize = 0x20_0000_0000;

static mut FDT_SIZE: usize = 0;

fn init_heap(fdt: &fdt::Fdt) {
    let fdt_root = fdt.root();
    unsafe {
        FDT_SIZE = fdt.size();
    }
    // TODO: search for all nodes with device_type == "memory"
    let fdt_mem = fdt_root.node("memory");
    let fdt_mem_reg = fdt_mem.prop::<u64>("reg");
    let pmem_start = (u64::from_be(fdt_mem_reg[0]) + 0xffffffe000000000) as *mut [u8; 4096];
    let pmem_size = u64::from_be(fdt_mem_reg[1]) as usize;
    let pmem = unsafe { core::slice::from_raw_parts_mut(pmem_start, pmem_size >> 12) };

    heap::Heap::set_global(pmem)
}

#[no_mangle]
unsafe extern "C" fn _start(fdt_addr: usize, krnl_elf: usize) -> ! {
    core::arch::asm!("la t1, {}
          csrw stvec, t1
          csrw sie, {}",
          sym trap::k_trap_start, in(reg) (1 << 9) | (1 << 5) | (1 << 1));
    let fdt = fdt::Fdt::from_addr(fdt_addr);
    trap::KRNL_ELF_ADDR = krnl_elf;
    trap::FDT_ADDR = fdt_addr;
    init_heap(&fdt);
    main();
    loop {
        core::arch::asm!("wfi");
    }
}

fn main() {
    println!("=====================================================");
    println!("Conifer Micro Kernel! (SPDX-License-Identifier: 0BSD)");
    println!("=====================================================");

    let mut earlyinit = proc::Proc::new();
    let earlyinit_elf = unsafe { elf::Elf::new(INIT_ELF.as_ptr()) };

    earlyinit.load(&earlyinit_elf);
    earlyinit.dump();
    earlyinit.switch();
}
