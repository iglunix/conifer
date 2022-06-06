#![no_std]
#![no_main]
#![feature(asm_sym)]
#![feature(naked_functions)]

#[macro_export]
macro_rules! read_csr {
    ($csr: expr) => {
        {
            #[allow(unused_unsafe)]
            let x = unsafe {
                let r: usize;
                core::arch::asm!(concat!("csrr {}, ", $csr), out(reg) r);
                r
            };
            x
        }
    }
}

#[macro_export]
macro_rules! write_csr {
    ($csr: expr, $v: expr) => {
        #[allow(unused_unsafe)]
        unsafe {
            core::arch::asm!(concat!("csrw ", $csr, ", {}"), in(reg) $v)
        }
    }
}

#[macro_use]
extern crate earlycon;

pub const KRNL_ELF: &[u8] = include_bytes!("../../krnl.elf");

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    eprintln!("{}", info);
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

#[no_mangle]
#[naked]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "la sp, _stack_end
         tail {}", sym entry,
        options(noreturn)
    );
}

extern "C" fn entry(_: usize, fdt_addr: usize) {
    main(fdt_addr);
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

#[no_mangle]
unsafe extern "C" fn boot(
    fdt_addr: usize,
    krnl_addr: usize,
    satp: usize,
    sp: usize,
    entry: usize,
) -> ! {
    core::arch::asm!(
        "csrw satp, {}
         sfence.vma
         mv sp, {}
         jr {}", in(reg) satp, in(reg) sp, in(reg) entry, in("a0") fdt_addr, in("a1") krnl_addr, options(noreturn))
}

fn main(fdt_addr: usize) {
    // let fdt = unsafe { fdt::Fdt::from_addr(fdt_addr) };
    // fdt.root().dump();

    let elf = unsafe { elf::Elf::new(KRNL_ELF.as_ptr()) };

    let mut heap: *mut u8;
    unsafe { core::arch::asm!("la {}, _heap_start", out(reg) heap) }

    let page_tbl_root: &mut [u64; 512] = unsafe {
        core::ptr::write_bytes(heap, 0, 1 << 12);
        let page_tbl = &mut *(heap as *mut [u64; 512]);
        heap = heap.offset(4096);
        page_tbl
    };
    eprintln!("page table root: {:p}", page_tbl_root);
    let page_tbl_mid: &mut [u64; 512] = unsafe {
        core::ptr::write_bytes(heap, 0, 1 << 12);
        let page_tbl = &mut *(heap as *mut [u64; 512]);
        heap = heap.offset(4096);
        page_tbl
    };
    let page_tbl_boot_mid: &mut [u64; 512] = unsafe {
        core::ptr::write_bytes(heap, 0, 1 << 12);
        let page_tbl = &mut *(heap as *mut [u64; 512]);
        heap = heap.offset(4096);
        page_tbl
    };
    let page_tbl_leaf: &mut [u64; 512] = unsafe {
        core::ptr::write_bytes(heap, 0, 1 << 12);
        let page_tbl = &mut *(heap as *mut [u64; 512]);
        heap = heap.offset(4096);
        page_tbl
    };
    let page_tbl_boot_leaf: &mut [u64; 512] = unsafe {
        core::ptr::write_bytes(heap, 0, 1 << 12);
        let page_tbl = &mut *(heap as *mut [u64; 512]);
        heap = heap.offset(4096);
        page_tbl
    };

    // put kernel at higher half of memory
    page_tbl_root[256] = (page_tbl_mid.as_ptr() as u64 >> 2) & !0x3ff & !(0x3ff << 54) | 1;
    page_tbl_mid[0] = (page_tbl_leaf.as_ptr() as u64 >> 2) & !0x3ff & !(0x3ff << 54) | 1;

    // map all memory to highest quarter of memory 0xffffffe000000000
    for i in 384..512 {
        // eprintln!("mapping vaddr {:x} to paddr {:x}", (i << 30) | 0xffffff8000000000, (i - 384) << 30);
        page_tbl_root[i] =
            ((i as u64 - 384) << 28) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;
    }

    let vaddr = boot as *const fn() as usize;

    let vpn = [
        (vaddr >> 12) & 0x1ff,
        (vaddr >> 21) & 0x1ff,
        (vaddr >> 30) & 0x1ff,
    ];

    page_tbl_root[vpn[2]] = (page_tbl_boot_mid.as_ptr() as u64 >> 2) & !0x3ff & !(0x3ff << 54) | 1;
    page_tbl_boot_mid[vpn[1]] =
        (page_tbl_boot_leaf.as_ptr() as u64 >> 2) & !0x3ff & !(0x3ff << 54) | 1;
    page_tbl_boot_leaf[vpn[0]] =
        (vaddr as u64 >> 2) & !0x3ff & !(0x3ff << 54) | (1 << 3) | (1 << 1) | 1;

    let mut highest_vpn0 = 0;

    for phdr in elf.phdrs {
        if matches!(phdr.ty, elf::PhType::Load) {
            let vaddr_start = phdr.vaddr;
            let vaddr_end = phdr.vaddr + phdr.memsz;
            // round vaddr start and end to the nearest page down and up respectively
            let vaddr_start = vaddr_start & !0xfff;
            let vaddr_end = (vaddr_end + 0xfff) & !0xfff;

            let required_mem = vaddr_end - vaddr_start;
            // eprintln!("mapping from {:x} to {:x}", vaddr_start, vaddr_end);

            assert_ne!(required_mem & !0xfff, 0);
            assert_eq!(required_mem & 0xfff, 0);

            unsafe {
                let copy_src = KRNL_ELF.as_ptr().offset(phdr.offset as isize);
                let copy_dst = heap.offset((phdr.vaddr & 0xfff) as isize);
                // eprintln!("copying from {:p} to {:p} ({:x})", copy_src, copy_dst, phdr.vaddr);
                core::ptr::copy_nonoverlapping(copy_src, copy_dst, phdr.filesz);
                core::ptr::write_bytes(
                    heap.offset(phdr.filesz as isize),
                    0,
                    phdr.memsz - phdr.filesz,
                );
            }

            for i in 0..(required_mem >> 12) {
                let vaddr = vaddr_start + (i << 12);
                let paddr = unsafe { heap.offset((i << 12) as isize) as u64 };
                // eprintln!("mapping addr {:x} to paddr {:x}", vaddr, paddr);
                let vpn = [
                    (vaddr >> 12) & 0x1ff,
                    (vaddr >> 21) & 0x1ff,
                    (vaddr >> 30) & 0x1ff,
                ];
                assert_eq!(vpn[2], 0x100);
                assert_eq!(vpn[1], 0);
                assert_ne!(page_tbl_root[vpn[2]], 0);
                assert_ne!(page_tbl_mid[vpn[1]], 0);

                let mut flags = 0;
                if (phdr.pflags & 1) > 0 {
                    flags = flags | (1 << 3);
                }
                if (phdr.pflags & 2) > 0 {
                    flags = flags | (1 << 2);
                }
                if (phdr.pflags & 4) > 0 {
                    flags = flags | (1 << 1);
                }
                page_tbl_leaf[vpn[0]] = (paddr >> 2) & !0x3ff & !(0x3ff << 54) | flags | 1;

                if highest_vpn0 < vpn[0] {
                    highest_vpn0 = vpn[0]
                }
            }
            heap = unsafe { heap.offset(required_mem as isize) };
        }
    }

    let _heap_vpn = highest_vpn0 + 1;
    let st: u64;
    let se: u64;
    unsafe {
        core::arch::asm!("la {}, _stack_start
                          la {}, _stack_end", out(reg) st, out(reg) se);
    }
    let st = st >> 12;
    let se = se >> 12;
    let count = se - st;
    eprintln!("stack pages: {}", count);
    for i in st..se {
        page_tbl_leaf[384 + (i as usize - st as usize)] =
            (i << 10) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;
        println!("need to map: {:x}", i << 12);
    }
    // unsafe {
    //     core::arch::asm!("wfi");
    // }

    // // Allocate a 16k stack for the kernel
    // page_tbl_leaf[511] = ((sp - 0x1000) >> 2) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;
    // page_tbl_leaf[510] = ((sp - 0x2000) >> 2) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;
    // page_tbl_leaf[509] = ((sp - 0x3000) >> 2) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;
    // page_tbl_leaf[508] = ((sp - 0x4000) >> 2) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;
    // page_tbl_leaf[507] = ((sp - 0x5000) >> 2) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;
    // page_tbl_leaf[506] = ((sp - 0x6000) >> 2) & !0x3ff & !(0x3ff << 54) | (1 << 2) | (1 << 1) | 1;

    // let sp = 0xffffffc000000000 + ((384 + count as usize - 1) << 12) + 0xf00;
    let sp = 0xffffffc000000000 + ((384 + count as usize) << 12);

    println!(
        "Jumping to higher half entry at: {:p}",
        elf.head.entry as *const fn()
    );

    let satp = (page_tbl_root.as_ptr() as usize >> 12) | 8 << 60;
    unsafe {
        boot(
            fdt_addr + 0xffffffe000000000,
            (KRNL_ELF.as_ptr() as usize) + 0xffffffe000000000,
            satp,
            sp,
            elf.head.entry,
        );
    }
}
