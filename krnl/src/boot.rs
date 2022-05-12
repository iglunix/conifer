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

#[no_mangle]
#[naked]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "la sp, _stack_end
         tail {}", sym entry,
        options(noreturn)
    );
}

use crate::mmu;

// TODO: higher half
// const OFFSET: usize = 0xffffffff00000000;
const OFFSET: usize = 0;

#[repr(align(4096))]
#[link_section = ".boot"]
extern "C" fn entry() {
    unsafe {
        crate::eprintln!("TEXT   {:0>16x} -> {:0>16x}", TEXT_START, TEXT_END);
        crate::eprintln!("RODATA {:0>16x} -> {:0>16x}", RODATA_START, RODATA_END);
        crate::eprintln!("DATA   {:0>16x} -> {:0>16x}", DATA_START, DATA_END);
        crate::eprintln!("BSS    {:0>16x} -> {:0>16x}", BSS_START, BSS_END);
        crate::eprintln!("STACK  {:0>16x} -> {:0>16x}", STACK_START, STACK_END);
        crate::eprintln!("HEAP   {:0>16x} -> {:0>16x}", HEAP_START, HEAP_END);
    }

    unsafe {
        let trap_addr: usize;
        core::arch::asm!("la t1, {}
              csrw stvec, t1",
              sym crate::trap::trap_start, out("t1") trap_addr);
        assert_eq!(trap_addr, read_csr!("stvec"));

        write_csr!("sie", (1 << 9) | (1 << 5) | (1 << 1));
        // write_csr!("sip", (1 << 9) | (1 << 5) | (1 << 1));
        crate::eprintln!("sip: {:x}", read_csr!("sip"));
    }

    let mut pages = crate::page::PageDescTable::init();
    pages.clear();

    let root = unsafe {
        pages
            .alloc::<crate::mmu::Table>(1)
            .as_uninit_mut()
            .unwrap()
            .write(crate::mmu::Table::new())
    };

    mmu::map(
        &mut pages,
        root,
        root as *const mmu::Table as usize + OFFSET,
        root as *const mmu::Table as usize,
        mmu::Entry(0b0110),
        0,
    );

    unsafe {
        mmu::map(
            &mut pages,
            root,
            &crate::trap::scratch as *const crate::trap::Scratch as usize,
            &crate::trap::scratch as *const crate::trap::Scratch as usize,
            mmu::Entry(0b0110) | mmu::EntryFlags::Global,
            0,
        );
        
        for i in 0..((TEXT_END - TEXT_START + (1 << 12) - 1) >> 12) {
            mmu::map(
                &mut pages,
                root,
                TEXT_START + (i << 12) + OFFSET,
                TEXT_START + (i << 12),
                mmu::Entry(0b1010) | mmu::EntryFlags::Global,
                0,
            )
        }

        for i in 0..((HEAP_END - HEAP_START + (1 << 12) - 1) >> 12) {
            mmu::map(
                &mut pages,
                root,
                HEAP_START + (i << 12) + OFFSET,
                HEAP_START + (i << 12),
                mmu::Entry(0b0110) | mmu::EntryFlags::Global,
                0,
            )
        }


        mmu::map(
            &mut pages,
            root,
            crate::init::init_fn as *const fn() as usize + OFFSET,
            crate::init::init_fn as *const fn() as usize,
            mmu::Entry(0b1010) | mmu::EntryFlags::User,
            0,
        );

        mmu::map(
            &mut pages,
            root,
            entry as *const fn() as usize,
            entry as *const fn() as usize,
            mmu::Entry(0b1010),
            0,
        );

        // mmu::map(
        //     &mut pages,
        //     root,
        //     0xffffffff00000000,
        //     crate::trap::trap_start as *const fn() as usize,
        //     mmu::Entry(0b1010) | mmu::EntryFlags::Global,
        //     0,
        // );

        mmu::map(
            &mut pages,
            root,
            crate::trap::trap_start as *const fn() as usize + OFFSET,
            crate::trap::trap_start as *const fn() as usize,
            mmu::Entry(0b1010) | mmu::EntryFlags::Global,
            0,
        );

        mmu::map(
            &mut pages,
            root,
            crate::trap::k2u as *const fn() as usize + OFFSET,
            crate::trap::k2u as *const fn() as usize,
            mmu::Entry(0b1010) | mmu::EntryFlags::Global,
            0,
        );

        for i in 0..((RODATA_END - RODATA_START + (1 << 12) - 1) >> 12) {
            mmu::map(
                &mut pages,
                root,
                RODATA_START + (i << 12) + OFFSET,
                RODATA_START + (i << 12),
                mmu::Entry(0b0010) | mmu::EntryFlags::Global,
                0,
            )
        }

        for i in 0..((BSS_END - BSS_START + (1 << 12) - 1) >> 12) {
            mmu::map(
                &mut pages,
                root,
                BSS_START + (i << 12) + OFFSET,
                BSS_START + (i << 12),
                mmu::Entry(0b0110) | mmu::EntryFlags::Global,
                0,
            )
        }

        for i in 0..((STACK_END - STACK_START + (1 << 12) - 1) >> 12) {
            mmu::map(
                &mut pages,
                root,
                STACK_START + (i << 12) + OFFSET,
                STACK_START + (i << 12),
                mmu::Entry(0b0110) | mmu::EntryFlags::Global,
                0,
            )
        }
    }

    let addr = pages.alloc::<[u8; 4096]>(1);
    unsafe {
        (*addr)[0] = 100;
    }
    let addr = addr as usize;

    assert_eq!(core::mem::size_of::<mmu::Table>(), 4096);
    assert_eq!(core::mem::align_of::<mmu::Table>(), 4096);

    mmu::map(&mut pages, root, 0x001000, addr, mmu::Entry(0b1110), 0);

    crate::eprintln!(
        "address: 0x{:x}",
        mmu::virt_to_phys(root, crate::init::init_fn as *const () as usize + OFFSET).unwrap()
    );
    unsafe {
        // root.dump();
        // write_csr!("sstatus", read_csr!("sstatus") | 1 << 18);
        core::arch::asm!("sfence.vma zero, zero");
        let target_addr = higher_entry as *const fn() as usize + OFFSET;
        crate::eprintln!("higher half entry point: 0x{:x}", target_addr);
        // write_csr!(
        //     "sstatus",
        //     ((root as *const mmu::Table as usize) >> 12 | 8 << 60)
        // );
        crate::trap::scratch.satp = ((root as *const mmu::Table as usize) >> 12 | 8 << 60);
        write_csr!(
            "satp",
            ((root as *const mmu::Table as usize) >> 12 | 8 << 60)
        );
        core::arch::asm!("jr t1", in("t1") target_addr);
    }
}

fn higher_entry() {
    unsafe {
        write_csr!("stvec", crate::trap::trap_start as *const fn() as usize + OFFSET);
        crate::println!("stvec: 0x{:x}", read_csr!("stvec"));
        // write_csr!(
        //     "sscratch",
        //     (crate::trap::trap_entry as *const fn() as usize)
        // );
        crate::trap::scratch.trap_entry = crate::trap::trap_entry as *const fn() as usize;
        write_csr!(
            "sscratch",
            &crate::trap::scratch as *const crate::trap::Scratch as usize
        );
        crate::eprintln!(
            "sstatus:  e c a 8 6 4 2 0 e c a 8 6 4 2 0 e c a 8 6 4 2 0 e c a 8 6 4 2 0"
        );
        crate::eprintln!("sstatus: {:b}", read_csr!("sstatus"));
        crate::println!("I'm a mapped ptr: {}", *(0x1000 as *const usize));
        crate::eprintln!("main: {:p}", crate::main as *const fn());
        core::arch::asm!("jr t1", in("t1") crate::main as *const fn() as usize + OFFSET);
    }
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }

}

core::arch::global_asm!(
    "
.section .rodata
.global TEXT_START
TEXT_START: .dword _text_start
.global TEXT_END
TEXT_END: .dword _text_end

.global RODATA_START
RODATA_START: .dword _rodata_start
.global RODATA_END
RODATA_END: .dword _rodata_end

.global DATA_START
DATA_START: .dword _data_start
.global DATA_END
DATA_END: .dword _data_end

.global BSS_START
BSS_START: .dword _bss_start
.global BSS_END
BSS_END: .dword _bss_end

.global STACK_START
STACK_START: .dword _stack_start
.global STACK_END
STACK_END: .dword _stack_end

.global HEAP_START
HEAP_START: .dword _heap_start
.global HEAP_END
HEAP_END: .dword _memory_end
.global HEAP_SIZE
HEAP_SIZE: .dword _heap_size
"
);

extern "C" {
    pub static TEXT_START: usize;
    pub static TEXT_END: usize;
    pub static RODATA_START: usize;
    pub static RODATA_END: usize;
    pub static DATA_START: usize;
    pub static DATA_END: usize;
    pub static BSS_START: usize;
    pub static BSS_END: usize;
    pub static STACK_START: usize;
    pub static STACK_END: usize;
    pub static HEAP_START: usize;
    pub static HEAP_END: usize;
    pub static HEAP_SIZE: usize;
}
