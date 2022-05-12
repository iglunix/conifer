#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(asm_sym)]
#![feature(fn_align)]
#![feature(ptr_as_uninit)]
#![feature(arbitrary_enum_discriminant)]

mod boot;
mod earlycon;
mod elf;
mod init;
mod mmu;
mod page;
mod panic;
mod sbi;
mod trap;
mod auxv;
// mod syscall;

fn main() {
    eprintln!("Conifer Micro-Kernel");

    let mut pages = page::PageDescTable::init();
    pages.dump();
    let sp = pages.alloc::<[u8; 4096]>(4);

    unsafe {
        let spu = sp as *mut usize;
        let spb = sp as *mut u8;
        let spo = spu as usize + 4096 * 3;
        let spu = core::slice::from_raw_parts_mut(spu, 512 * 4);
        let spb = core::slice::from_raw_parts_mut(spb, 4096 * 4);
        spb[4087 + 4096 * 3] = b'\0';
        spb[4086 + 4096 * 3] = b't';
        spb[4085 + 4096 * 3] = b'i';
        spb[4084 + 4096 * 3] = b'n';
        spb[4083 + 4096 * 3] = b'i';
        spu[257 + 512 * 3] = spo + 4096 - 13;
        spu[256 + 512 * 3] = 1;
    }

    let sp = sp as usize;

    let root = unsafe {
        pages
            .alloc::<crate::mmu::Table>(1)
            .as_uninit_mut()
            .unwrap()
            .write(crate::mmu::Table::new())
    };

    eprintln!("k2u start {:p}", trap::k2u as *const fn());
    mmu::map(
        &mut pages,
        root,
        trap::k2u as *const fn() as usize,
        trap::k2u as *const fn() as usize,
        mmu::Entry(0b1010),
        0,
    );

    unsafe {
    eprintln!("sscratch start {:p}", &trap::scratch as *const trap::Scratch);
    mmu::map(
        &mut pages,
        root,
        &trap::scratch as *const trap::Scratch as usize,
        &trap::scratch as *const trap::Scratch as usize,
        mmu::Entry(0b0110) | mmu::EntryFlags::Global,
        0,
    );
    }

    eprintln!("trap start {:p}", trap::trap_start as *const fn());
    mmu::map(
        &mut pages,
        root,
        trap::trap_start as *const fn() as usize,
        trap::trap_start as *const fn() as usize,
        mmu::Entry(0b1010),
        0,
    );
    for i in 0..4 {
        mmu::map(
            &mut pages,
            root,
            sp + (i << 12),
            sp + (i << 12),
            mmu::Entry(0b0110) | mmu::EntryFlags::User,
            0,
        );
    }

    // unsafe {
    //     for i in 0..((crate::boot::STACK_END - crate::boot::STACK_START + (1 << 12) - 1) >> 12) {
    //         mmu::map(
    //             &mut pages,
    //             root,
    //             crate::boot::STACK_START + (i << 12),
    //             crate::boot::STACK_START + (i << 12),
    //             mmu::Entry(0b0110) | mmu::EntryFlags::Global,
    //             0,
    //         )
    //     }
    // }
    sbi::set_timer((crate::read_csr!("time") as u64) + 10000000);
    unsafe { core::arch::asm!("wfi") };
    
    // eprintln!("using allocated stack pointer: {:p}", sp as *const u8);
    let sp = sp + 2048 + 4096 * 3;
    let sp = sp as *const u8;
    eprintln!("using allocated stack pointer: {:p}", sp);
    let entry = unsafe { elf::Elf::new(init::INIT_ELF.as_ptr()).load(root) };
    eprintln!("entry: {:b}", entry);
    eprintln!("page table: {:p}", root);
    root.dump();
    unsafe {
        trap::k2u(entry as *const fn(), sp, root);
    }
}
