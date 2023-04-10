#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(fn_align)]

#[macro_use]
extern crate con;

extern crate elf;
extern crate fdt;

#[repr(C)]
#[derive(Clone, Copy)]
struct PageTblEntry(u64);
impl  PageTblEntry {
    const fn new() -> Self {
        Self(0)
    }

    fn set_addr(&mut self, paddr: usize) {
        // 56 bit paddr
        let paddr = paddr & ((1 << 56) - 1);
        // 12 bit page offset
        let paddr = paddr >> 12;
        self.0 &= !(((1 << 44) - 1) << 10);
        self.0 |= (paddr as u64) << 10;
    }

    fn addr(&self) -> usize {
        ((self.0 & (((1 << 56) - 1) << 10)) << 2) as usize
    }

    fn set_global(&mut self, global: bool) {
        if global {
            self.0 |= 1 << 5;
        } else {
            self.0 &= !(1 << 5);
        }
    }

    fn set_user(&mut self, user: bool) {
        if user {
            self.0 |= 1 << 4;
        } else {
            self.0 &= !(1 << 4);
        }
    }

    fn set_exec(&mut self, exec: bool) {
        if exec {
            self.0 |= 1 << 3;
        } else {
            self.0 &= !(1 << 3);
        }
    }

    fn set_write(&mut self, write: bool) {
        if write {
            self.0 |= 1 << 2;
        } else {
            self.0 &= !(1 << 2);
        }
    }

    fn set_read(&mut self, read: bool) {
        if read {
            self.0 |= 1 << 1;
        } else {
            self.0 &= !(1 << 1);
        }
    }

    fn set_valid(&mut self, valid: bool) {
        if valid {
            self.0 |= 1 << 0;
        } else {
            self.0 &= !(1 << 0);
        }
    }

    fn valid(&self) -> bool {
        (self.0 & 1) > 0
    }
}

#[repr(C)]
#[repr(align(0x1000))]
#[derive(Clone)]
struct PageTbl([PageTblEntry; 0x200]);

// We need to allocate space for 4 page tables ready for loading the kernel:
//  - the top level page table
//  - the higher half level 1 page table
//  - the stack page table (at the high end of the high half)
//  - the kernel text page table (at the low end of he high half)
static mut KTBL: PageTbl = PageTbl([PageTblEntry::new(); 0x200]);

macro_rules! include_bytes_aligned {
    ($align_to:expr, $path:expr) => {{
        #[repr(C, align($align_to))]
        struct __Aligned<T: ?Sized>(T);

        static __DATA: &'static __Aligned<[u8]> = &__Aligned(*include_bytes!($path));

        &__DATA.0
    }};
}

#[repr(align(0x1000))]
struct Stack([u8; 0x100000]);

static mut STACK: Stack = Stack([0; 0x100000]);

#[repr(align(0x1000))]
struct Buddy([u8; 0x100000]);

static mut BUDDY: Buddy = Buddy([0; 0x100000]);

#[repr(align(0x1000))]
struct Zero([u8; 0x1000]);
static ZERO: Zero = Zero([0; 0x1000]);

// Mark pages as used in the buddy allocator
//  - Note we only mark the first buddy. Everything else we fill out when we
//    get to the kernel
fn reserve_page(idx: usize) {
    unsafe {
        let block = &mut BUDDY.0[idx >> 3]; // divide by 8 since we fit 8 bits ina block
        let val = *block | (1 << (idx & 0b111));
        *block = val;
    }
}

fn is_reserved_page(idx: usize) -> bool {
    unsafe {
        let block = &mut BUDDY.0[idx >> 3]; // divide by 8 since we fit 8 bits ina block
        (*block & (1 << (idx & 0b111))) > 0
    }
}

static KRNL_ELF: &[u8] = include_bytes_aligned!(0x1000, "../out/krnl.elf");

extern "C" {
    static _boot_start: usize;
    static _boot_end: usize;
}
fn boot_start() -> usize {
    unsafe { 0x80000000 }
}

fn boot_end() -> usize {
    unsafe { 0x80100000 }
}

fn reserve_pages() {
    // We need to mark memory as allocated so the kernel does not trample over
    // important things.
    //
    // We need to mark the following:
    //  - SBI's pages so ecalls to SBI work
    //  - The buddy allocator pages themselves
    //  - Pages used for the kernel binary
    //  - The kernel stack
    //
    // We notably do not mark boot since the kernel doesn't need it. None of
    // those pages will ever be needed again. We do however reuse the stack
    // (though resetting the sp to the top again) so we do mark those pages.
    println!("Reserving SBI pages");
    for i in 0..32 {
        reserve_page(i);
    }
    println!("Reserving buddy pages");
    let buddy_start = unsafe { &BUDDY } as *const Buddy as usize;
    let buddy_start = (buddy_start - 0x80000000) >> 12;
    let buddy_end = buddy_start + 0x100;
    for i in buddy_start..buddy_end {
        reserve_page(i);
    }

    println!("Reserving Kernel pages");
    let krnl_start = unsafe { KRNL_ELF }.as_ptr() as usize - 0x80000000;
    let krnl_end = krnl_start + unsafe { KRNL_ELF }.len();
    let krnl_start = krnl_start >> 12;
    let krnl_end = krnl_end >> 12;
    for i in krnl_start..krnl_end {
        reserve_page(i);
    }

    println!("Reserving stack pages");
    let stack_start = unsafe { &STACK } as *const Stack as usize;
    let stack_start = (stack_start - 0x80000000) >> 12;
    let stack_end = stack_start + 0x1000;
    for i in stack_start..stack_end {
        reserve_page(i);
    }

    println!("Reserving Page Table pages");
    let tbl_start = unsafe { &KTBL } as *const PageTbl as usize;
    let tbl_start = (tbl_start - 0x80000000) >> 12;
    reserve_page(tbl_start);

    println!("Reserved pages");
}

fn alloc_page() -> usize {
    let start_page = (boot_end() - boot_start()) >> 12;
    let mut page = start_page;
    while is_reserved_page(page) {
        page += 1;
    }
    reserve_page(page);
    let ret = boot_start() + (page << 12);

    ret
}

#[repr(u8)]
enum Prot {
    Ro = 0b001,
    Rw = 0b011,
    Rx = 0b101,
    Rwx = 0b111
}

fn map(paddr: usize, vaddr: usize, read: bool, write: bool, exec: bool) {
    let vpn = [
        (vaddr >> 12) & 0b111111111,
        (vaddr >> 21) & 0b111111111,
        (vaddr >> 30) & 0b111111111,
    ];

    let root = unsafe { &mut KTBL };
    let root_pte = &mut root.0[vpn[2]];

    let mid = if !root_pte.valid() {
        let mid = alloc_page();
        root_pte.set_addr(mid);
        root_pte.set_valid(true);
        let mid = mid as *mut PageTbl;
        let mid = unsafe { &mut *mid };
        *mid = PageTbl([PageTblEntry::new(); 0x200]);
        mid
    } else {
        let mid = root_pte.addr();
        let mid = mid as *mut PageTbl;
        let mid = unsafe { &mut *mid };
        mid
    };

    let mid_pte = &mut mid.0[vpn[1]];

    let leaf = if !mid_pte.valid() {
        let leaf = alloc_page();
        mid_pte.set_addr(leaf);
        mid_pte.set_valid(true);
        let leaf = leaf as *mut PageTbl;
        let leaf = unsafe { &mut *leaf };
        *leaf = PageTbl([PageTblEntry::new(); 0x200]);
        leaf
    } else {
        let leaf = mid_pte.addr();
        let leaf = leaf as *mut PageTbl;
        let leaf = unsafe { &mut *leaf };
        leaf
    };

    let leaf_pte = &mut leaf.0[vpn[0]];
    leaf_pte.set_addr(paddr);
    leaf_pte.set_read(read);
    leaf_pte.set_write(write);
    leaf_pte.set_exec(exec);
    leaf_pte.set_valid(true);
}

fn zero_paddr() -> usize {
    ZERO.0.as_ptr() as usize
}

fn map_kernel() -> usize {
    println!("Mapping kernel");
    let elf = unsafe { elf::Elf::from_bytes(KRNL_ELF) };
    elf.phdrs.into_iter().for_each(|hdr| {
        match hdr.ty {
            elf::PhType::Load => {
                let base_paddr = KRNL_ELF.as_ptr() as usize + hdr.offset;
                let base_paddr_aligned = base_paddr & !0xfff;
                let base_vaddr = hdr.vaddr;
                let base_vaddr_aligned = base_vaddr & !0xfff;
                assert_eq!(base_paddr & 0xfff, base_vaddr & 0xfff);
                let file_len = ((base_paddr & 0xfff) + (hdr.filesz + 0xfff)) >> 12;
                let mem_len = ((base_vaddr & 0xfff) + (hdr.memsz + 0xfff)) >> 12;
                for i in 0..file_len {
                    map(
                        base_paddr_aligned + (i << 12), base_vaddr_aligned + (i << 12),
                        (hdr.pflags & 0x4) > 0,
                        (hdr.pflags & 0x2) > 0,
                        (hdr.pflags & 0x1) > 0
                    );
                }
                for i in file_len..mem_len {
                    map(
                        zero_paddr(), base_vaddr_aligned + (i << 12),
                        (hdr.pflags & 0x4) > 0,
                        (hdr.pflags & 0x2) > 0,
                        (hdr.pflags & 0x1) > 0
                    );
                }
            }
            _ => {}
        }
    });
    println!("Mapped kernel");
    elf.head.entry
}

fn map_stack() {
    println!("Mapping stack");
    // Kernel stack goes right at the top of virtual memory
    //let stack_end = 0xffffffff_fffff000;
    let stack_end : usize = 0;
    let stack_len : usize = unsafe { STACK.0.len() };
    let stack_start : usize = stack_end.wrapping_sub(stack_len);
    let paddr = unsafe { STACK.0.as_ptr() } as usize;
    for i in 0..(stack_len >> 12) {
        map(paddr + (i << 12), stack_start + (i << 12), true, true, false);
    }
    println!("Mapped stack");
}

fn map_buddy() {
    println!("Mapping Buddy");
    let buddy_addr = 0xffffffff_00000000;
    let paddr = unsafe { &mut BUDDY } as *mut Buddy as usize;
    let buddy_len = 0x100000;
    for i in 0..(buddy_len >> 12) {
        map(paddr + (i << 12), buddy_addr + (i << 12), true, true, false);
    }
    println!("Mapped Buddy");
}

#[repr(align(0x1000))]
fn boot(entry: usize, fdt_addr: usize, buddy_addr: usize) -> ! {
    let root_ppn = (unsafe { KTBL.0.as_ptr() } as usize) >> 12;
    let satp_val = 8 << 60 | root_ppn;
    unsafe {
        let sp: usize = 0xfffffffffffffff0;
        // core::arch::asm!(
        //     "csrw satp, {}
        //      mv sp, {}
        //      sfence.vma
        //      wfi", in(reg) satp_val, in(reg) sp, options(noreturn))
        core::arch::asm!(
            "csrw satp, {}
             mv sp, {}
             sfence.vma
             jr {}", in(reg) satp_val, in(reg) sp, in(reg) entry, in("a0") fdt_addr, in("a1") buddy_addr, options(noreturn))
    }
}

fn physical_memory_span(fdt: &fdt::Fdt) -> (usize, usize) {
    let memory = fdt.root().node("memory@");
    memory.dump();
    let reg = memory.prop("reg");
    let device_type: &[u8] = memory.prop("device_type");
    let device_type = core::str::from_utf8(&device_type[..(device_type.len() - 1)]).unwrap();
    assert_eq!(device_type, "memory");
    let mem_start = u64::from_be_bytes(reg[0..8].try_into().unwrap());
    let mem_len = u64::from_be_bytes(reg[8..16].try_into().unwrap());
    eprintln!("Physical memory spans: {:x} -> {:x}", mem_start, mem_start + mem_len);

    (mem_start as usize, (mem_start + mem_len) as usize)
}

fn main(fdt_addr: usize) {
    let fdt = unsafe { fdt::Fdt::from_addr(fdt_addr) };
    physical_memory_span(&fdt);

    reserve_pages();
    let entry = map_kernel();
    map_stack();
    map_buddy();
    map(
        boot as *const () as usize, boot as *const () as usize,
        true, false, true
    );
    boot(entry, fdt_addr, unsafe { &mut BUDDY } as *mut Buddy as usize);
}

#[no_mangle]
#[naked]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "la sp, {}
         li t0, 0x100000
         add sp, sp, t0
         tail {}", sym STACK, sym entry,
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
