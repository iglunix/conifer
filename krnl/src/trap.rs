#[naked]
#[repr(align(4))]
pub unsafe extern "C" fn k_trap_start() {
    core::arch::asm!(
        "addi sp, sp, -16
         csrr ra, sepc
         sd ra, 8(sp)
         sd fp, 0(sp)
         addi fp, sp, 16
         call {}", sym trap_entry, options(noreturn));
}

#[naked]
#[repr(align(4))]
pub unsafe extern "C" fn u_trap_start() {
    core::arch::asm!(
        "csrrw t6, stvec, t6
         la t6, {}
         csrrw t6, stvec, t6

         csrrw sp, sscratch, sp
         la sp, {}
         ld sp, 0(sp)
         addi sp, sp, -256

         sd x0, 0(sp)
         sd x1, 8(sp)
         sd x2, 16(sp)
         sd x3, 24(sp)
         sd x4, 32(sp)
         sd x5, 40(sp)
         sd x6, 48(sp)
         sd x7, 56(sp)
         sd x8, 64(sp)
         sd x9, 72(sp)
         sd x10, 80(sp)
         sd x11, 88(sp)
         sd x12, 96(sp)
         sd x13, 104(sp)
         sd x14, 112(sp)
         sd x15, 120(sp)
         sd x16, 128(sp)
         sd x17, 136(sp)
         sd x18, 144(sp)
         sd x19, 152(sp)
         sd x20, 160(sp)
         sd x21, 168(sp)
         sd x22, 176(sp)
         sd x23, 184(sp)
         sd x24, 192(sp)
         sd x25, 200(sp)
         sd x26, 208(sp)
         sd x27, 216(sp)
         sd x28, 224(sp)
         sd x29, 232(sp)
         sd x30, 240(sp)
         sd x31, 248(sp)

         mv a0, sp

         // addi sp, sp, -16
         // csrr t6, sepc
         // sd t6, 8(sp)
         // sd x0, 0(sp)
         // addi fp, sp, 16

         call {}

         // addi sp, sp, 16

         ld x1, 8(sp)
         ld x2, 16(sp)
         ld x3, 24(sp)
         ld x4, 32(sp)
         ld x5, 40(sp)
         ld x6, 48(sp)
         ld x7, 56(sp)
         ld x8, 64(sp)
         ld x9, 72(sp)
         ld x10, 80(sp)
         ld x11, 88(sp)
         ld x12, 96(sp)
         ld x13, 104(sp)
         ld x14, 112(sp)
         ld x15, 120(sp)
         ld x16, 128(sp)
         ld x17, 136(sp)
         ld x18, 144(sp)
         ld x19, 152(sp)
         ld x20, 160(sp)
         ld x21, 168(sp)
         ld x22, 176(sp)
         ld x23, 184(sp)
         ld x24, 192(sp)
         ld x25, 200(sp)
         ld x26, 208(sp)
         ld x27, 216(sp)
         ld x28, 224(sp)
         ld x29, 232(sp)
         ld x30, 240(sp)
         ld x31, 248(sp)

         addi sp, sp, 256
         csrrw sp, sscratch, sp


         csrrw t6, stvec, t6
         la t6, {}
         csrrw t6, stvec, t6

         sret", sym k_trap_start, sym KRNL_SP, sym trap_entry, sym u_trap_start, options(noreturn));
}

#[repr(C)]
#[derive(Debug)]
struct Frame {
    fp: *const Frame,
    ra: usize,
}

pub static mut KRNL_ELF_ADDR: usize = 0;
pub static mut KRNL_SP: usize = 0xffffffc00001ff00;
pub static mut FDT_ADDR: usize = 0;

unsafe fn find_symbol(ra: usize) -> &'static str {
    let krnl_elf = elf::Elf::new(KRNL_ELF_ADDR as *const u8);
    let symtab = krnl_elf
        .shdrs
        .iter()
        .find_map(|shdr| {
            if matches!(shdr.ty, elf::ShType::SymTab) {
                Some(core::slice::from_raw_parts(
                    (KRNL_ELF_ADDR as *const u8).offset(shdr.offset as isize)
                        as *const elf::SymTabEnt,
                    shdr.size / core::mem::size_of::<elf::SymTabEnt>(),
                ))
            } else {
                None
            }
        })
        .unwrap();

    let strtab = krnl_elf
        .shdrs
        .iter()
        .rev()
        .find_map(|shdr| {
            if matches!(shdr.ty, elf::ShType::StrTab) {
                Some(core::slice::from_raw_parts(
                    (KRNL_ELF_ADDR as *const u8).offset(shdr.offset as isize),
                    shdr.size,
                ))
            } else {
                None
            }
        })
        .unwrap();

    let mut distance = 0xffffffffffffffff;
    let mut ret = None;
    for sym in symtab {
        if sym.name > 0 && sym.value > 0xffffffc000000000 && strtab[sym.name as usize] != b'.' {
            if (ra - sym.value) < distance {
                ret = Some(sym);
                distance = ra - sym.value;
            }
        }
    }
    let ret = ret.unwrap();

    let mut len = 0;
    while strtab[ret.name as usize + len] != b'\0' {
        len += 1
    }
    core::str::from_utf8(&strtab[(ret.name as usize)..(ret.name as usize + len)]).unwrap()
}

#[repr(packed)]
#[derive(Debug, Clone, Copy)]
struct DebugLineHdr {
    length: u32,
    version: u16,
    hdr_length: u32,
    min_instr_length: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    op_base: u8,
    op_lengths: [u8; 12],
}

unsafe fn _addr2line(ra: usize) -> &'static str {
    let krnl_elf = elf::Elf::new(KRNL_ELF_ADDR as *const u8);
    let shstrtab = krnl_elf
        .shdrs
        .iter()
        .find_map(|shdr| {
            if matches!(shdr.ty, elf::ShType::StrTab) {
                Some(core::slice::from_raw_parts(
                    (KRNL_ELF_ADDR as *const u8).offset(shdr.offset as isize),
                    shdr.size,
                ))
            } else {
                None
            }
        })
        .unwrap();

    let debug_line = krnl_elf
        .shdrs
        .iter()
        .find_map(|shdr| {
            if matches!(shdr.ty, elf::ShType::ProgBits) {
                let mut len = 0;
                while shstrtab[shdr.name as usize + len] != b'\0' {
                    len += 1
                }

                let name = &shstrtab[(shdr.name as usize)..(shdr.name as usize + len)];
                let name = core::str::from_utf8(name).unwrap();
                if name == ".debug_line" {
                    eprintln!("debug_line_offset: {:x}", shdr.offset);
                    Some(core::slice::from_raw_parts(
                        (KRNL_ELF_ADDR as *const u8).offset(shdr.offset as isize),
                        shdr.size,
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap();
    eprintln!(
        "debug_line: {:#x?}",
        &*(debug_line.as_ptr() as *const DebugLineHdr)
    );
    ""
}

impl Frame {
    pub unsafe fn unwind(&self, idx: usize) {
        let krnl_elf = elf::Elf::new(KRNL_ELF_ADDR as *const u8);
        if self.fp as usize > 0xffffffc00001ff00 {
            let sym = find_symbol(self.ra);
            let sym = rustc_demangle::demangle(sym);
            eprintln!("{:>4}: {}", idx, sym);
            eprintln!("             at {:x}", self.ra);
            (*self.fp.offset(-1)).unwind(idx + 1)
        }
    }
}

#[repr(usize)]
#[derive(Debug)]
enum Cause {
    InstAlign = 0,
    InstAccess = 1,
    IllegalInst = 2,

    Break = 3,

    LoadAlign = 4,
    LoadAccess = 5,

    StoreAlign = 6,
    StoreAccess = 7,

    UCall = 8,
    SCall = 9,

    InstPage = 12,
    LoadPage = 13,
    StorePage = 15,

    SoftInt = (1 << 63) | 1,
    TimerInt = (1 << 63) | 5,
    ExtInt = (1 << 63) | 9,
}

unsafe extern "C" fn trap_entry(regs: &mut [usize; 32]) {
    let stval;
    let scause: usize;
    let sstatus: usize;
    let sepc: usize;
    core::arch::asm!(
        "csrr {}, stval
         csrr {}, scause
         csrr {}, sstatus
         csrr {}, sepc", out(reg) stval, out(reg) scause, out(reg) sstatus, out(reg) sepc);
    trap(
        stval,
        sepc,
        core::mem::transmute::<usize, Cause>(scause),
        sstatus,
        regs,
    );
    core::arch::asm!("csrw sepc, {}", in(reg) sepc + 4);
}

fn trap(stval: usize, sepc: usize, cause: Cause, sstatus: usize, regs: &mut [usize; 32]) {
    let s_mode = (sstatus & (1 << 8)) > 0;
    if s_mode {
        unsafe { core::arch::asm!("wfi") };
    }
    match cause {
        Cause::InstAlign
        | Cause::InstAccess
        | Cause::IllegalInst
        | Cause::LoadAlign
        | Cause::LoadAccess
        | Cause::StoreAlign
        | Cause::StoreAccess
        | Cause::InstPage
        | Cause::LoadPage
        | Cause::StorePage => {
            panic!(
                "trap s_mode: {}: {:?}:{:x} at {:x}: ret: {:x}",
                s_mode, cause, stval, sepc, regs[1]
            );
        }

        Cause::UCall => {
            crate::sys::syscall(regs);
        }

        Cause::Break => todo!(),
        _ => todo!(),
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    eprintln!("{}", info);
    let pc;
    let fp;
    unsafe {
        let sstatus: usize;
        core::arch::asm!(
            "auipc {}, 0
             csrr {}, sstatus
             mv {}, fp", out(reg) pc, out(reg) sstatus, out(reg) fp);
        // only stack unwind in smode faults
        // if (sstatus & (1 << 8)) > 0 {
        if true {
            let fp = Frame { fp, ra: pc };
            fp.unwind(0)
        }
        loop {
            core::arch::asm!("wfi");
        }
    }
}
