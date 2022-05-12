#[repr(align(4096))]
#[naked]
#[link_section = ".trap"]
pub unsafe extern "C" fn trap_start() {
    core::arch::asm!("
        csrrw t6, sscratch, t6
        sd x0, 0(t6)
        sd ra, 8(t6)
        sd sp, 16(t6)
        sd gp, 24(t6)
        sd tp, 32(t6)
        sd t0, 40(t6)
        sd t1, 48(t6)
        sd t2, 56(t6)
        sd s0, 64(t6)
        sd s1, 72(t6)
        sd a0, 80(t6)
        sd a1, 88(t6)
        sd a2, 96(t6)
        sd a3, 104(t6)
        sd a4, 112(t6)
        sd a5, 120(t6)
        sd a6, 128(t6)
        sd a7, 136(t6)
        sd s2, 144(t6)
        sd s3, 152(t6)
        sd s4, 160(t6)
        sd s5, 168(t6)
        sd s6, 176(t6)
        sd s7, 184(t6)
        sd s8, 192(t6)
        sd s9, 200(t6)
        sd s10, 208(t6)
        sd s11, 216(t6)
        sd t3, 224(t6)
        sd t4, 232(t6)
        sd t5, 240(t6)
        csrrw t5, sscratch, t5
        sd t5, 248(t6)
        csrrw t5, sscratch, t5

        # load kernel stack pointer
        ld sp, 264(t6)

        # load kernel satp
        ld a1, 272(t6)
        csrrw a1, satp, a1
        sd a1, 272(t6)
        sfence.vma
            
        mv a0, t6
        ld t1, 256(t6)
        auipc ra, 0
        addi ra, ra, 8
        jalr t1
        la t1, {}
        
        # load user satp
        ld a1, 272(t6)
        csrrw a1, satp, a1
        sd a1, 272(t6)
        sfence.vma
            
        ld ra, 8(t6)
        ld sp, 16(t6)
        ld gp, 24(t6)
        ld tp, 32(t6)
        ld t0, 40(t6)
        ld t1, 48(t6)
        ld t2, 56(t6)
        ld s0, 64(t6)
        ld s1, 72(t6)
        ld a0, 80(t6)
        ld a1, 88(t6)
        ld a2, 96(t6)
        ld a3, 104(t6)
        ld a4, 112(t6)
        ld a5, 120(t6)
        ld a6, 128(t6)
        ld a7, 136(t6)
        ld s2, 144(t6)
        ld s3, 152(t6)
        ld s4, 160(t6)
        ld s5, 168(t6)
        ld s6, 176(t6)
        ld s7, 184(t6)
        ld s8, 192(t6)
        ld s9, 200(t6)
        ld s10, 208(t6)
        ld s11, 216(t6)
        ld t3, 224(t6)
        ld t4, 232(t6)
        ld t5, 240(t6)
        csrrw t5, sscratch, t5
        ld t5, 248(t6)
        csrrw t5, sscratch, t5

        csrrw t6, sscratch, t6

        sret
    ", sym trap_entry, options(noreturn));
}

#[repr(usize)]
#[derive(Debug)]
#[allow(unused)]
enum Exception {
    InstructionMisaligned = 0,
    InstructionAccess = 1,
    IllegalInstruction = 2,
    Breakpoint = 3,
    LoadMisaligned = 4,
    LoadAccess = 5,
    StoreMisaligned = 6,
    StoreAccess = 7,
    EcallU = 8,
    EcallS = 9,
    InstructionPageFault = 12,
    LoadPageFault = 13,
    StorePageFault = 15,

    Software = 1 + (1 << 63),
    Timer = 5 + (1 << 63),
    External = 9 + (1 << 63),
}

#[repr(align(4))]
pub unsafe extern "C" fn trap_entry(s: *mut Scratch) {
    let s = &mut *s;
    let sepc = crate::read_csr!("sepc");
    let scause = crate::read_csr!("scause");
    let sepc = trap(s, sepc, core::mem::transmute::<usize, Exception>(scause));
    crate::write_csr!("sepc", sepc);
}

fn trap(s: &mut Scratch, sepc: usize, scause: Exception) -> usize {
    let regs = s.regs;
    let sstatus = crate::read_csr!("sstatus");
    let s_mode = (sstatus & (1 << 8)) > 0;
    match scause {
        Exception::InstructionMisaligned => panic!("misaligned instruction at 0x{:x}", sepc),
        Exception::InstructionAccess => panic!("illegal instruction access at 0x{:x}", sepc),
        Exception::IllegalInstruction => panic!("illegal instruction at 0x{:x}", sepc),
        Exception::Breakpoint => {
            crate::eprintln!("breakpoint at 0x {:x}", sepc);
            crate::eprintln!("registers: {:#?}", regs);
            sepc + 2
        }
        Exception::LoadMisaligned => panic!("misaligned load at 0x{:x}", sepc),
        Exception::LoadAccess => panic!("illegal load access at 0x{:x}", sepc),
        Exception::StoreMisaligned => panic!("misaligned store at 0x{:x}", sepc),
        Exception::StoreAccess => panic!("illegal store access at 0x{:x}", sepc),

        Exception::EcallU => {
            let n = regs[17]; // a7

            match n {
                0 => {
                    crate::sbi::console_putchar(regs[10] as u8);
                }
                64 => unsafe {
                    let satp = &*(((s.satp & 0xfffffffffff) << 12) as *const crate::mmu::Table);
                    let buf_addr = crate::mmu::virt_to_phys(satp, regs[11]).unwrap();
                    core::slice::from_raw_parts(buf_addr as *const u8, regs[12]).iter().for_each(|b| {
                        crate::sbi::console_putchar(*b);
                    })
                }
                93 => panic!("syscall exit"),
                n => crate::eprintln!("WARNING: unimplemented syscall: {}", n),
            }
            sepc + 4
        }

        Exception::InstructionPageFault => panic!("instruction page fault at 0x{:x}", sepc),
        Exception::LoadPageFault => panic!("load page fault at 0x{:x}: 0x{:x}", sepc, crate::read_csr!("stval")),
        Exception::StorePageFault => panic!("store page fault at 0x{:x}: 0x{:x}", sepc, crate::read_csr!("stval")),
        Exception::Timer => {
            crate:: eprintln!("timer");
            crate::sbi::set_timer((crate::read_csr!("time") as u64) + 10000000);
            sepc
        }
        _ => todo!("{:#?}", scause as usize),
    }
}


#[repr(align(4096))]
#[link_section = ".trap"]
pub unsafe extern "C" fn k2u(entry: *const fn(), sp: *const u8, tbl: *const crate::mmu::Table) {
    core::arch::asm!("mv t1, sp", out("t1") scratch.stack_ptr);
    core::arch::asm!(
        "csrw sepc, t1
         mv sp, t2
         csrw satp, t3
         sfence.vma
         sret", in("t1") entry, in("t2") sp, in("t3") ((tbl as usize) >> 12 | 8 << 60), options(noreturn));
}

#[link_section = ".scratch"]
pub static mut scratch: Scratch = Scratch {
    regs: [0; 32],
    trap_entry: 0,
    stack_ptr: 0,
    satp: 0
};

#[repr(C)]
pub struct Scratch {
    pub regs: [usize; 32],
    pub trap_entry: usize,
    pub stack_ptr: usize,
    pub satp: usize,
}

