#[repr(align(4))]
#[naked]
pub unsafe fn trap_start() {
    core::arch::asm!("
        addi sp, sp, -256
        sd x0, 0(sp)
        sd ra, 8(sp)
        sd sp, 16(sp)
        sd gp, 24(sp)
        sd tp, 32(sp)
        sd t0, 40(sp)
        sd t1, 48(sp)
        sd t2, 56(sp)
        sd s0, 64(sp)
        sd s1, 72(sp)
        sd a0, 80(sp)
        sd a1, 88(sp)
        sd a2, 96(sp)
        sd a3, 104(sp)
        sd a4, 112(sp)
        sd a5, 120(sp)
        sd a6, 128(sp)
        sd a7, 136(sp)
        sd s2, 144(sp)
        sd s3, 152(sp)
        sd s4, 160(sp)
        sd s5, 168(sp)
        sd s6, 176(sp)
        sd s7, 184(sp)
        sd s8, 192(sp)
        sd s9, 200(sp)
        sd s10, 208(sp)
        sd s11, 216(sp)
        sd t3, 224(sp)
        sd t4, 232(sp)
        sd t5, 240(sp)
        sd t6, 248(sp)

        mv a0, sp

        call {}

        ld ra, 8(sp)
        ld sp, 16(sp)
        ld gp, 24(sp)
        ld tp, 32(sp)
        ld t0, 40(sp)
        ld t1, 48(sp)
        ld t2, 56(sp)
        ld s0, 64(sp)
        ld s1, 72(sp)
        ld a0, 80(sp)
        ld a1, 88(sp)
        ld a2, 96(sp)
        ld a3, 104(sp)
        ld a4, 112(sp)
        ld a5, 120(sp)
        ld a6, 128(sp)
        ld a7, 136(sp)
        ld s2, 144(sp)
        ld s3, 152(sp)
        ld s4, 160(sp)
        ld s5, 168(sp)
        ld s6, 176(sp)
        ld s7, 184(sp)
        ld s8, 192(sp)
        ld s9, 200(sp)
        ld s10, 208(sp)
        ld s11, 216(sp)
        ld t3, 224(sp)
        ld t4, 232(sp)
        ld t5, 240(sp)
        ld t6, 248(sp)

        addi sp, sp, 256
        sret
    ", sym trap_entry, options(noreturn));
}

#[repr(u64)]
#[derive(Debug)]
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
    StorePageFault = 15,


    Software = 1 + (1 << 63),
    Timer = 5 + (1 << 63),
    External = 9 + (1 << 63),
}

unsafe extern "C" fn trap_entry(sp: *mut u64) {
    let regs = core::slice::from_raw_parts_mut(sp, 32);
    let sepc = crate::read_csr!("sepc");
    let scause = crate::read_csr!("scause") as u64;
    let sepc = trap(regs, sepc, core::mem::transmute::<u64, Exception>(scause));
    crate::write_csr!("sepc", sepc);
}

fn trap(regs: &[u64], sepc: usize, scause: Exception) -> usize {
    match scause {
        Exception::InstructionMisaligned => panic!("misaligned instruction at 0x{:x}", sepc),
        Exception::InstructionAccess => panic!("illegal instruction access at 0x{:x}", sepc),
        Exception::IllegalInstruction => panic!("illegal instruction at 0x{:x}", sepc),
        Exception::Breakpoint => {
            crate::eprintln!("breakpoint at 0x {:x}", sepc);
            sepc + 2
        }
        Exception::LoadMisaligned => panic!("misaligned load at 0x{:x}", sepc),
        Exception::LoadAccess => panic!("illegal load access at 0x{:x}", sepc),
        Exception::StoreMisaligned => panic!("misaligned store at 0x{:x}", sepc),
        Exception::StoreAccess => panic!("illegal store access at 0x{:x}", sepc),

        _ => todo!()
    }
}
