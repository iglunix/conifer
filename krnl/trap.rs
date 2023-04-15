pub extern "C" fn init() {
    unsafe {
        core::arch::asm!("la t1, {}
              csrw stvec, t1
              csrw sie, {}
              csrsi sstatus, 2",
              sym trap_start, in(reg) (1 << 9) | (1 << 5) | (1 << 1));
    }
    eprintln!("Setup vector");
}

static sp: usize = 0xfffffffffffffff0;
#[naked]
#[repr(align(4))]
unsafe extern "C" fn trap_start() {
    core::arch::asm!(
        concat!(
            /*
            // start by checking if we are coming from user mode
            "csrrw sp, sscratch, sp\n",
            "csrrs sp, sstatus, x0\n",
            "andi sp, sp, 1 << 8\n",
            "j 1f\n",
            "beq sp, x0, 1f\n",
            // if we are coming from user mode. switch stacks
            "la sp, {}\n",
            "ld sp, 0(sp)\n",
            "j 2f\n",
            "1:\n",
            // if we are coming from s mode, reload the stack from scratch
            "csrrs sp, sscratch, x0\n",
            "2:\n",
            */
            "addi sp, sp, -256\n",
            "sd x0, 0(sp)\n", // 0(sp) is pc
            "sd x1, 8(sp)\n",
            "sd x2, 16(sp)\n",
            "sd x3, 24(sp)\n",
            "sd x4, 32(sp)\n",
            "sd x5, 40(sp)\n",
            "sd x6, 48(sp)\n",
            "sd x7, 56(sp)\n",
            "sd x8, 64(sp)\n",
            "sd x9, 72(sp)\n",
            "sd x10, 80(sp)\n",
            "sd x11, 88(sp)\n",
            "sd x12, 96(sp)\n",
            "sd x13, 104(sp)\n",
            "sd x14, 112(sp)\n",
            "sd x15, 120(sp)\n",
            "sd x16, 128(sp)\n",
            "sd x17, 136(sp)\n",
            "sd x18, 144(sp)\n",
            "sd x19, 152(sp)\n",
            "sd x20, 160(sp)\n",
            "sd x21, 168(sp)\n",
            "sd x22, 176(sp)\n",
            "sd x23, 184(sp)\n",
            "sd x24, 192(sp)\n",
            "sd x25, 200(sp)\n",
            "sd x26, 208(sp)\n",
            "sd x27, 216(sp)\n",
            "sd x28, 224(sp)\n",
            "sd x29, 232(sp)\n",
            "sd x30, 240(sp)\n",
            "sd x31, 248(sp)\n",
            "mv a0, sp\n",
            "call {}\n",
            // "ld x0, 0(sp)\n",
            "ld x1, 8(sp)\n",
            "ld x3, 24(sp)\n",
            "ld x4, 32(sp)\n",
            "ld x5, 40(sp)\n",
            "ld x6, 48(sp)\n",
            "ld x7, 56(sp)\n",
            "ld x8, 64(sp)\n",
            "ld x9, 72(sp)\n",
            "ld x10, 80(sp)\n",
            "ld x11, 88(sp)\n",
            "ld x12, 96(sp)\n",
            "ld x13, 104(sp)\n",
            "ld x14, 112(sp)\n",
            "ld x15, 120(sp)\n",
            "ld x16, 128(sp)\n",
            "ld x17, 136(sp)\n",
            "ld x18, 144(sp)\n",
            "ld x19, 152(sp)\n",
            "ld x20, 160(sp)\n",
            "ld x21, 168(sp)\n",
            "ld x22, 176(sp)\n",
            "ld x23, 184(sp)\n",
            "ld x24, 192(sp)\n",
            "ld x25, 200(sp)\n",
            "ld x26, 208(sp)\n",
            "ld x27, 216(sp)\n",
            "ld x28, 224(sp)\n",
            "ld x29, 232(sp)\n",
            "ld x30, 240(sp)\n",
            "ld x31, 248(sp)\n",
            "ld x2, 16(sp)\n", // load stack pointer last so we load all the correct register state that we just switched in
            "addi sp, sp, 256\n",
            // restore the stack pointer and sret
            //"csrrs sp, sscratch, x0\n",
            "sret"
        ), /* sym sp, */ sym trap_entry, options(noreturn)
    );
}

#[non_exhaustive]
#[repr(usize)]
enum Interrupt {
    Software = 1,
    Timer = 5,
    External = 9,
}

fn get_time() -> u64 {
    unsafe {
        let ret;
        core::arch::asm!("csrrs {}, time, x0", out(reg) ret);
        ret
    }
}

fn set_time(t: u64) {
    unsafe {
        core::arch::asm!(
            "   li a6, 0x0
                li a7, 0x0
                ecall
                 ", in("a0") t, out("a6") _, out("a7") _);
    }
}

pub unsafe fn timer() {
    set_time(get_time() /* + 10_000_000 */ + 10_000);
}

pub fn disable_timer() {}

pub fn eanble_timer() {}

extern "C" fn trap_entry(ctx: &mut crate::Context) {
    unsafe {
        let scause: usize;
        let sepc: usize;
        let stval: usize;
        core::arch::asm!("csrrs {}, scause, x0", out(reg) scause);
        core::arch::asm!("csrrs {}, sepc, x0", out(reg) sepc);
        core::arch::asm!("csrrs {}, stval, x0", out(reg) stval);

        if scause > (1 << 63) {
            let int = scause & !(1 << 63);
            let npc = match int {
                5 => {
                    let cur = crate::CUR_TASK.0;
                    let next = cur + 1;
                    let next = next % 2;
                    let curctx = &mut crate::TASK_CTX[cur];
                    let newctx = &mut crate::TASK_CTX[next];
                    ctx.pc = sepc;
                    core::mem::replace(curctx, ctx.clone());
                    core::mem::replace(ctx, newctx.clone());
                    crate::CUR_TASK = crate::Task(next);
                    timer();
                    ctx.pc
                }
                _ => {
                    panic!("Unimplemented interrupt")
                }
            };
            core::arch::asm!("csrw sepc, {}", in(reg) npc);
        } else {
            panic!("{}", scause);
        }
    }
}
