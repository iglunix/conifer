use crate::sbi;

struct TrapFrame {
    regs: [usize; 32],
}

/// syscall table
static mut SYSCALLS: [usize; 1] = [0];

/// register syscall.
/// maps the syscall number `n` to the function pointer `f` of the current
/// process.
fn register(_: &TrapFrame) {}

/// early console syscall
/// writes `len` bytes from `buf` to the console
fn earlycon(frame: &TrapFrame) {
    unsafe {
        let buf = frame.regs[0] as *const u8;
        let len = frame.regs[1];
        core::slice::from_raw_parts(buf, len).iter().for_each(|b| {
            sbi::console_putchar(*b);
        })
    }
}

