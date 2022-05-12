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
        let buf = frame.regs[10] as *const u8;
        let len = frame.regs[11];
        core::slice::from_raw_parts(buf, len).iter().for_each(|b| {
            sbi::console_putchar(*b);
        })
    }
}

/// Early write syscall. Allows printing to stdout and stderr before `fsd(4)` has started
fn write(frame: &TrapFrame) {
    unsafe {
        let fd = frame.regs[10];
        if fd == 1 || fd == 2 {
            let buf = frame.regs[11] as *const u8;
            let len = frame.regs[12];
            core::slice::from_raw_parts(buf, len).iter().for_each(|b| {
                crate::sbi::console_putchar(*b);
            })
        } else {
            crate::eprintln!("Unsupported early write to fd: {}", fd);
        }
    }
}

/// Syscall table.
#[repr(u32)]
enum Syscall {
    Write = 64
    Exit = 93,
    Brk = 214,

    // Conifer specific syscalls
    Earlycon = 0x1_0001,
}
