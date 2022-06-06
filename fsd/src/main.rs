// mod sys {
//     // TODO: accept process state rather than simple args
//     extern "C" fn write(fd: usize, buf: *const u8, len: usize) {
//         match fd {
//             1 => core::arch::asm!("ecall", in("a0") buf, in("a1") len, in("a7") 65536),
//             _ => eprintln!("Warning! unimplemented")
//         }
//     }
// }


fn main() {
    eprintln!("Starting FSD");

    // // Replace the write syscall defined in the kernel with a new one here
    // core::arch::asm!("ecall", in("a0") 64, in("a1") sys::write as *const fn());
}
