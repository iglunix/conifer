#[macro_export]
macro_rules! read_csr {
    ($csr: expr) => {
        unsafe {
            let r: usize;
            core::arch::asm!(concat!("csrr {}, ", $csr), out(reg) r);
            r
        }
    }
}

#[macro_export]
macro_rules! write_csr {
    ($csr: expr, $v: expr) => {
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
         j entry",
        options(noreturn)
    );
}

#[no_mangle]
extern "C" fn entry() {
    unsafe {
        let trap_addr: usize;
        core::arch::asm!("la t1, {}
              csrw stvec, t1",
              sym crate::trap::trap_start, out("t1") trap_addr);
        assert_eq!(trap_addr, read_csr!("stvec"));

        write_csr!("sie", (1 << 9) | (1 << 5) | (1 << 1));
    }

    crate::main();
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
