#![no_std]
#![no_main]
#![feature(asm_sym)]
#![feature(naked_functions)]

mod fdt;
mod tar;

struct PanicPrinter();
impl core::fmt::Write for PanicPrinter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print(s);

        Ok(())
    }
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    PanicPrinter().write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprint {
    () => ();
    ($($arg:tt)*) => ($crate::print!("\x1B[91m{}\x1B[0m", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ($crate::eprint!("{}\n", format_args!($($arg)*)));
}

#[repr(C)]
#[derive(Debug)]
struct Frame {
    fp: *const Frame,
    ra: usize,
}

impl Frame {
    pub unsafe fn unwind(&self, idx: usize) {
        if self.fp as usize > 0x400000000 && self.ra < 0x400000000 {
            // let sym = find_symbol(self.ra);
            // let sym = rustc_demangle::demangle(sym);
            eprintln!("{:>4}: {:x}", idx, self.ra);
            // eprintln!("             at {:x}", self.ra);
            (*self.fp.offset(-1)).unwind(idx + 1)
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print("ERROR: init panic!\n");
    eprintln!("{}", _info);

    unsafe {
        let fp;
        let pc;
        core::arch::asm!(
            "auipc {}, 0
             mv {}, fp", out(reg) pc, out(reg) fp);
        let fp = Frame { fp, ra: pc };
        fp.unwind(0)
    }
    exit(1);
}

fn print(s: &str) {
    let len = s.as_bytes().len();
    let ptr = s.as_ptr();
    unsafe {
        core::arch::asm!("ecall", in("a0") 1, in("a1") ptr, in("a2") len, in("a7") 64);
    }
}

fn exit(code: usize) -> ! {
    unsafe { core::arch::asm!("ecall", in("a0") code, in("a7") 93, options(noreturn)) }
}

fn mpp<T>(paddr: *const T, count: usize) -> *mut T {
    eprintln!("count: {}", count);
    unsafe {
        let ret;
        core::arch::asm!("ecall", in("a7") 65538, in("a0") paddr, in("a1") count, lateout("a0") ret);
        ret
    }
}
// clone(SIGCHLD, 0)
fn clone() -> usize {
    unsafe {
        let ret;
        core::arch::asm!("ecall", in("a7") 220, in("a0") 17 /* SIGCHLD */, in("a1") 0, lateout("a0") ret);
        ret
    }
}

fn mexecve(elf: *const u8, argv: *const *const u8, envp: *const *const u8) {
    unsafe {
        core::arch::asm!("ecall", in("a7") 65539, in("a0") elf, in("a1") argv, in("a2") envp);
    }
}

#[no_mangle]
#[naked]
unsafe extern "C" fn _start() {
    core::arch::asm!(
        "mv a0, sp
         andi sp, sp, -16
         tail {}",
         sym entry, options(noreturn));
}

/// stack start
///  - argc
///  - argv[0]
///  - argv[1]
///  - argv[..]
///  - argv[argc] = NULL
///  - envp[0]
///  - envp[1]
///  - envp[..]
///  - envp[envc] = NULL
///  - auxv[0]
unsafe extern "C" fn entry(sp: *const usize) {
    let fdt = fdt::Fdt::from_addr(getfdt());
    fdt.root().dump();

    let initrd_start = u32::from_be_bytes(
        fdt.root()
            .node("chosen")
            .prop("linux,initrd-start")
            .try_into()
            .unwrap(),
    ) as *const u64;
    let initrd_end = u32::from_be_bytes(
        fdt.root()
            .node("chosen")
            .prop("linux,initrd-end")
            .try_into()
            .unwrap(),
    ) as *const u64;
    let initrd_start_virt = (mpp(
        (initrd_start as usize & !0xfff) as *const u64,
        (initrd_end as usize - (initrd_start as usize & !0xfff) + 0xfff) >> 12,
    ) as *const u8)
        .offset((initrd_start as isize) & (0xfff)) as *const u64;
    eprintln!("initrd_start: {:p}", initrd_start);
    eprintln!(
        "initrd_start: {:p}",
        (initrd_start as usize & !0xfff) as *const u64
    );
    eprintln!("initrd_start: {:p}", initrd_start_virt);
    eprintln!("initrd_end: {:p}", initrd_end);
    let initrd = unsafe {
        core::slice::from_raw_parts(
            initrd_start_virt,
            (initrd_end as usize - initrd_start as usize) >> 3,
        )
    };
    let cmdline = fdt.root().node("chosen").prop("bootargs");
    print!("cmdline: ");
    for i in cmdline {
        print!("{}", char::from_u32(*i as u32).unwrap());
    }
    println!();

    // let initrd_len = initrd_end as usize - initrd_start as usize;
    // println!("phys initrd: {:p} => {:p}: {} bytes", initrd_start, initrd_end, initrd_len);
    // let initrd_start = mpp(initrd_start).offset((initrd_start as isize) & (0xfff));
    // println!("virt initrd: {:p} => {} bytes", initrd_start, initrd_len);

    let tar = core::slice::from_raw_parts(
        initrd_start_virt as *const [u8; 512],
        (initrd_end as usize - initrd_start as usize) >> 9,
    );

    // possible names for the fsd
    // /fsd.elf
    // /fsd
    // /sbin/fsd
    println!("searching for file system daemon in archive with names:");
    println!(" - /fsd.elf");
    println!(" - /fsd");
    println!(" - /sbin/fsd");

    // TODO: do we need a tar here if fs and block drivers are included in fsd?
    let tar = tar::Tar::new(tar);
    let h = tar.find("fsd.elf");
    // let h = tar.find("toybox");
    let elf = h as *const tar::TarHeader as *const u8;
    let elf = elf.offset(0x200);
    eprintln!("uelf: {:p}", elf);

    // TODO:
    //  - load fsd.elf
    //  - clone
    //  - mexecve
    let x = clone();
    eprintln!("x: {}", x);
    let argv = [b"toybox\0" as *const u8, core::ptr::null()];
    eprintln!("argv: {:#x?}", argv);
    let argv = (&argv).as_ptr();
    mexecve(elf, argv, core::ptr::null());
    exit(0);

    // let c = *sp;
    // eprintln!("argc: {}", c);
    // let v = sp.offset(1) as *const *const u8;
    // eprintln!("argv: {:p}", v);
    // let s = *v;
    // let mut len = 0;
    // while *s.offset(len as isize) != b'\0' {
    //     len += 1;
    // }
    // let s = core::slice::from_raw_parts(s, len);
    // let s = core::str::from_utf8(s).unwrap();
    // eprintln!("argv0: {}", s);
    // let mut o = 1;
    // while *v.offset(c as isize + o) != core::ptr::null() {
    //     let p = *v.offset(c as isize + o) as *const u8;
    //     eprintln!("envp: {:p}", p);
    //     let mut len = 1;
    //     while *p.offset(len as isize) != b'\0' {
    //         len += 1;
    //     }
    //     eprintln!("p0 len: {}", len);

    //     let p = core::slice::from_raw_parts(p, len);
    //     let p = core::str::from_utf8(p).unwrap();
    //     eprintln!("envp: {}, {}", o - 1, p);
    //     o += 1;
    // }
    // let auxv_base = v.offset(c as isize + o + 1) as *const usize;
    // eprintln!("auxv: {:p}", auxv_base);
    // let mut o = 0;
    // while *auxv_base.offset(o) != 0 {
    //     eprintln!(
    //         "auxv: {}: {:x}:{:x}",
    //         o,
    //         *auxv_base.offset(o),
    //         *auxv_base.offset(o + 1)
    //     );
    //     o += 2;
    // }

    // for _ in 0..c {
    //     print("Hello, World!\n");
    // }

    // eprintln!("fdt: {}", getfdt());
}

fn getfdt() -> usize {
    unsafe {
        let ret;
        core::arch::asm!("ecall", in("a7") 65537, out("a0") ret);
        ret
    }
}
