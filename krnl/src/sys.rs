use alloc::vec::Vec;

#[repr(C)]
struct IoVec {
    base: *const u8,
    len: usize,
}

pub fn syscall(regs: &mut [usize; 32]) {
    let n = regs[17];
    if false {
        eprintln!("DEBUG: call: {}", n);
    }
    let args = &mut regs[10..17];

    match n {
        64 => {
            let buf_addr = crate::mmu::virt_to_phys(crate::mmu::Table::root(), args[1]).unwrap()
                + crate::KMEM_OFFSET;
            print!(
                "{}",
                core::str::from_utf8(unsafe {
                    core::slice::from_raw_parts(buf_addr as *const u8, args[2])
                })
                .unwrap()
            );
            args[0] = args[2];
        }
        66 => {
            let vecs = (crate::mmu::virt_to_phys(crate::mmu::Table::root(), args[1]).unwrap()
                + crate::KMEM_OFFSET) as *const IoVec;
            let vecs = unsafe { core::slice::from_raw_parts(vecs, args[2]) };
            let mut written = 0;
            for vec in vecs {
                if !vec.base.is_null() {
                    let buf_addr =
                        crate::mmu::virt_to_phys(crate::mmu::Table::root(), vec.base as usize)
                            .unwrap()
                            + crate::KMEM_OFFSET;
                    print!(
                        "{}",
                        core::str::from_utf8(unsafe {
                            core::slice::from_raw_parts(buf_addr as *const u8, vec.len)
                        })
                        .unwrap()
                    );
                    written += vec.len;
                }
            }
            args[0] = written;
        }

        93 => {
            eprintln!("exit: {}", args[0]);
            panic!("exit: {}", args[0]);
        }

        94 => {
            eprintln!("exit_group: {}", args[0]);
            panic!("exit: {}", args[0]);
        }

        96 => {
            eprintln!("TODO: set_tid_address");
            args[0] = 1;
        }

        160 => {
            eprintln!("uname");
            // uname
            #[repr(C)]
            struct UtsName {
                sysname: [u8; 65],
                nodename: [u8; 65],
                release: [u8; 65],
                version: [u8; 65],
                machine: [u8; 65],
                _domain: [u8; 65],
            }

            let uname = args[0];
            let uname = crate::mmu::virt_to_phys(crate::mmu::Table::root(), uname).unwrap();
            let uname = uname + crate::KMEM_OFFSET;

            let uname = unsafe { &mut *(uname as *mut UtsName) };
            uname.sysname[0] = b'L';
            uname.sysname[1] = b'i';
            uname.sysname[2] = b'n';
            uname.sysname[3] = b'u';
            uname.sysname[4] = b'x';
            uname.sysname[5] = b'\0';
            uname.machine[0] = b'r';
            uname.machine[1] = b'i';
            uname.machine[2] = b's';
            uname.machine[3] = b'c';
            uname.machine[4] = b'v';
            uname.machine[5] = b'6';
            uname.machine[6] = b'4';
            uname.machine[7] = b'\0';
            uname.version[0] = b'C';
            uname.version[1] = b'o';
            uname.version[2] = b'n';
            uname.version[3] = b'i';
            uname.version[4] = b'f';
            uname.version[5] = b'e';
            uname.version[6] = b'r';
            uname.version[7] = b'\0';
            uname.release[0] = b'0';
            uname.release[1] = b'.';
            uname.release[2] = b'0';
            uname.release[3] = b'.';
            uname.release[4] = b'0';
            uname.release[5] = b'\0';
            uname.nodename[0] = b'(';
            uname.nodename[1] = b'n';
            uname.nodename[2] = b'o';
            uname.nodename[3] = b'n';
            uname.nodename[4] = b'e';
            uname.nodename[5] = b')';
            uname.nodename[6] = b'\0';
            args[0] = 0;
        }

        174 => {
            args[0] = 0;
        }

        175 => {
            args[0] = 0;
        }

        214 => {
            args[0] = crate::proc::Proc::from_pid(1).brk(args[0]);
        }

        220 => {
            eprintln!("clone: not implemented yet");
            crate::proc::Proc::from_pid(1).clone();
        }

        222 => {
            eprintln!("mmap: not implemented: {:x}", args[0]);
            println!("mmap: {:#x?}", args);
            let pages = (args[1] + 0xfff) >> 12;
            // HACK:

            if args[0] != 0 {
                let x = Vec::<u8>::with_capacity(4096);
                let xa = x.as_ptr() as usize;
                // TODO: size
                // TODO: PROT flags
                crate::proc::Proc::from_pid(1).mapk2u(
                    xa,
                    args[0],
                    pages,
                    crate::mmu::EntryFlags::User
                        | crate::mmu::EntryFlags::Read
                        | crate::mmu::EntryFlags::Write,
                );
                // TODO: memory leak
                core::mem::forget(x);
            } else {
                let x = Vec::<u8>::with_capacity(4096);
                let xa = x.as_ptr() as usize;
                eprintln!("allocated: {:x}", xa);
                let xu = crate::mmu::virt_to_phys(crate::mmu::Table::root(), xa).unwrap()
                    + crate::UMAP_OFFSET;
                crate::proc::Proc::from_pid(1).mapk2u(
                    xa,
                    xu,
                    pages,
                    crate::mmu::EntryFlags::User
                        | crate::mmu::EntryFlags::Read
                        | crate::mmu::EntryFlags::Write,
                );
                core::mem::forget(x);
                args[0] = xu;
            }
            println!("mmap returning {:x} length {}({})", args[0], pages, args[1]);
        }

        65537 => {
            let uaddr = unsafe { crate::trap::FDT_ADDR - crate::KMEM_OFFSET + crate::UMAP_OFFSET };
            let kaddr = unsafe { crate::trap::FDT_ADDR };
            crate::proc::Proc::from_pid(1).mapk2u(
                kaddr,
                uaddr,
                unsafe { (crate::FDT_SIZE + 0xfff) >> 12 },
                crate::mmu::EntryFlags::Read | crate::mmu::EntryFlags::User,
            );
            args[0] = uaddr;
        }
        // TODO: remove and replace with conifer specific mmap(MAP_PHYS)
        // MAP_PHYS combined with MAP_FIXED should probably not be supported?
        65538 => {
            eprintln!("mapping {} pages: {:x}", args[1], args[0]);
            crate::proc::Proc::from_pid(1).map2u(
                args[0],
                args[0] + crate::UMAP_OFFSET,
                args[1],
                crate::mmu::EntryFlags::Read | crate::mmu::EntryFlags::User,
            );
            args[0] += crate::UMAP_OFFSET;
            eprintln!("mapping {} pages: {:x}", args[1], args[0]);
        }
        65539 => {
            let argv = crate::mmu::virt_to_phys(crate::mmu::Table::root(), args[1]).unwrap()
                + crate::KMEM_OFFSET;
            let argv = argv as *const *const u8;
            let mut len = 0;
            while !unsafe { *argv.offset(len) }.is_null() {
                len += 1;
            }
            let argv = unsafe { core::slice::from_raw_parts(argv, len as usize + 1) };
            let s = argv[0] as usize;
            let s = crate::mmu::virt_to_phys(crate::mmu::Table::root(), s).unwrap();
            let s = (s + crate::KMEM_OFFSET) as *const u8;
            let mut len = 0;
            while unsafe { *s.offset(len as isize) } != b'\0' {
                len += 1
            }
            let s = unsafe { core::slice::from_raw_parts(s, len) };
            eprintln!("s: {:#x?}", s);
            let s = core::str::from_utf8(s).unwrap();

            eprintln!("TODO: mexecve: {:#?}: {}", argv, s);
            let elf_buf = crate::mmu::virt_to_phys(crate::mmu::Table::root(), args[0]).unwrap()
                + crate::KMEM_OFFSET;
            let elf = unsafe { elf::Elf::new(elf_buf as *const u8) };
            crate::proc::Proc::from_pid(1).load(&elf);
            crate::proc::Proc::from_pid(1).switch();
        }
        n => {
            println!("TODO: unimplemented syscall: {}", n);
        }
    }
}
