use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct Proc {
    /// Mapped pages: (kaddr, vaddr, size)
    mmap: Vec<(Vec<u8>, usize, crate::mmu::Entry)>,
    entry: *const fn(),
    stack_idx: usize,
    pid: usize,
    brk: usize,
    frame: [usize; 32],
}

const STACK_SZ: usize = 4;

static mut ACTIVE_PID: usize = 0;
static mut PID_COUNT: AtomicUsize = AtomicUsize::new(0);
static mut PROCS: Vec<Proc> = Vec::new();

impl Proc {
    pub fn dump_all() {
        unsafe {
            eprintln!("{:#x?}", PROCS);
        }
    }
    
    pub fn from_pid(pid: usize) -> &'static mut Self {
        eprintln!("from pid: {}", pid);
        unsafe { &mut PROCS[pid - 1] }
    }

    pub fn clone(&self) -> &'static mut Self {
        let mmap = self.mmap.clone();
        unsafe {
            *PID_COUNT.get_mut() += 1;
        }
        let pid = unsafe { PID_COUNT.load(Ordering::Relaxed) };
        let ret = Self {
            mmap,
            entry: self.entry,
            stack_idx: 0,
            pid,
            brk: self.brk,
            frame: [0; 32],
        };
        unsafe {
            PROCS.push(ret);
            &mut PROCS[PROCS.len() - 1]
        }
    }

    pub fn new() -> &'static mut Self {
        let mut mmap = Vec::with_capacity(4);
        let mut stack = vec![0; STACK_SZ * 0x1000];
        stack[STACK_SZ * 0x1000 - 128] = 1;
        mmap.push((
            stack,
            0x4_0000_0000,
            crate::mmu::EntryFlags::Read
                | crate::mmu::EntryFlags::Write
                | crate::mmu::EntryFlags::User,
        ));
        unsafe {
            *PID_COUNT.get_mut() += 1;
        }
        let pid = unsafe { PID_COUNT.load(Ordering::Relaxed) };
        let ret = Self {
            mmap,
            entry: core::ptr::null(),
            stack_idx: 0,
            pid,
            brk: 0,
            frame: [0; 32],
        };
        unsafe {
            PROCS.push(ret);
            &mut PROCS[PROCS.len() - 1]
        }
    }

    pub fn load(&mut self, elf: &elf::Elf) {
        while self.mmap.len() > 1 {
            self.mmap.pop();
        }
        {
            let stack = &mut self.mmap[0].0;
            // argc
            stack[STACK_SZ * 0x1000 - 128] = 2;

            // argv0
            stack[STACK_SZ * 0x1000 - 120] = 0xf7;
            stack[STACK_SZ * 0x1000 - 119] = 0x3f;
            stack[STACK_SZ * 0x1000 - 118] = 0;
            stack[STACK_SZ * 0x1000 - 117] = 0;
            stack[STACK_SZ * 0x1000 - 116] = 4;
            stack[STACK_SZ * 0x1000 - 115] = 0;
            stack[STACK_SZ * 0x1000 - 114] = 0;
            stack[STACK_SZ * 0x1000 - 113] = 0;

            // argv1
            stack[STACK_SZ * 0x1000 - 112] = 0xfd;
            stack[STACK_SZ * 0x1000 - 111] = 0x3f;
            stack[STACK_SZ * 0x1000 - 100] = 0;
            stack[STACK_SZ * 0x1000 - 109] = 0;
            stack[STACK_SZ * 0x1000 - 108] = 4;
            stack[STACK_SZ * 0x1000 - 107] = 0;
            stack[STACK_SZ * 0x1000 - 106] = 0;
            stack[STACK_SZ * 0x1000 - 105] = 0;

            // argv null
            // -104 to -97
            // envp null
            // -96 to -89

            // AT_PAGESZ
            stack[STACK_SZ * 0x1000 - 88] = 6;

            stack[STACK_SZ * 0x1000 - 79] = 0x10;

            // argv strings
            stack[STACK_SZ * 0x1000 - 9] = b'u';
            stack[STACK_SZ * 0x1000 - 8] = b'n';
            stack[STACK_SZ * 0x1000 - 7] = b'a';
            stack[STACK_SZ * 0x1000 - 6] = b'm';
            stack[STACK_SZ * 0x1000 - 5] = b'e';
            stack[STACK_SZ * 0x1000 - 4] = b'\0';
            stack[STACK_SZ * 0x1000 - 3] = b'-';
            stack[STACK_SZ * 0x1000 - 2] = b'a';
            stack[STACK_SZ * 0x1000 - 1] = b'\0';
        }

        for phdr in elf.phdrs {
            if matches!(phdr.ty, elf::PhType::Load) {
                let mut flags = crate::mmu::Entry(0);
                if (phdr.pflags & 1) > 0 {
                    flags = flags | crate::mmu::EntryFlags::Exec | crate::mmu::EntryFlags::User;
                }
                if (phdr.pflags & 2) > 0 {
                    flags = flags | crate::mmu::EntryFlags::Write | crate::mmu::EntryFlags::User;
                }
                if (phdr.pflags & 4) > 0 {
                    flags = flags | crate::mmu::EntryFlags::Read | crate::mmu::EntryFlags::User;
                }
                let mut mem = vec![0; phdr.memsz + (phdr.vaddr & 0xfff)];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (elf.head as *const elf::ElfHeader as *const u8)
                            .offset(phdr.offset as isize),
                        mem.as_mut_ptr().offset((phdr.vaddr & 0xfff) as isize),
                        phdr.filesz,
                    );
                }
                let pbrk = (phdr.vaddr + phdr.memsz + 0xfff) & !0xfff;
                eprintln!("pbrk: {:x}", pbrk);
                if pbrk > self.brk {
                    self.brk = pbrk;
                }
                eprintln!("phdr: {:x}", phdr.vaddr);
                self.mmap.push((mem, phdr.vaddr, flags))
            }
        }
        self.entry = elf.head.entry as *const fn();
        // self.brk += 0x1000;
        // eprintln!("head: {:#x?}", elf.head);
        eprintln!("entry: {:p}", self.entry);
    }

    pub fn brk(&mut self, ptr: usize) -> usize {
        // println!("brk {:x}->{:x}", self.brk, ptr);
        if ptr != 0 {
            assert_eq!(ptr & 0xfff, 0);
            let inc = ptr - self.brk;
            let b = Vec::<u8>::with_capacity(inc);
            self.mapk2u(
                b.as_ptr() as usize,
                self.brk,
                inc >> 12,
                crate::mmu::EntryFlags::Read
                    | crate::mmu::EntryFlags::Write
                    | crate::mmu::EntryFlags::User,
            );
            core::mem::forget(b);
            self.brk = ptr;
            self.brk
        } else {
            self.brk
        }
    }

    pub fn dump(&self) {
        for m in &self.mmap {
            eprintln!("mapped {:p} to {:p}", &m.0, m.1 as *const u8);
        }
    }

    pub fn switch(&mut self) -> ! {
        crate::mmu::Table::root().clear_user_ptes();
        for m in &self.mmap {
            crate::mmu::mapk2u(m.0.as_ptr() as usize, m.1, (m.0.len() + 0xfff) >> 12, m.2);
        }
        crate::mmu::fence();
        eprintln!("setting entry to: {:p}", self.entry);
        let stack = self.mmap[self.stack_idx].1 as *const u8;
        eprintln!("setting stack to: {:p}", stack);
        unsafe {
            ACTIVE_PID = self.pid;
            // can we forget the whole stack?
            let kstackp = &mut crate::trap::KRNL_SP as *mut usize;
            // let mut kstackp: usize = 0;
            // let kstackp = &mut kstackp as *mut usize;
            eprintln!("saving kstackp to: {:p}", kstackp);
            core::arch::asm!(
                "csrw sepc, {}
                 csrw stvec, {}
                 sd sp, 0({})
                 mv sp, {}
                 sret", in(reg) self.entry, in(reg) crate::trap::u_trap_start, in(reg) kstackp, in(reg) stack.offset(STACK_SZ as isize * 0x1000 - 128), options(noreturn))
        }
    }

    pub fn mapk2u(&mut self, kaddr: usize, uaddr: usize, count: usize, flags: crate::mmu::Entry) {
        crate::mmu::mapk2u(kaddr, uaddr, count, flags);
        // TODO: save this mapping
    }

    pub fn map2u(&mut self, paddr: usize, uaddr: usize, count: usize, flags: crate::mmu::Entry) {
        crate::mmu::map2u(paddr, uaddr, count, flags);
        // TODO: save this mapping
    }
}
