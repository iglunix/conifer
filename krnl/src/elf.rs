#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
#[allow(unused)]
enum ElfMagic {
    Elf = 0x464c457f,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
enum ElfClass {
    X32 = 1,
    X64 = 2,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
enum ElfEndianness {
    Little = 1,
    Big = 2,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
enum ElfAbi {
    SysV = 0,
    HpUx = 1,
    NetBSD = 2,
    Linux = 3,
    Hurd = 4,
    Solaris = 6,
    AIX = 7,
    IRIX = 8,
    FreeBSD = 9,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
enum ElfType {
    None = 0,
    Rel = 1,
    Exec = 2,
    Dyn = 3,
    Core = 4,
}

#[repr(u16)]
#[derive(Debug)]
#[allow(unused)]
enum ElfArch {
    None = 0,
    RiscV = 0xf3,
}

#[repr(C)]
#[derive(Debug)]
struct ElfHeader {
    magic: ElfMagic,
    class: ElfClass,
    endianness: ElfEndianness,
    version: u8,
    abi: ElfAbi,
    abi_ver: u8,
    pad: [u8; 7],
    ty: ElfType,
    arch: ElfArch,
    e_ver: u32,
    entry: usize,
    phoff: usize,
    shoff: usize,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[repr(u32)]
#[derive(Debug)]
#[allow(unused)]
pub enum PhType {
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    _Shlib = 5,
    Table = 6,
    _GnuStack = 0x51,
}

#[repr(C)]
#[derive(Debug)]
pub struct ProgramHeader {
    ty: PhType,
    pflags: u32,
    offset: usize,
    vaddr: usize,
    paddr: usize,
    filesz: usize,
    memsz: usize,
    align: usize,
}

#[derive(Debug)]
pub struct Elf<'a> {
    head: &'a ElfHeader,
    phdrs: &'a [ProgramHeader],
}

impl<'a> Elf<'a> {
    pub unsafe fn new(bytes: *const u8) -> Self {
        let head = &*(bytes as *const ElfHeader);
        if head.magic != ElfMagic::Elf {
            panic!();
        }

        let phdrs = core::slice::from_raw_parts(
            (bytes.offset(head.phoff as isize)) as *const ProgramHeader,
            head.phnum as usize,
        );

        crate::println!("{:#?}", head);
        crate::println!("{:#?}", phdrs);
        Self { head, phdrs }
    }

    pub fn load(&self, root: &mut crate::mmu::Table) -> usize {
        for phdr in self.phdrs {
            match &phdr.ty {
                PhType::Load => {
                    crate::eprintln!("loading PH");
                    assert_eq!(phdr.align % 4096, 0);
                    let mut pages = crate::page::PageDescTable::init();
                    let to_alloc = (phdr.memsz + 0xfff) / 0x1000;
                    crate::eprintln!("allocating {} pages", to_alloc);
                    let dst = pages.alloc::<[u8; 4096]>((phdr.memsz + 0xfff) / 0x1000);
                    let dst = (dst as *const u8 as usize) | (phdr.vaddr & 0xfff);
                    unsafe {
                        core::ptr::copy_nonoverlapping((self.head as *const ElfHeader as *const u8).offset(phdr.offset as isize), dst as *mut u8, phdr.filesz);
                    }
                    let mut flags = crate::mmu::Entry(0);
                    if (phdr.pflags & 1) > 0 {
                        flags = flags | crate::mmu::EntryFlags::Exec;
                    }
                    if (phdr.pflags & 2) > 0 {
                        flags = flags | crate::mmu::EntryFlags::Write;
                    }
                    if (phdr.pflags & 4) > 0 {
                        flags = flags | crate::mmu::EntryFlags::Read;
                    }
                    for i in 0..to_alloc {
                        crate::mmu::map(
                            &mut pages,
                            root,
                            phdr.vaddr + (i << 12),
                            dst as usize + (i << 12),
                            flags | crate::mmu::EntryFlags::User,
                            0,
                        );
                        crate::eprintln!("mapped to vaddr: 0x{:x}", crate::mmu::virt_to_phys(root, phdr.vaddr + (i << 12)).unwrap());
                    }
                }
                ty => crate::eprintln!("not loading PH of type {:?}", ty)
            }
        }
        self.head.entry
    }
}
