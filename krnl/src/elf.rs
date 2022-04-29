#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
enum ElfMagic {
    Elf = 0x464c457f
}

#[repr(u8)]
#[derive(Debug)]
enum ElfClass {
    X32 = 1,
    X64 = 2,
}

#[repr(u8)]
#[derive(Debug)]
enum ElfEndianness {
    Little = 1,
    Big = 2,
}

#[repr(u8)]
#[derive(Debug)]
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
enum ElfType {
    None = 0,
    Rel = 1,
    Exec = 2,
    Dyn = 3,
    Core = 4,
}

#[repr(u16)]
#[derive(Debug)]
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
enum PhType {
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
struct ProgramHeader {
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

impl <'a> Elf<'a> {
    pub unsafe fn new(bytes: *const u8) {
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
    }
}
