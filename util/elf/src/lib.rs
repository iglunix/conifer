#![no_std]
#![feature(assert_matches)]

#[macro_use]
extern crate earlycon;

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(unused)]
pub enum ElfMagic {
    Elf = 0x464c457f,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
pub enum ElfClass {
    X32 = 1,
    X64 = 2,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
pub enum ElfEndianness {
    Little = 1,
    Big = 2,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
pub enum ElfAbi {
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
pub enum ElfType {
    None = 0,
    Rel = 1,
    Exec = 2,
    Dyn = 3,
    Core = 4,
}

#[repr(u16)]
#[derive(Debug)]
#[allow(unused)]
pub enum ElfArch {
    None = 0,
    RiscV = 0xf3,
}

#[repr(C)]
#[derive(Debug)]
pub struct ElfHeader {
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
    pub entry: usize,
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
    pub ty: PhType,
    pub pflags: u32,
    pub offset: usize,
    pub vaddr: usize,
    pub paddr: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
}

#[repr(u32)]
#[derive(Debug,Clone,Copy)]
pub enum ShType {
    Null = 0,
    ProgBits = 1,
    SymTab = 2,
    StrTab = 3,
    Rela = 4,
    Hash = 5,
    Dyn = 6,
    Note = 7,
    NoBits = 8,
    Rel = 9,
    ShLib = 10,
    DynSym = 11,
    InitArray = 14,
    FiniArray = 15,
}

#[repr(C)]
#[derive(Debug)]
pub struct SectionHeader {
    pub name: u32,
    pub ty: ShType,
    flags: usize,
    addr: usize,
    pub offset: usize,
    pub size: usize,
    link: u32,
    info: u32,
    addralign: usize,
    entsize: usize
}

#[repr(C)]
#[derive(Debug)]
pub struct SymTabEnt {
    pub name: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
    pub value: usize,
    pub size: u64
}

#[derive(Debug)]
pub struct Elf<'a> {
    pub head: &'a ElfHeader,
    pub phdrs: &'a [ProgramHeader],
    pub shdrs: &'a [SectionHeader]
}

impl<'a> Elf<'a> {
    pub unsafe fn new(bytes: *const u8) -> Self {
        // eprintln!("byte: {:#x?}", core::slice::from_raw_parts(bytes, 32));
        
        let head = &*(bytes as *const ElfHeader);
        if head.magic as u32 != ElfMagic::Elf as u32 {
            panic!("not an elf file");
        }

        if !matches!(head.endianness, ElfEndianness::Little) {
            panic!();
        }

        let phdrs = core::slice::from_raw_parts(
            (bytes.offset(head.phoff as isize)) as *const ProgramHeader,
            head.phnum as usize,
        );

        let shdrs = core::slice::from_raw_parts(
            (bytes.offset(head.shoff as isize)) as *const SectionHeader,
            head.shnum as usize
        );

        Self { head, phdrs, shdrs }
    }
}
