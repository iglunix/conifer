#![no_std]

#[macro_use]
extern crate con;

#[repr(C)]
#[derive(Debug)]
struct FdtHeader {
    magic: u32,
    total_size: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

#[derive(Debug)]
pub struct FdtNode {
    structs: &'static [u32],
    strings: &'static [u8],
}

impl FdtNode {
    pub fn node(&self, name: &str) -> Self {
        let mut structs = self.structs.iter().map(|x| u32::from_be(*x)).enumerate();
        while match structs.next() {
            Some((i, 1)) => {
                let mut name = name.bytes();
                let mut found = false;

                let sptr = unsafe { self.structs.as_ptr().offset(i as isize + 1) } as *const u8;
                let mut j = 0;

                while match name.next() {
                    Some(b) if b == b'@' && b == unsafe { *sptr.offset(j) } => {
                        while unsafe { *sptr.offset(j) } != 0 {
                            j += 1
                        }
                        return Self {
                            structs: &self.structs[(i + ((j as usize + 3) >> 2) + 1)..],
                            strings: self.strings,
                        };
                    }

                    Some(b) if b == unsafe { *sptr.offset(j) } => true,

                    None if 0 == unsafe { *sptr.offset(j) } => {
                        return Self {
                            structs: &self.structs[(i + ((j as usize + 3) >> 2) + 1)..],
                            strings: self.strings,
                        };
                    }

                    Some(_) => false,
                    None => false,
                } {
                    j += 1;
                }

                true
            }
            Some((_, 9)) => false,
            Some(_) => true,
            None => panic!(),
        } {}

        panic!("Node `{}` not found in FDT", name);
    }

    pub fn dump(&self) {
        let mut structs = self.structs.iter().map(|x| u32::from_be(*x));
        let mut depth = 0;
        while {
            for i in 0..depth {
                print!("- ")
            }
            match structs.next() {
                Some(1) => {
                    print!("Begin Node ");
                    depth += 1;
                    loop {
                        let s = structs.next().unwrap();
                        let a = s >> 24 & 0xff;
                        if a == 0 {
                            break;
                        }
                        print!("{}", char::from_u32(a).unwrap());
                        let a = s >> 16 & 0xff;
                        if a == 0 {
                            break;
                        }
                        print!("{}", char::from_u32(a).unwrap());
                        let a = s >> 8 & 0xff;
                        if a == 0 {
                            break;
                        }
                        print!("{}", char::from_u32(a).unwrap());
                        let a = s & 0xff;
                        if a == 0 {
                            break;
                        }
                        print!("{}", char::from_u32(a).unwrap());
                    }
                    println!();
                    true
                }
                Some(2) => {
                    if depth == 0 {
                        false
                    } else {
                        depth -= 1;
                        println!();
                        true
                    }
                }
                Some(3) => {
                    let len = structs.next().unwrap();
                    let name_off = structs.next().unwrap();
                    print!("Property ({}) ", len);

                    let mut x = name_off;
                    loop {
                        let c = self.strings[x as usize];
                        if c == 0 {
                            break;
                        }
                        print!("{}", char::from_u32(c as u32).unwrap());
                        x += 1;
                    }
                    println!();

                    for i in 0..((len + 3) >> 2) {
                        structs.next();
                    }
                    true
                }
                Some(4) => {
                    println!("Nop");
                    true
                }
                Some(9) => false,
                Some(_) => {
                    panic!("Error parsing FDT");
                    false
                }
                None => false,
            }
        } {}
    }

    pub fn prop(&self, name: &str) -> &'static [u8] {
        let mut structs = self.structs.iter().map(|x| u32::from_be(*x)).enumerate();
        while match structs.next() {
            Some((_, 1)) => {
                while match structs.next() {
                    Some((_, 2)) => false,
                    Some(_) => true,
                    None => panic!(),
                } {}
                true
            }
            Some((i, 3)) => {
                let len = structs.next().unwrap().1;
                let name_off = structs.next().unwrap().1;
                let bytes = &self.strings[(name_off as usize)..];
                let mut name = name.bytes();
                let mut j = 0;

                while match name.next() {
                    Some(b) if b == bytes[j] => true,

                    Some(_) => false,

                    None if bytes[j] == 0 => {
                        return unsafe {
                            core::slice::from_raw_parts(
                                self.structs[(i + 3)..].as_ptr() as *const u8,
                                (len as usize),
                            )
                        };
                    }

                    None => false,
                } {
                    j += 1
                }

                true
            }
            Some((_, 9)) => false,
            Some(_) => true,
            None => panic!(),
        } {}

        panic!();
    }
}

#[derive(Debug)]
pub struct Fdt {
    head: &'static FdtHeader,
    structs: &'static [u32],
    strings: &'static [u8],
}

impl Fdt {
    pub unsafe fn from_addr(addr: usize) -> Self {
        let head = &*(addr as *const FdtHeader);

        let structs = core::slice::from_raw_parts(
            (addr + u32::from_be(head.off_dt_struct) as usize) as *const u32,
            u32::from_be(head.size_dt_struct) as usize >> 2,
        );

        let strings = core::slice::from_raw_parts(
            (addr + u32::from_be(head.off_dt_strings) as usize) as *const u8,
            u32::from_be(head.size_dt_strings) as usize,
        );

        Self {
            head,
            structs,
            strings,
        }
    }

    pub fn root(&self) -> FdtNode {
        FdtNode {
            structs: &self.structs[2..],
            strings: self.strings,
        }
    }

    pub fn size(&self) -> usize {
        u32::from_be(self.head.total_size) as usize
    }
}
