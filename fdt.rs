pub struct Fdt<'a> {
    data: &'a [u8],
    size: usize,
    structs: &'a [u8],
    strings: &'a [u8],
    memres_offset: usize,
}

struct MemoryRes {
    addr: usize,
    size: usize,
}

use core::ffi::CStr;
enum FdtToken {
    FdtBeginNode = 1,
    FdtEndNode = 2,
    FdtProp = 3,
    FdtNop = 4,
    FdtEnd = 9,
}

pub struct FdtNode<'a> {
    fdt: &'a Fdt<'a>,
    name: &'a str,
    data: &'a [u8],
    struct_index: usize,
    done: bool,
}

impl core::fmt::Debug for FdtNode<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        let mut s = f.debug_struct("FdtNode");
        let mut n = FdtNode {
            fdt: self.fdt,
            name: self.name,
            data: self.data,
            struct_index: self.struct_index,
            done: self.done,
        };

        for element in n {
            match element {
                FdtPart::Node(node) => {
                    s.field(node.name, &node);
                }

                FdtPart::Prop(prop) => {
                    s.field(prop.name, &prop);
                }
            }
        }

        s.finish()
    }
}

impl<'a> FdtNode<'a> {
    fn new(fdt: &'a Fdt<'a>, name: &'a str, struct_index: usize, len: usize) -> Self {
        let data = &fdt.data[(struct_index * 4)..(struct_index * 4) + len];
        Self {
            fdt,
            name,
            data,
            struct_index: 0,
            done: false,
        }
    }
}

pub struct FdtProp<'a> {
    fdt: &'a Fdt<'a>,
    name: &'a str,
    prop: &'a [u8],
}
impl core::fmt::Debug for FdtProp<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("FdtProp")
            .field("size", &self.prop.len())
            .finish()
    }
}

#[derive(Debug)]
pub enum FdtPart<'a> {
    Node(FdtNode<'a>),
    Prop(FdtProp<'a>),
}

impl FdtNode<'_> {
    fn struct_val(&self, i: usize) -> u32 {
        u32::from_be_bytes(self.data[i * 4..i * 4 + 4].try_into().unwrap())
    }
    fn struct_token(&self, i: usize) -> FdtToken {
        match self.struct_val(i) {
            val if val == (FdtToken::FdtBeginNode as u32) => FdtToken::FdtBeginNode,
            val if val == (FdtToken::FdtEndNode as u32) => FdtToken::FdtEndNode,
            val if val == (FdtToken::FdtProp as u32) => FdtToken::FdtProp,
            val if val == (FdtToken::FdtNop as u32) => FdtToken::FdtNop,
            val if val == (FdtToken::FdtEnd as u32) => FdtToken::FdtEnd,
            val => panic!("unexpected fdt token value at {}: {}", i, val),
        }
    }
}

impl FdtNode<'_> {
    fn skip(&mut self) {
        let mut depth = 1;
        while match {
            let t = self.struct_token(self.struct_index);
            self.struct_index += 1;
            t
        } {
            FdtToken::FdtBeginNode => {
                let s = CStr::from_bytes_until_nul(&self.data[self.struct_index * 4..]).unwrap();
                self.struct_index += (s.count_bytes() + 4) >> 2;
                let s = s.to_str().unwrap();
                depth += 1;
                true
            }
            FdtToken::FdtEndNode => {
                depth -= 1;
                depth != 0
            }
            FdtToken::FdtProp => {
                let len = self.struct_val(self.struct_index);
                self.struct_index += 1;
                let nameoff = self.struct_val(self.struct_index);
                self.struct_index += 1;
                self.struct_index += (len as usize + 3) >> 2;
                true
            }
            FdtToken::FdtNop => true,
            FdtToken::FdtEnd => false,
        } {}
    }
}

impl<'a> Iterator for FdtNode<'a> {
    type Item = FdtPart<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match {
            let t = self.struct_token(self.struct_index);
            self.struct_index += 1;
            t
        } {
            FdtToken::FdtBeginNode => {
                let s = CStr::from_bytes_until_nul(&self.data[self.struct_index * 4..]).unwrap();
                self.struct_index += (s.count_bytes() + 4) >> 2;
                let name = s.to_str().unwrap();
                let start_index = self.struct_index;
                self.skip();
                let end_index = self.struct_index;
                let data = &self.data[start_index * 4..end_index * 4];
                Some(FdtPart::Node(FdtNode {
                    fdt: self.fdt,
                    name,
                    data,
                    struct_index: 0,
                    done: false,
                }))
            }
            FdtToken::FdtEndNode => {
                self.done = true;
                None
            }
            FdtToken::FdtProp => {
                let len = self.struct_val(self.struct_index);
                self.struct_index += 1;
                let nameoff = self.struct_val(self.struct_index);
                self.struct_index += 1;
                let prop =
                    &self.data[(self.struct_index * 4)..(self.struct_index * 4) + len as usize];
                self.struct_index += (len as usize + 3) >> 2;

                let name = self.fdt.lookup_string(nameoff as usize);

                Some(FdtPart::Prop(FdtProp {
                    fdt: self.fdt,
                    name,
                    prop,
                }))
            }
            FdtToken::FdtNop => self.next(),
            FdtToken::FdtEnd => {
                self.done = true;
                None
            }
        }
    }
}

impl<'a> Fdt<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
        let struct_offset = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
        let string_offset = u32::from_be_bytes(data[12..16].try_into().unwrap()) as usize;
        let memres_offset = u32::from_be_bytes(data[16..20].try_into().unwrap()) as usize;
        let string_size = u32::from_be_bytes(data[32..36].try_into().unwrap()) as usize;
        let struct_size = u32::from_be_bytes(data[36..40].try_into().unwrap()) as usize;

        let mut addr = 1;
        let mut i = 0;
        while addr != 0 {
            let o = memres_offset + i * 16;
            addr = u64::from_be_bytes(data[o..o + 8].try_into().unwrap());
            let size = u64::from_be_bytes(data[o + 8..o + 16].try_into().unwrap());
            i += 1;
        }

        let strings = &data[string_offset..string_offset + string_size];
        let structs = &data[struct_offset..struct_offset + struct_size];
        Self {
            data,
            size,
            structs,
            strings,
            memres_offset,
        }
    }

    fn struct_val(&self, i: usize) -> u32 {
        u32::from_be_bytes(self.structs[i * 4..i * 4 + 4].try_into().unwrap())
    }
    fn struct_token(&self, i: usize) -> FdtToken {
        match self.struct_val(i) {
            val if val == (FdtToken::FdtBeginNode as u32) => FdtToken::FdtBeginNode,
            val if val == (FdtToken::FdtEndNode as u32) => FdtToken::FdtEndNode,
            val if val == (FdtToken::FdtProp as u32) => FdtToken::FdtProp,
            val if val == (FdtToken::FdtNop as u32) => FdtToken::FdtNop,
            val if val == (FdtToken::FdtEnd as u32) => FdtToken::FdtEnd,
            val => panic!("unexpected fdt token value at {}: {}", i, val),
        }
    }

    pub fn root(&'a self) -> FdtNode<'a> {
        if let Some(FdtPart::Node(node)) = {
            FdtNode {
                fdt: self,
                name: "",
                data: self.structs,
                struct_index: 0,
                done: false,
            }
            .next()
        } {
            node
        } else {
            panic!("invalid fdt");
        }
    }

    pub fn lookup_string(&self, offset: usize) -> &str {
        CStr::from_bytes_until_nul(&self.strings[offset..])
            .unwrap()
            .to_str()
            .unwrap()
    }
}

/*
impl<'a> Fdt<'a> {
    fn strings(&'a self) -> FdtStrings<'a> {
        FdtStrings {
            fdt: self,
            offset: 0,
        }
    }
}

struct FdtStrings<'a> {
    fdt: &'a Fdt<'a>,
    offset: usize,
}

impl<'a> Iterator for FdtStrings<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset < self.fdt.strings.len() {
            let s = CStr::from_bytes_until_nul(&self.fdt.strings[self.offset..]).unwrap();
            self.offset += s.count_bytes() + 1;
            Some(s.to_str().unwrap())
        } else {
            None
        }
    }
}

impl core::fmt::Debug for FdtStrings<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        let s = FdtStrings {
            fdt: self.fdt,
            offset: 0,
        };
        f.debug_list().entries(s).finish()
    }
}
*/

impl core::fmt::Debug for Fdt<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Fdt")
            .field("structs", &self.root())
            .finish()
            // .field("strings", &self.strings())
    }
}
