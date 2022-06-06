// TODO: maybe support cpio too
#[derive(Debug)]
#[repr(C)]
pub struct TarHeader {
    name: [u8; 100],
    mode: [u8; 8],
    uid: [u8; 8],
    gid: [u8; 8],
    size: [u8; 12],
    mtime: [u8; 12],
}

fn from_oct(oct: &[u8]) -> usize {
    let mut ret = 0;
    for o in oct {
        if *o != b'\0' {
            ret *= 8;
            ret += *o as usize - 0x30;
        }
    }
    ret
}

impl TarHeader {
    pub fn name(&self) -> &str {
        let mut i = 0;
        while self.name[i] != b'\0' {
            i += 1;
        }
        core::str::from_utf8(&self.name[..i]).unwrap()
    }

    pub fn size(&self) -> usize {
        from_oct(&self.size)
    }
}

#[derive(Debug)]
pub struct Tar<'a> {
    tar: &'a [[u8; 512]],
}

impl<'a> Tar<'a> {
    pub fn new(tar: &'a [[u8; 512]]) -> Self {
        Self { tar }
    }

    pub fn find(&self, name: &str) -> &TarHeader {
        let mut i = 0;
        let mut head;
        while {
            unsafe {
                head = &*(self.tar[i].as_ptr() as *const TarHeader);
                i += (head.size() + 0x1ff) >> 9;
                crate::println!(
                    "checking: {} == {} = {}",
                    head.name(),
                    name,
                    head.name() == name
                );
                head.name() != name
            }
        } {}
        head
    }
}
