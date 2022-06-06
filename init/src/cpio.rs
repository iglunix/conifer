/// We only support newc
#[repr(packed)]
#[derive(Debug,Clone,Copy)]
pub struct CpioHeader {
    // don't include magic?
    magic: [u8; 6],
    ino: u64,
    mode: u64,
    uid: u64,
    gid: u64,
    nlink: u64,
    mtime: u64,
    filesize: u64,
    devmajor: u64,
    devminor: u64,
    rdevmajor: u64,
    rdevminor: u64,
    namesize: u64,
    check: u64
}

impl <'a> CpioHeader {
    pub fn name(&'a self) -> &'a str {
        core::str::from_utf8(
            // SAFETY: safe all the while `self` is a valid reference to a CpioHeader
            unsafe {
                core::slice::from_raw_parts(
                    (self as *const CpioHeader).offset(1) as *const u8,
                    self.namesize as usize
                )
            }
        ).unwrap()
    }
}
