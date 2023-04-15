#[repr(C)]
#[derive(Clone, Copy)]
struct PageTblEntry(u64);
impl  PageTblEntry {
    const fn new() -> Self {
        Self(0)
    }

    fn set_addr(&mut self, paddr: usize) {
        // 56 bit paddr
        let paddr = paddr & ((1 << 56) - 1);
        // 12 bit page offset
        let paddr = paddr >> 12;
        self.0 &= !(((1 << 44) - 1) << 10);
        self.0 |= (paddr as u64) << 10;
    }

    fn addr(&self) -> usize {
        ((self.0 & (((1 << 56) - 1) << 10)) << 2) as usize
    }

    fn set_global(&mut self, global: bool) {
        if global {
            self.0 |= 1 << 5;
        } else {
            self.0 &= !(1 << 5);
        }
    }

    fn set_user(&mut self, user: bool) {
        if user {
            self.0 |= 1 << 4;
        } else {
            self.0 &= !(1 << 4);
        }
    }

    fn set_exec(&mut self, exec: bool) {
        if exec {
            self.0 |= 1 << 3;
        } else {
            self.0 &= !(1 << 3);
        }
    }

    fn set_write(&mut self, write: bool) {
        if write {
            self.0 |= 1 << 2;
        } else {
            self.0 &= !(1 << 2);
        }
    }

    fn set_read(&mut self, read: bool) {
        if read {
            self.0 |= 1 << 1;
        } else {
            self.0 &= !(1 << 1);
        }
    }

    fn set_valid(&mut self, valid: bool) {
        if valid {
            self.0 |= 1 << 0;
        } else {
            self.0 &= !(1 << 0);
        }
    }

    fn valid(&self) -> bool {
        (self.0 & 1) > 0
    }
}

#[repr(C)]
#[repr(align(0x1000))]
#[derive(Clone)]
struct PageTbl([PageTblEntry; 0x200]);
