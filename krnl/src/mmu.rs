use crate::eprintln;

#[repr(align(4096))]
pub struct Table {
    pub entries: [Entry; 512],
}

impl Table {
    pub fn new() -> Self {
        Table {
            entries: [Entry(0); 512],
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn do_dump(&self, depth: usize, indices: &mut [usize; 3]) {
        assert!(depth < 3);
        self.entries.iter().enumerate().for_each(|(i, e)| match e {
            Entry(0) => {}
            e if e.is_leaf() => {
                let Entry(e) = e;
                indices[depth] = i;
                let v = (indices[0] << 30) | (indices[1] << 21) | (indices[2] << 12);
                eprintln!("map 0x{:x} -> 0x{:x}", v, ((e >> 10) & 0x7ffffff) << 12);
            }
            Entry(v) => {
                let Entry(e) = e;
                // eprintln!("node {}: 0x{:x}", i, ((e >> 10) & 0x7ffffff) << 12);
                indices[depth] = i;
                unsafe {
                    (((v & !0x3ff) << 2) as *const Table)
                        .as_ref()
                        .unwrap()
                        .do_dump(depth + 1, indices);
                }
            }
        });
    }
    
    pub fn dump(&self) {
        let mut indices = [0; 3];
        self.do_dump(0, &mut indices);
    }
}

use core::ops::BitOr;

#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum EntryFlags {
    Valid = 1 << 0,
    Read = 1 << 1,
    Write = 1 << 2,
    Exec = 1 << 3,
    User = 1 << 4,
    Global = 1 << 5,
    Access = 1 << 6,
    Dirty = 1 << 7,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Entry(pub u64);

impl core::ops::BitOr<EntryFlags> for EntryFlags {
    type Output = Entry;
    fn bitor(self, rhs: EntryFlags) -> Self::Output {
        Entry(self as u64 | rhs as u64)
    }
}

impl core::ops::BitAnd<EntryFlags> for EntryFlags {
    type Output = Entry;
    fn bitand(self, rhs: EntryFlags) -> Self::Output {
        Entry(self as u64 & rhs as u64)
    }
}

impl core::ops::BitOr<EntryFlags> for Entry {
    type Output = Entry;
    fn bitor(self, rhs: EntryFlags) -> Self::Output {
        Entry(self.0 | rhs as u64)
    }
}

impl core::ops::BitAnd<EntryFlags> for Entry {
    type Output = Entry;
    fn bitand(self, rhs: EntryFlags) -> Self::Output {
        Entry(self.0 & rhs as u64)
    }
}

impl core::ops::BitOr<Entry> for Entry {
    type Output = Entry;
    fn bitor(self, rhs: Entry) -> Self::Output {
        Entry(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd<Entry> for Entry {
    type Output = Entry;
    fn bitand(self, rhs: Entry) -> Self::Output {
        Entry(self.0 & rhs.0)
    }
}

impl Entry {
    pub fn is_valid(&self) -> bool {
        self.0 & EntryFlags::Valid as u64 == EntryFlags::Valid as u64
    }

    pub fn is_invalid(&self) -> bool {
        !self.is_valid()
    }

    pub fn is_leaf(&self) -> bool {
        self.0 & 0b1110 != 0
    }

    pub fn is_branch(&self) -> bool {
        !self.is_leaf()
    }
}

pub fn map(
    pages: &mut crate::page::PageDescTable,
    root: &mut Table,
    vaddr: usize,
    paddr: usize,
    flags: Entry,
    level: usize,
) {
    assert!((flags & (EntryFlags::Read | EntryFlags::Write | EntryFlags::Exec)).0 != 0);

    let vpn = [
        (vaddr >> 12) & 0x1ff,
        (vaddr >> 21) & 0x1ff,
        (vaddr >> 30) & 0x1ff,
    ];

    let ppn = [
        (paddr >> 12) & 0x1ff,
        (paddr >> 21) & 0x1ff,
        (paddr >> 30) & 0x3ff_ffff,
    ];

    let mut v = &mut root.entries[vpn[2]];

    for i in (level..2).rev() {
        if v.is_invalid() {
            let page = pages.alloc::<crate::mmu::Table>(1);
            unsafe {
                page.as_uninit_mut()
                    .unwrap()
                    .write(crate::mmu::Table::new());
            }

            v.0 = (page as u64 >> 2) | EntryFlags::Valid as u64;
        }

        assert!(v.is_valid());

        let tbl = unsafe { (((v.0 & !0x3ff) << 2) as *mut Table).as_mut().unwrap() };

        v = unsafe { &mut tbl.entries[vpn[i]] };
    }

    let entry = (ppn[2] << 28) as u64
        | (ppn[1] << 19) as u64
        | (ppn[0] << 10) as u64
        | (flags | EntryFlags::Valid).0;

    v.0 = entry;
    assert!(v.is_leaf());
    assert!(v.is_valid());
}

pub fn virt_to_phys(root: &Table, vaddr: usize) -> Option<usize> {
    let vpn = [
        (vaddr >> 12) & 0x1ff,
        (vaddr >> 21) & 0x1ff,
        (vaddr >> 30) & 0x1ff,
    ];

    let mut v = &root.entries[vpn[2]];

    for i in (0..=2).rev() {
        if v.is_invalid() {
            panic!("page fault: {:x}", vaddr);
        } else if v.is_leaf() {
            let off_mask = (1 << (12 + i * 9)) - 1;
            let vaddr_pgoff = vaddr & off_mask;
            let addr = ((v.0 << 2) as usize) & !off_mask;
            return Some(addr | vaddr_pgoff);
        }

        let tbl = unsafe { (((v.0 & !0x3ff) << 2) as *const Table).as_ref().unwrap() };

        v = unsafe { &tbl.entries[vpn[i - 1]] };
    }

    None
}
