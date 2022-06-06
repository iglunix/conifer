use alloc::boxed::Box;
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

#[repr(align(4096))]
#[derive(Clone)]
pub struct Table {
    pub entries: [Entry; 512],
}

static mut root_tbl: *mut Table = core::ptr::null_mut();

impl Table {
    pub fn root() -> &'static mut Table {
        unsafe {
            if core::intrinsics::unlikely(root_tbl.is_null()) {
                let satp: usize;
                core::arch::asm!("csrr {}, satp", out(reg) satp);
                root_tbl = (((satp & 0xffffffffffffff) << 12) + crate::KMEM_OFFSET) as *mut Table;
                eprintln!("MMU: root page table at {:p}", root_tbl);
            }

            &mut *root_tbl
        }
    }

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
            Entry(0) => {
                // eprintln!("{:0>3x}: empty", i);
            }
            e if e.is_leaf() => {
                println!("at leaf");
                let Entry(e) = e;
                indices[depth] = i;
                let v = (indices[0] << 30) | (indices[1] << 21) | (indices[2] << 12);
                let mut bytes = [b' ', b' ', b' ', 0];
                if (e & (1 << 1)) > 0 {
                    bytes[0] = b'r';
                }
                if (e & (1 << 2)) > 0 {
                    bytes[1] = b'w';
                }
                if (e & (1 << 3)) > 0 {
                    bytes[2] = b'x';
                }
                let s = core::str::from_utf8(&bytes).unwrap();
                eprintln!(
                    "map 0x{:x} -> 0x{:x} : {}",
                    v,
                    ((e >> 10) & 0x7ffffff) << 12,
                    s
                );
            }
            Entry(v) => {
                let Entry(e) = e;
                eprintln!("node {}: 0x{:x}", i, ((e >> 10) & ((1 << 56) - 1)) << 12);
                indices[depth] = i;
                unsafe {
                    ((((v & !0x3ff) << 2) as usize + crate::KMEM_OFFSET) as *const Table)
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

    pub fn clear_user_ptes(&mut self) {
        self.entries[..256].iter_mut().for_each(|e| *e = Entry(0));
        unsafe { core::arch::asm!("sfence.vma") }
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

pub fn map(root: &mut Table, vaddr: usize, paddr: usize, flags: Entry, level: usize) {
    assert!((root as *const Table as usize) > (1 << 63));

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
            let mut page = Box::new(crate::mmu::Table::new());
            let ppage = page.as_mut() as *mut Table as usize;
            let ppage = virt_to_phys(crate::mmu::Table::root(), ppage).unwrap();
            v.0 = (ppage as u64 >> 2) | EntryFlags::Valid as u64;
            // TODO: this is a memory leak
            core::mem::forget(page);
        }

        assert!(v.is_valid());

        let tbl = unsafe {
            let tbl_naddr = ((v.0 & !0x3ff) << 2);
            assert!((tbl_naddr) < (1 << 63));
            let tbl_naddr = tbl_naddr + crate::KMEM_OFFSET as u64;
            (tbl_naddr as *mut Table).as_mut().unwrap()
        };

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
    let mut v = root.entries[(vaddr >> 30) & 0x1ff];

    for i in (0..=2).rev() {
        if v.is_invalid() {
            panic!("page fault at depth {}: {:x}", i, vaddr);
        } else if v.is_leaf() {
            let off_mask = (1 << (12 + i * 9)) - 1;
            let vaddr_pgoff = vaddr & off_mask;
            let addr = ((v.0 << 2) as usize) & !off_mask;
            return Some(addr | vaddr_pgoff);
        }

        let tbl = unsafe {
            let tbl_naddr = ((v.0 & !0x3ff) << 2);
            assert!((tbl_naddr) < (1 << 63));
            let tbl_naddr = tbl_naddr + crate::KMEM_OFFSET as u64;
            (tbl_naddr as *mut Table).as_mut().unwrap()
        };

        v = unsafe { tbl.entries[vpn[i - 1]] };
    }

    None
}
pub fn map2u(paddr: usize, uaddr: usize, count: usize, flags: Entry) {
    let root = Table::root();

    for i in 0..count {
        map(root, uaddr + (i << 12), paddr + (i << 12), flags, 0);
    }
}

pub fn mapk2u(kaddr: usize, uaddr: usize, count: usize, flags: Entry) {
    let root = Table::root();
    let paddr = virt_to_phys(root, kaddr).unwrap();
    map2u(paddr, uaddr, count, flags);
}

pub fn fence() {
    unsafe {
        core::arch::asm!("sfence.vma");
    }
}
