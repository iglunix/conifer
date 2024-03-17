// can take memory cap when starting new hart to use as kernel stack.

use crate::abi;
use crate::abi::SysError;
use crate::abi::Syscall;
use crate::rwlock::RwLock;

use core::marker::PhantomData;

pub fn wait() {
    unsafe { core::arch::asm!("wfi") }
}

pub fn get_time() -> usize {
    unsafe {
        let ret;
        core::arch::asm!("csrr {}, time", out(reg) ret);
        ret
    }
}

pub fn set_time(time: usize) {
    unsafe {
        const TIME_EID: usize = 0x54494D45;
        const TIME_FID: usize = 0;
        core::arch::asm!("ecall", in("a0") time, in("a6") TIME_FID, in("a7") TIME_EID);
    }
}

fn enable_timer() {
    unsafe {
        core::arch::asm!("csrs sie, {}", in(reg) 0x20);
    }
}

// fn enable_interrupts() {
// 	unsafe {
// 		core::arch::asm!("csrc sstatus, {}", in(reg) 0x2);
// 	}
// }

pub fn putchar(c: u8) {
    unsafe {
        core::arch::asm!("ecall", in("a0") c as u32, in("a6") 0, in("a7") 1);
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PageTableEntry<const LEVEL: usize>(usize);

impl<const LEVEL: usize> PageTableEntry<LEVEL> {
    const fn zero() -> Self {
        Self(0)
    }

    // PROVENANCE: this is a physical address with no provenance.
    // provenance must be forged with ptr.with_addr()
    fn addr(&self) -> usize {
        ((self.0 >> 10) & ((1 << 44) - 1)) << 12
    }

    fn valid(&self) -> bool {
        (self.0 & 0b1) == 0b1
    }

    fn prot(&self) -> usize {
        (self.0 >> 1) & 0b1111
    }

    fn invalidate(&mut self) -> CapRef<Mem> {
        let paddr = self.addr();
        self.0 = self.0 & !1;
        CapRef::<Mem>::new(core::ptr::from_exposed_addr_mut(paddr), PAGE_SIZE)
    }
}

impl<const LEVEL: usize> core::fmt::Debug for PageTableEntry<LEVEL> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("addr", &self.addr())
            .field("prot", &self.prot())
            .field("valid", &self.valid())
            .finish()
    }
}

impl PageTableEntry<2> {
    fn try_next_table_mut(&mut self) -> Option<&mut PageTable<1>> {
        if self.valid() {
            Some(self.next_table_mut())
        } else {
            None
        }
    }

    fn try_next_table(&self) -> Option<&PageTable<1>> {
        if self.valid() {
            Some(self.next_table())
        } else {
            None
        }
    }

    fn next_table_mut(&mut self) -> &mut PageTable<1> {
        unsafe { &mut *(pmem_map().add(self.addr()) as *mut PageTable<1>) }
    }

    fn next_table(&self) -> &PageTable<1> {
        unsafe { &*(pmem_map().add(self.addr()) as *const PageTable<1>) }
    }
}

impl PageTableEntry<1> {
    fn try_next_table_mut(&mut self) -> Option<&mut PageTable<0>> {
        if self.valid() {
            Some(self.next_table_mut())
        } else {
            None
        }
    }

    fn try_next_table(&self) -> Option<&PageTable<0>> {
        if self.valid() {
            Some(self.next_table())
        } else {
            None
        }
    }

    fn next_table_mut(&mut self) -> &mut PageTable<0> {
        unsafe { &mut *(pmem_map().add(self.addr()) as *mut PageTable<0>) }
    }

    fn next_table(&self) -> &PageTable<0> {
        unsafe { &*(pmem_map().add(self.addr()) as *const PageTable<0>) }
    }
}

impl<const LEVEL: usize> PageTableEntry<LEVEL> {
    fn new(cap: CapRef<Mem>, prot: abi::Prot) -> Self {
        let bits = prot_to_bits(prot);
        let paddr = cap.ptr().addr();
        Self(paddr >> 12 << 10 | bits | 0b10001)
    }
}

//#[repr(align(4096))]
#[repr(C)]
struct PageTable<const LEVEL: usize>([PageTableEntry<LEVEL>; 512]);

impl<const LEVEL: usize> PageTable<LEVEL> {
    fn entry(&self, idx: usize) -> &PageTableEntry<LEVEL> {
        &self.0[idx]
    }

    fn entry_mut(&mut self, idx: usize) -> &mut PageTableEntry<LEVEL> {
        &mut self.0[idx]
    }

    fn dump(&self) {
        eprintln!("{{");
        for i in 0..512 {
            let e = self.entry(i);
            if e.valid() {
                eprintln!("\t{:0>3}:{:?}", i, self.entry(i));
            }
        }
        eprintln!("}}");
    }
}

impl PageTable<2> {
    fn fill_pmap(&mut self) {
        for i in 0..128 {
            let entry = PageTableEntry::<2>(i * 0x10000000 | 0x7);
            unsafe {
                self.0[256 + i] = entry;
            }
        }
    }

    fn fill_kmem(&mut self) {
        self.0[511] = TaskRef::current().root_table().0[511];
    }

    fn try_next_table(&self, idx: usize) -> Option<&PageTable<1>> {
        self.entry(idx).try_next_table()
    }

    fn try_next_table_mut(&mut self, idx: usize) -> Option<&mut PageTable<1>> {
        self.entry_mut(idx).try_next_table_mut()
    }
}

impl PageTable<1> {
    fn try_next_table(&self, idx: usize) -> Option<&PageTable<0>> {
        self.entry(idx).try_next_table()
    }

    fn try_next_table_mut(&mut self, idx: usize) -> Option<&mut PageTable<0>> {
        self.entry_mut(idx).try_next_table_mut()
    }
}

impl Table {
    fn cap_ptr(&self) -> *const Option<CapRaw> {
        core::ptr::from_exposed_addr(0xffffffe000000000)
    }

    fn cap_mut_ptr(&mut self) -> *mut Option<CapRaw> {
        core::ptr::from_exposed_addr_mut(0xffffffe000000000)
    }

    fn get_raw(&self, idx: usize) -> &Option<CapRaw> {
        unsafe { &*self.cap_ptr().add(idx) }
    }

    fn get_mut_raw(&mut self, idx: usize) -> &mut Option<CapRaw> {
        unsafe { &mut *self.cap_mut_ptr().add(idx) }
    }

    fn try_get<T: CapObj>(&self, idx: usize) -> Result<&Option<CapRef<T>>, SysError> {
        let raw = self.get_raw(idx);
        if raw.is_some() {
            if raw.as_ref().unwrap().ty() == T::CAP_TYPE {
                Ok(unsafe { core::mem::transmute(raw) })
            } else {
                Err(SysError::InvalidCapType)
            }
        } else {
            Ok(unsafe { core::mem::transmute(raw) })
        }
    }

    fn get<T: CapObj>(&self, idx: usize) -> Result<&CapRef<T>, SysError> {
        self.try_get(idx)
            .and_then(|o| o.as_ref().ok_or(SysError::SlotEmpty))
    }

    fn try_get_mut<T: CapObj>(&mut self, idx: usize) -> Result<&mut Option<CapRef<T>>, SysError> {
        let raw = self.get_mut_raw(idx);
        if raw.is_some() {
            if raw.as_mut().unwrap().ty() == T::CAP_TYPE {
                Ok(unsafe { core::mem::transmute(raw) })
            } else {
                Err(SysError::InvalidCapType)
            }
        } else {
            Ok(unsafe { core::mem::transmute(raw) })
        }
    }

    fn get_mut<T: CapObj>(&mut self, idx: usize) -> Result<&mut CapRef<T>, SysError> {
        self.try_get_mut(idx)
            .and_then(|o| o.as_mut().ok_or(SysError::SlotEmpty))
    }

    fn can_map(&self, addr: usize, depth: usize) -> Result<(), SysError> {
        let vpn = [
            (addr >> 12) & 0x1ff,
            (addr >> 21) & 0x1ff,
            (addr >> 30) & 0x1ff,
        ];
        let l2 = &self.0;
        match depth {
            34 => {
                if l2.entry(vpn[2]).valid() {
                    Err(SysError::SlotNotEmpty)
                } else {
                    Ok(())
                }
            }
            43 => {
                let l1 = l2.try_next_table(vpn[2]).ok_or(SysError::SlotEmpty)?;
                if l1.entry(vpn[1]).valid() {
                    Err(SysError::SlotNotEmpty)
                } else {
                    Ok(())
                }
            }
            52 => {
                let l1 = l2.try_next_table(vpn[2]).ok_or(SysError::SlotEmpty)?;
                let l0 = l1.try_next_table(vpn[1]).ok_or(SysError::SlotEmpty)?;
                if l0.entry(vpn[0]).valid() {
                    Err(SysError::SlotNotEmpty)
                } else {
                    Ok(())
                }
            }
            _ => Err(SysError::WrongAlign),
        }
    }

    fn map(
        &mut self,
        cap: CapRef<Mem>,
        addr: usize,
        depth: usize,
        prot: abi::Prot,
    ) -> Result<(), SysError> {
        let vpn = [
            (addr >> 12) & 0x1ff,
            (addr >> 21) & 0x1ff,
            (addr >> 30) & 0x1ff,
        ];
        let l2 = &mut self.0;
        match depth {
            34 => {
                let mut l2e = l2.entry_mut(vpn[2]);
                if l2e.valid() {
                    Err(SysError::SlotNotEmpty)
                } else {
                    *l2e = PageTableEntry::new(cap, prot);
                    Ok(())
                }
            }
            43 => {
                let mut l1 = l2.try_next_table_mut(vpn[2]).ok_or(SysError::SlotEmpty)?;
                let mut l1e = l1.entry_mut(vpn[1]);
                if l1e.valid() {
                    Err(SysError::SlotNotEmpty)
                } else {
                    *l1e = PageTableEntry::new(cap, prot);
                    Ok(())
                }
            }
            52 => {
                let mut l1 = l2.try_next_table_mut(vpn[2]).ok_or(SysError::SlotEmpty)?;
                let mut l0 = l1.try_next_table_mut(vpn[1]).ok_or(SysError::SlotEmpty)?;
                let mut l0e = l0.entry_mut(vpn[0]);
                if l0e.valid() {
                    Err(SysError::SlotNotEmpty)
                } else {
                    *l0e = PageTableEntry::new(cap, prot);
                    Ok(())
                }
            }
            _ => Err(SysError::WrongAlign),
        }
    }

    fn unmap(&mut self, addr: usize, depth: usize) -> Result<CapRef<Mem>, SysError> {
        let vpn = [
            (addr >> 12) & 0x1ff,
            (addr >> 21) & 0x1ff,
            (addr >> 30) & 0x1ff,
        ];
        let l2 = &mut self.0;
        match depth {
            34 => {
                let mut l2e = l2.entry_mut(vpn[2]);
                if l2e.valid() {
                    Ok(l2e.invalidate())
                } else {
                    Err(SysError::SlotNotEmpty)
                }
            }
            43 => {
                let mut l1 = l2.try_next_table_mut(vpn[2]).ok_or(SysError::SlotEmpty)?;
                let mut l1e = l1.entry_mut(vpn[1]);
                if l1e.valid() {
                    Ok(l1e.invalidate())
                } else {
                    Err(SysError::SlotNotEmpty)
                }
            }
            52 => {
                let mut l1 = l2.try_next_table_mut(vpn[2]).ok_or(SysError::SlotEmpty)?;
                let mut l0 = l1.try_next_table_mut(vpn[1]).ok_or(SysError::SlotEmpty)?;
                let mut l0e = l0.entry_mut(vpn[0]);
                if l0e.valid() {
                    Ok(l0e.invalidate())
                } else {
                    Err(SysError::SlotNotEmpty)
                }
            }
            _ => Err(SysError::WrongAlign),
        }
    }

    fn flush(&self) {
	    unsafe {
		    core::arch::asm!("sfence.vma");
	    }
    }
}

#[repr(transparent)]
struct CapRef<T>(CapRaw, PhantomData<T>);

impl<T: CapObj> core::ops::Deref for CapRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self.0 .0.offset(-(T::CAP_TYPE as isize))) }
    }
}

unsafe trait CapObj {
    const CAP_TYPE: CapType;
}

static INIT_TASK: Aligned<Task> = Aligned(Task {
    table: RwLock::new(Table(PageTable([PageTableEntry::zero(); 512]))),
    id: 1,
});
static mut L1_TABLE: Aligned<PageTable<1>> = Aligned(PageTable([PageTableEntry::zero(); 512]));
static mut L0_TABLE: Aligned<PageTable<0>> = Aligned(PageTable([PageTableEntry::zero(); 512]));

fn pmem_map() -> *mut u8 {
    let ret;
    unsafe {
        core::arch::asm!("li {}, 0xffffffc000000000", out(reg) ret);
    }
    ret
}

#[repr(isize)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CapType {
    NullCap,
    Untyped,
    TaskCap,
    MemCap,
    ConCap,
}

#[derive(Debug)]
struct CapRaw(*mut u8, usize);

impl CapRaw {
    fn from_mem<const N: usize>(mem: *mut Memory<N>) -> Self {
        unsafe {
            let ptr = mem as *mut u8;
            Self(ptr.add(CapType::MemCap as usize), N)
        }
    }

    fn ty(&self) -> CapType {
        unsafe { core::mem::transmute(self.0.addr() & 0xf) }
    }

    fn ptr(&self) -> *const u8 {
        unsafe { self.0.offset(-(self.ty() as isize)) }
    }

    fn mut_ptr(&mut self) -> *mut u8 {
        unsafe { self.0.offset(-(self.ty() as isize)) }
    }

    fn val(&self) -> usize {
        self.1
    }
}

#[repr(transparent)]
struct Untyped(CapRaw);

impl Untyped {
    fn try_from(raw: CapRaw) -> Result<Self, CapRaw> {
        match raw.ty() {
            CapType::Untyped => Ok(Self(raw)),
            _ => Err(raw),
        }
    }
}

#[repr(align(4096))]
#[repr(C)]
struct Memory<const N: usize>([u8; N]);

#[repr(align(4096))]
#[repr(C)]
struct Page([usize; 512]);

impl Page {
    const fn zero() -> Self {
        Self([0; 512])
    }
}

impl<const N: usize> Memory<N> {
    fn new() -> Self {
        Self([0; N])
    }
}

const PAGE_SIZE: usize = 0x1000;
const PAGE_MASK: usize = PAGE_SIZE - 1;

#[derive(Debug)]
#[repr(transparent)]
struct MemRef(CapRaw);

impl MemRef {
    fn new<T>(data: &mut [T]) -> Result<Self, ()> {
        let ptr = data.as_mut_ptr() as *mut u8;

        if (ptr.addr() & PAGE_MASK) > 0 {
            return Err(());
        }
        let ptr = unsafe { ptr.byte_add(CapType::MemCap as usize) };
        let sz = core::mem::size_of::<T>() * data.len();

        // round up to page size
        let sz = (sz + PAGE_SIZE) & !PAGE_MASK;

        Ok(Self(CapRaw(ptr, sz)))
    }

    fn split(self, n: usize) -> Result<(Self, Self), Self> {
        if (n & PAGE_MASK) > 0 {
            return Err(self);
        }
        let ptr = self.0 .0;
        let len = self.0 .1;
        Ok((
            Self(CapRaw(ptr, n)),
            Self(CapRaw(unsafe { ptr.byte_add(n) }, len - n)),
        ))
    }

    fn try_from(cap: CapRaw) -> Result<Self, CapRaw> {
        match cap.ty() {
            CapType::MemCap => Ok(Self(cap)),
            _ => Err(cap),
        }
    }

    fn size(&self) -> usize {
        self.0 .1
    }

    fn into_raw(self) -> CapRaw {
        self.0
    }

    fn invoke(self, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> Self {
        match a6 {
            1 => {
                let (a, b) = self.split(a1).unwrap();
                a
            }
            _ => panic!(),
        }
    }
}

#[repr(transparent)]
struct Table(PageTable<2>);

#[repr(C)]
struct Task {
    table: RwLock<Table>,
    id: usize,
}

impl Task {
    // const fn new() -> Self {
    // 	use core::sync::atomic::{AtomicUsize, Ordering};
    // 	const NEXT_TASK_ID: AtomicUsize = AtomicUsize::new(1);
    // 	Self {
    // 		table: RwLock::new(Table(PageTable([PageTableEntry::zero(); 512]))),
    // 		id: NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed),
    // 	}
    // }

    fn table(&self) -> &RwLock<Table> {
        &self.table
    }
}

impl PartialEq for Task {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Task {}

//type Task = RwLock<PageTable<2>>;

#[derive(Debug)]
#[repr(transparent)]
struct TaskRef<'a>(CapRaw, core::marker::PhantomData<&'a ()>);

#[derive(Clone, Copy, Eq, PartialEq)]
enum MapFlags {
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
    Read = 4,
    ReadWrite = 5,
    ReadExecute = 6,
    Execute = 7,
    Cap = 8,
}

fn prot_to_bits(prot: abi::Prot) -> usize {
    match prot {
        abi::Prot::Read => 0b10,
        abi::Prot::ReadWrite => 0b110,
        abi::Prot::Execute => 0b1000,
        abi::Prot::ReadExecute => 0b1010,
    }
}

impl MapFlags {
    fn get_prot(&self) -> usize {
        match self {
            Self::Read => 0b10,
            Self::ReadWrite | Self::Cap => 0b110,
            Self::ReadExecute => 0b1010,
            Self::Execute => 0b1000,
            _ => 0,
        }
    }

    fn valid_for_mem(&self) -> bool {
        match self {
            Self::Read => true,
            Self::ReadWrite => true,
            Self::ReadExecute => true,
            Self::Execute => true,
            Self::Level1 => true,
            Self::Level2 => true,
            _ => false,
        }
    }

    fn valid_for_cap(&self) -> bool {
        match self {
            Self::Cap => true,
            Self::Level1 => true,
            Self::Level2 => true,
            _ => false,
        }
    }
}

type SysResult = Result<(), core::num::NonZeroUsize>;

impl<'a> TaskRef<'a> {
    fn current() -> Self {
        let activation_value;
        unsafe {
            core::arch::asm!("csrr {}, satp", out(reg) activation_value);
        }
        let paddr = (activation_value & ((1 << 44) - 1)) << 12;
        let ptr = unsafe { pmem_map().add(paddr).add(CapType::TaskCap as usize) };
        Self(CapRaw(ptr, activation_value), core::marker::PhantomData)
    }

    fn root_table(&self) -> &mut PageTable<2> {
        unsafe { &mut *(self.0.ptr() as *mut PageTable<2>) }
    }

    fn paddr_of<T>(&self, addr: *const T) -> usize {
        // PROVINANCE: this is okay. we never dereference this.
        // we simply use this for looking up the paddr of some memory
        // the resulting paddr is only used for configuring page tables
        let addr = addr.addr();

        let vpn = [
            (addr >> 12) & 0x1ff,
            (addr >> 21) & 0x1ff,
            (addr >> 30) & 0x1ff,
        ];

        self.root_table()
            .entry_mut(vpn[2])
            .next_table_mut()
            .entry_mut(vpn[1])
            .next_table_mut()
            .entry_mut(vpn[0])
            .addr()
    }

    // TODO: not readable enough
    fn map_mem(&self, cap: CapRaw, pointer: *mut u8, map_flags: MapFlags) -> Result<(), CapRaw> {
        if pointer.align_offset(4096) != 0 {
            return Err(cap);
        }

        let cap = {
            let mem = MemRef::try_from(cap)?;
            if mem.size() > 0x1000 {
                Err(mem.into_raw())
            } else {
                Ok(mem.into_raw())
            }?
        };

        let addr = pointer.addr();

        let vpn = [
            (addr >> 12) & 0x1ff,
            (addr >> 21) & 0x1ff,
            (addr >> 30) & 0x1ff,
        ];

        if (pointer.addr() >> 63) == 0 {
            let l2_entry = self.root_table().entry_mut(vpn[2]);
            if map_flags == MapFlags::Level2 {
                if l2_entry.valid() {
                    Err(cap)
                } else {
                    let mem = MemRef::try_from(cap)?;
                    *l2_entry = PageTableEntry(
                        ((TaskRef::current().paddr_of(mem.0.ptr()) >> 12) << 10) | 0b1,
                    );
                    Ok(())
                }
            } else {
                if l2_entry.valid() {
                    let l1_entry = l2_entry.next_table_mut().entry_mut(vpn[1]);

                    if map_flags == MapFlags::Level1 {
                        if l1_entry.valid() {
                            Err(cap)
                        } else {
                            let mem = MemRef::try_from(cap)?;
                            *l1_entry = PageTableEntry(
                                ((TaskRef::current().paddr_of(mem.0.ptr()) >> 12) << 10) | 0b1,
                            );
                            Ok(())
                        }
                    } else {
                        if l1_entry.valid() {
                            let l0_entry = l1_entry.next_table_mut().entry_mut(vpn[0]);
                            let prot_bits = map_flags.get_prot();
                            if prot_bits == 0 {
                                Err(cap)
                            } else {
                                if l0_entry.valid() {
                                    Err(cap)
                                } else {
                                    let mem = MemRef::try_from(cap)?;
                                    *l0_entry = PageTableEntry(
                                        ((TaskRef::current().paddr_of(mem.0.ptr()) >> 12) << 10)
                                            | 0b10001
                                            | prot_bits,
                                    );
                                    Ok(())
                                }
                            }
                        } else {
                            Err(cap)
                        }
                    }
                } else {
                    Err(cap)
                }
            }
        } else {
            eprintln!("can't map higher half; that's the kernel's job silly!");
            Err(cap)
        }
    }

    fn map_cap(&mut self, cap: CapRaw, cap_addr: usize, map_flags: MapFlags) -> Result<(), CapRaw> {
        unsafe {
            let cap_base: *mut Option<CapRaw> =
                core::ptr::from_exposed_addr_mut(0xffffffe000000000);
            let cap_ptr = cap_base.add(cap_addr);
        }
        // capabilities can be mapped in the memory range
        // -128GiB -> -64GiB
        const CAP_L2_VPN: usize = 0x180;

        let vpn = [
            (cap_addr >> 8) & 0x1ff,
            (cap_addr >> 17) & 0x1ff,
            (cap_addr >> 26) & 0x1ff,
        ];

        if cap_addr < 0x800000000 {
            let l2_entry = self.root_table().entry_mut(CAP_L2_VPN + vpn[2]);
            if map_flags == MapFlags::Level2 {
                if l2_entry.valid() {
                    Err(cap)
                } else {
                    let mem = MemRef::try_from(cap)?;
                    *l2_entry = PageTableEntry(
                        ((TaskRef::current().paddr_of(mem.0.ptr()) >> 12) << 10) | 0b1,
                    );
                    Ok(())
                }
            } else {
                if l2_entry.valid() {
                    let l1_entry = l2_entry.next_table_mut().entry_mut(vpn[1]);

                    if map_flags == MapFlags::Level1 {
                        if l1_entry.valid() {
                            Err(cap)
                        } else {
                            let mem = MemRef::try_from(cap)?;
                            *l1_entry = PageTableEntry(
                                ((TaskRef::current().paddr_of(mem.0.ptr()) >> 12) << 10) | 0b1,
                            );
                            Ok(())
                        }
                    } else {
                        if l1_entry.valid() {
                            let l0_entry = l1_entry.next_table_mut().entry_mut(vpn[0]);
                            let prot_bits = map_flags.get_prot();
                            if prot_bits == 0 {
                                Err(cap)
                            } else {
                                if l0_entry.valid() {
                                    Err(cap)
                                } else {
                                    let mem = MemRef::try_from(cap)?;
                                    *l0_entry = PageTableEntry(
                                        ((TaskRef::current().paddr_of(mem.0.ptr()) >> 12) << 10)
                                            | 0b1
                                            | MapFlags::ReadWrite.get_prot(),
                                    );
                                    Ok(())
                                }
                            }
                        } else {
                            Err(cap)
                        }
                    }
                } else {
                    Err(cap)
                }
            }
        } else {
            Err(cap)
        }
    }

    fn flush() {
        // TODO: only flush specific ASID
        unsafe {
            core::arch::asm!("sfence.vma");
        }
    }

    fn is_mapped(self, ptr: *const ()) -> bool {
        todo!();
    }

    pub fn get_cap(&mut self, idx: usize) -> &mut Option<CapRaw> {
        // SAFETY: dereferencing of an unmapped address results in a page fault which is caught
        // and passed on to userspace.
        unsafe {
            &mut *core::ptr::from_exposed_addr_mut::<Option<CapRaw>>(0xffffffe000000000).add(idx)
        }
    }
}

#[repr(align(4096))]
#[repr(C)]
struct Stack([usize; 512 * 16]);
static STACK: Stack = Stack([0; 512 * 16]);

#[repr(C)]
#[derive(Clone, Copy)]
struct TaskCall {
    satp: core::num::NonZeroUsize,
    sepc: usize,
}

#[repr(align(4096))]
#[repr(C)]
struct Aligned<T>(T);

//#[repr(align(4096))]
#[repr(C)]
struct Thread {
    stack: [usize; 512 * 4],
    call_depth: usize,
    ra: usize,
    sp: usize,
    gp: usize,
    tp: usize,
    t0: usize,
    t1: usize,
    t2: usize,
    s0: usize,
    s1: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    t3: usize,
    t4: usize,
    t5: usize,
    t6: usize,
    calls: [Option<TaskCall>; 256],
}

impl Thread {
    fn new() -> Self {
        Self {
            call_depth: 0,
            ra: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            t0: 0,
            t1: 0,
            t2: 0,
            s0: 0,
            s1: 0,
            a0: 0,
            a1: 0,
            a2: 0,
            a3: 0,
            a4: 0,
            a5: 0,
            a6: 0,
            a7: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
            t3: 0,
            t4: 0,
            t5: 0,
            t6: 0,
            stack: [0; 512 * 4],
            calls: [None; 256],
        }
    }

    fn push(&mut self, call: TaskCall) {
        self.calls[self.call_depth] = Some(call);
        self.call_depth += 1;
    }

    fn switch(&mut self, interval: usize) {
        // scheduler threads do not have the timer enabled
        // we enable it as we activate the target thread.
        enable_timer();
        set_time(get_time() + interval);
        self.activate();
    }

    fn activate(&mut self) -> ! {
        if self.call_depth == 0 {
            panic!("tried to activate a thread with no tasks");
        }
        unsafe {
            self.call_depth -= 1;
            let task = self.calls[self.call_depth].unwrap();
            core::arch::asm!(
                "li t5, 0x00000100",
                "csrc sstatus, t5",
                "csrw sepc, {sepc}",
                "csrw satp, {satp}",
                "csrw sscratch, t6",
                // "addi t6, t6, -256",
                "ld ra, (8 * 1)(t6)",
                "ld sp, (8 * 2)(t6)",
                "ld gp, (8 * 3)(t6)",
                "ld tp, (8 * 4)(t6)",
                "ld t0, (8 * 5)(t6)",
                "ld t1, (8 * 6)(t6)",
                "ld t2, (8 * 7)(t6)",
                "ld s0, (8 * 8)(t6)",
                "ld s1, (8 * 9)(t6)",
                "ld a0, (8 * 10)(t6)",
                "ld a1, (8 * 11)(t6)",
                "ld a2, (8 * 12)(t6)",
                "ld a3, (8 * 13)(t6)",
                "ld a4, (8 * 14)(t6)",
                "ld a5, (8 * 15)(t6)",
                "ld a6, (8 * 16)(t6)",
                "ld a7, (8 * 17)(t6)",
                "ld s2, (8 * 18)(t6)",
                "ld s3, (8 * 19)(t6)",
                "ld s4, (8 * 20)(t6)",
                "ld s5, (8 * 21)(t6)",
                "ld s6, (8 * 22)(t6)",
                "ld s7, (8 * 23)(t6)",
                "ld s8, (8 * 24)(t6)",
                "ld s9, (8 * 25)(t6)",
                "ld s10, (8 * 26)(t6)",
                "ld s11, (8 * 27)(t6)",
                "ld t3, (8 * 28)(t6)",
                "ld t4, (8 * 29)(t6)",
                "ld t5, (8 * 30)(t6)",
                "ld t6, (8 * 31)(t6)",
                "sfence.vma",
                "sret",
                sepc = in(reg) task.sepc,
                satp = in(reg) task.satp.get(),
                in("t6") &mut self.call_depth,
                options(noreturn)
            )
        }
    }
}

// usage of initial space
//
//
// +       0 - firmware
// +  200000 - start of code
// +code_end -
#[naked]
#[link_section = ".text._start"]
#[no_mangle]
unsafe extern "C" fn _start() {
    core::arch::asm!(
        // Linux header
        // MZ magic
        "c.li s4, -13",
        // jump to after headers
        "j 1f",
        ".align 3",
        ".quad 0x200000",
        ".quad krnl_size",
        ".quad 0",
        ".word 2",
        ".word 0",
        ".quad 0",
        ".quad 0x5643534952",
        ".word 0x05435352",
        // TODO: used for EFI
        ".word 0",
    "1:",
        "la t0, 2f",
        "li a6, 0",
        "li a7, 1",
    "1:",
        "lb a0, 0(t0)",
        "addi t0, t0, 1",
        "beqz a0, 1f",
        "ecall",
        "j 1b",
    "2:",
        ".ascii \"\\nConifer Boot Stub\\n\\0\"",
    "1:",
        // load physical address of kernel base
        "la t3, _start",
        // load page table addresses
        "la t2, {l2_table}",
        "la t1, {l1_table}",
        "la t0, {l0_table}",
        // fill out l0 table
        // t3 = pte
        // t4 = index
        // t5 = table addr
        // set index to 512
        "li t4, 512",
        // set pte bits
        "srli t3, t3, 12",
        "slli t3, t3, 10",
        // set rwx and valid
        "ori t3, t3, 0b1111",
        // put table address in t5 so we can use it again later
        "mv t5, t0",
    "1:",
        // while t4 > 0
        "beqz t4, 1f",

        "sd t3, 0(t5)",

        // t4 += -1
        "addi t4, t4, -1",
        // next pte
        "addi t5, t5, 8",
        // inc address in pte
        "addi t3, t3, 0x400",

        // progress indicator
        "li a0, '.'",
        "ecall",
        "j 1b",
    "1:",
        "li a0, '\n'",
        "ecall",
        "srli t0, t0, 12",
        "slli t0, t0, 10",
        "ori t0, t0, 1",
        "sd t0, 0(t1)",

        "srli t1, t1, 12",
        "slli t1, t1, 10",
        "ori t1, t1, 1",

        "li t6, 0xff8",
        "add t6, t6, t2",
        "sd t1, 0(t6)",

        // load next address
        "lui t6, %hi(1f)",
        "addi t6, t6, %lo(1f)",
        "csrw stvec, t6",

        // format page table address for satp
        "srli t2, t2, 12",
        "li t6, 1<<63",
        "or t2, t2, t6",

        "csrw satp, t2",
        "sfence.vma",
        ".align 2",
    "1:",
        "la sp, {stack}",
        "li t0, 0x40000",
        "add sp, sp, t0",
        "addi sp, sp, -8",
        "li a0, '\n'",
        "ecall",
        "tail {rust_start}",
        options(noreturn),
        l2_table = sym INIT_TASK,
        l1_table = sym L1_TABLE,
        l0_table = sym L0_TABLE,
        rust_start = sym rust_start,
        stack = sym STACK,
    );
}

extern "C" fn rust_start(hart: usize, fdt: usize) -> ! {
    eprintln!("Conifer Kernel");
    eprintln!("\thart: {:x}", hart);
    eprintln!("\t fdt: {:x}", fdt);
    eprintln!();

    eprintln!("Building Initial Task");
    eprintln!("\tfilling physical memory map");
    unsafe {
        core::arch::asm!(
            "la {temp}, {}",
            "csrw stvec, {temp}",
            sym init_trap, temp = out(reg) _
        );
    }
    // map all physical memory (well only 128GiB of it)
    // with other modes (sv48, sv57) we can map more.
    {
        let mut guard = INIT_TASK.0.table().write();
        (*guard).0.fill_pmap();
        drop(guard);
    }

    unsafe {
        core::arch::asm!("sfence.vma");
    }
    eprintln!("\tmapping initial capability space");
    let mut cap_table_mem = core::array::from_fn::<_, { 2 + 1 }, _>(|_| Page::zero());
    let mut cap_table_mem_cap = MemRef::new(&mut cap_table_mem).unwrap();
    let (cap_table_l1_cap, cap_table_mem_cap) = cap_table_mem_cap.split(PAGE_SIZE).unwrap();
    let (cap_table_l0_cap, cap_table_mem_cap) = cap_table_mem_cap.split(PAGE_SIZE).unwrap();
    let (cap_table_mem_cap, _) = cap_table_mem_cap.split(PAGE_SIZE).unwrap();

    // map an initial capability space of 256 capabilities.
    TaskRef::current()
        .map_cap(cap_table_l1_cap.into_raw(), 0, MapFlags::Level2)
        .unwrap();
    TaskRef::current()
        .map_cap(cap_table_l0_cap.into_raw(), 0, MapFlags::Level1)
        .unwrap();
    TaskRef::current()
        .map_cap(cap_table_mem_cap.into_raw(), 0, MapFlags::Cap)
        .unwrap();

    eprintln!("\tmapping initial task memory");
    let mut init_l1_mem = Memory::<0x1000>::new();
    let init_l1_cap = CapRaw::from_mem(&mut init_l1_mem);
    let mut init_l0_mem = Memory::<0x1000>::new();
    let init_l0_cap = CapRaw::from_mem(&mut init_l0_mem);

    let mut init_l1_stack_mem = Memory::<0x1000>::new();
    let init_l1_stack_cap = CapRaw::from_mem(&mut init_l1_stack_mem);
    let mut init_l0_stack_mem = Memory::<0x1000>::new();
    let init_l0_stack_cap = CapRaw::from_mem(&mut init_l0_stack_mem);

    let mut init_code_cap = MemRef::new(unsafe { &mut crate::_init }).unwrap();
    let init_start_ptr = core::ptr::from_exposed_addr_mut::<u8>(0x0);
    let init_entry_ptr = unsafe { init_start_ptr.byte_add(PAGE_SIZE) };

    TaskRef::current()
        .map_mem(init_l1_cap, init_start_ptr, MapFlags::Level2)
        .unwrap();
    TaskRef::current()
        .map_mem(init_l0_cap, init_start_ptr, MapFlags::Level1)
        .unwrap();

    let mut init_code_ptr = init_start_ptr;
    while init_code_cap.size() >= PAGE_SIZE {
        let (a, b) = init_code_cap.split(PAGE_SIZE).unwrap();
        TaskRef::current()
            .map_mem(a.into_raw(), init_code_ptr, MapFlags::ReadExecute)
            .unwrap();
        init_code_cap = b;
        unsafe {
            init_code_ptr = init_code_ptr.byte_add(PAGE_SIZE);
        }
    }

    let mut init_stack_mem = Memory::<0x1000>::new();
    let init_stack_cap = CapRaw::from_mem::<0x1000>(&mut init_stack_mem);

    unsafe {
        let init_stack_ptr: *mut u8 = core::ptr::from_exposed_addr_mut(0x4000000000);
        TaskRef::current()
            .map_mem(
                init_l1_stack_cap,
                init_stack_ptr.offset(-0x1000),
                MapFlags::Level2,
            )
            .unwrap();
        TaskRef::current()
            .map_mem(
                init_l0_stack_cap,
                init_stack_ptr.offset(-0x1000),
                MapFlags::Level1,
            )
            .unwrap();
        TaskRef::current()
            .map_mem(
                init_stack_cap,
                init_stack_ptr.offset(-0x1000),
                MapFlags::ReadWrite,
            )
            .unwrap();
    }

    unsafe {
        let cap_base: *mut Option<CapRaw> = core::ptr::from_exposed_addr_mut(0xffffffe000000000);
        let cap_0: &mut Option<CapRaw> = &mut *cap_base;
        cap_0.replace(CapRaw(
            core::ptr::from_exposed_addr_mut(CapType::ConCap as usize),
            0,
        ));
        let cap_1: &mut Option<CapRaw> = &mut *cap_base.add(1);
        cap_1.replace(TaskRef::current().0);
        let cap_2: &mut Option<CapRaw> = &mut *cap_base.add(2);
        cap_2.replace(CapRaw(
            // memory range starts at 0
            core::ptr::from_exposed_addr_mut(CapType::MemCap as usize),
            // sv39 supports up to 56 bits of physical addresses.
            1 << 56,
        ));
    }
    unsafe {
        core::arch::asm!("sfence.vma");
    }

    eprintln!();
    eprintln!("\tcreating initial thread");
    let mut thread = {
        let aligned = Aligned(Thread::new());
        aligned.0
    };
    let satp;
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) satp);
    }
    let call = TaskCall {
        satp: core::num::NonZeroUsize::new(satp).unwrap(),
        sepc: init_entry_ptr.addr(),
    };

    thread.push(call);

    unsafe {
        core::arch::asm!(
            "la {temp}, {}",
            "csrw stvec, {temp}",
            sym _trap, temp = out(reg) _
        );
    }

    thread.sp = 0x4000000000;
    thread.a0 = fdt;

    eprintln!("\tactivating initial thread");
    eprintln!("\ttime: {}", get_time());
    // let t = get_time();
    // set_time(t + 0x10000);
    // enable_timer();
    thread.activate();

    loop {
        wait()
    }
}

#[repr(transparent)]
struct ConRef(CapRaw);

impl ConRef {
    const WRITE: usize = 2;

    #[inline(always)]
    fn write(&self, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) {
        for a in [a1, a2, a3, a4, a5, a6] {
            for b in a.to_ne_bytes() {
                if b == 0 {
                    return;
                }
                putchar(b);
            }
        }
    }

    #[inline(never)]
    fn invoke(&self, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) {
        match a7 {
            Self::WRITE => self.write(a1, a2, a3, a4, a5, a6),
            _ => todo!("Error handling"),
        }
    }
}

struct Con;

unsafe impl CapObj for Con {
    const CAP_TYPE: CapType = CapType::ConCap;
}

impl Con {
    fn write(con: &Con, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) {
        for a in [a1, a2, a3, a4, a5] {
            for b in a.to_ne_bytes() {
                if b == 0 {
                    return;
                }
                putchar(b);
            }
        }
    }
}

fn current_task<'a>() -> &'a Task {
    let activation_value: usize;
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) activation_value);
    }
    let paddr = (activation_value & ((1 << 44) - 1)) << 12;
    let ptr = unsafe { pmem_map().add(paddr) };
    unsafe { core::mem::transmute(ptr) }
}

enum Mem {}
unsafe impl CapObj for Mem {
    const CAP_TYPE: CapType = CapType::MemCap;
}

unsafe impl CapObj for Task {
    const CAP_TYPE: CapType = CapType::TaskCap;
}

impl<T: CapObj> CapRef<T> {
    fn ptr(&self) -> *mut T {
        unsafe { self.0 .0.byte_offset(-(T::CAP_TYPE as usize as isize)) as *mut T }
    }

    fn into_raw(self) -> CapRaw {
        self.0
    }
}

impl CapRef<Mem> {
    fn new(ptr: *mut Mem, len: usize) -> Self {
        Self(
            CapRaw(
                unsafe { ptr.byte_add(Mem::CAP_TYPE as usize) as *mut u8 },
                len,
            ),
            core::marker::PhantomData,
        )
    }

    fn len(&self) -> usize {
        self.0 .1
    }
}

fn syscall(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    thread: &mut Thread,
    syscall: Syscall,
) -> Result<(), SysError> {
    let task = current_task();
    let table = task.table();
    match syscall {
        Syscall::CapIdentify => {
            let guard = table.read();
            let cap = guard.get_raw(a0);
            eprintln!("{:?}:{:#?}", cap.as_ref().map(|c| c.ty()), cap);
            Ok(())
        }
        Syscall::ConWrite => {
            let guard = table.read();
            let con = guard.get::<Con>(a0)?;
            Con::write(&*con, a1, a2, a3, a4, a5);
            Ok(())
        }
        Syscall::MemSplit => {
            let mut guard = table.write();
            let line = a2;
            eprintln!("line: {:x}", line);
            if (line & PAGE_MASK) > 0 {
                return Err(SysError::InvalidCall);
            }

            if guard.try_get::<Mem>(a1)?.is_some() {
                return Err(SysError::SlotNotEmpty);
            }

            let (base, len) = {
                let mut mem_a = guard.get_mut::<Mem>(a0)?;
                let base = mem_a.ptr();
                let len = mem_a.len();
                *mem_a = CapRef::<Mem>::new(base, line);
                (base, len)
            };

            let mut mem_b = guard.try_get_mut::<Mem>(a1)?;
            mem_b.replace(CapRef::<Mem>::new(
                unsafe { base.byte_add(line) },
                len - line,
            ));
            Ok(())
        }
        Syscall::TaskMapMem => {
            let task_cap_addr = a0;
            let mem_cap_addr = a1;
            let map_addr = a2;
            let map_level = a3;
            let prot = abi::Prot::try_from(a4)?;
            let mut guard = table.write();
            let other_guard;
            let mut guard = {
                let mem = guard.get::<Mem>(mem_cap_addr)?;

                if mem.len() != PAGE_SIZE {
                    return Err(SysError::WrongSize);
                }

                let cur_task = task;
                let task = guard.get::<Task>(task_cap_addr)?;
                if cur_task.eq(task) {
                    guard
                } else {
                    other_guard = task.table().write();
                    other_guard
                }
            };
            guard.can_map(map_addr, map_level)?;
            let mem = {
                let mem = guard.try_get_mut::<Mem>(mem_cap_addr)?;
                mem.take().unwrap()
            };
            guard.map(mem, map_addr, map_level, prot).unwrap();
            guard.flush();
            Ok(())
        }
        Syscall::TaskUnmapMem => {
            let task_cap_addr = a0;
            let mem_cap_addr = a1;
            let map_addr = a2;
            let map_level = a3;
            let mut guard = table.write();
            let other_guard;
            let mut guard = {
                let mem = guard.try_get::<Mem>(mem_cap_addr)?;
                if mem.is_some() {
                    return Err(SysError::SlotNotEmpty);
                }

                let cur_task = task;
                let task = guard.get::<Task>(task_cap_addr)?;
                if cur_task.eq(task) {
                    guard
                } else {
                    other_guard = task.table().write();
                    other_guard
                }
            };

            let mem = guard.unmap(map_addr, map_level)?;
            guard.flush();
            let mut mem_cap = guard.try_get_mut::<Mem>(mem_cap_addr)?;
            mem_cap.replace(mem);

            Ok(())
        }
        _ => Err(SysError::InvalidCall),
    }
}

// entry point from an ecall
// a0: the capability address
// a1-a5: arguments
// a6: current thread but offset to stack base.
// a7: the capability function index
unsafe extern "C" fn syscall_entry(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: *mut Thread,
    a7: usize,
) -> usize {
    let thread = a6.offset(-(core::mem::offset_of!(Thread, call_depth) as isize));
    let ret = syscall(a0, a1, a2, a3, a4, a5, &mut *thread, Syscall(a7));
    match ret {
        Ok(_) => 0,
        Err(e) => e as usize,
    }
}

// trap vector used before switching to userspace
#[naked]
#[repr(align(4))]
unsafe extern "C" fn init_trap() {
    core::arch::asm!("wfi", options(noreturn))
}

const TIME_FREQ_MS: usize = 10000;

// This is not a Thread sleep. This is a highly privalidged operation that
// sleeps the whole hart. The only Task that should have that capability is
// the scheduler task.
//
// The hart can be awoken early by other interupts such as software interupts.
// which should be used by the scheduling task to communicate between its
// threads.
fn sleep_ms(ms: usize) {
    set_time(get_time() + TIME_FREQ_MS * ms);
    unsafe {
        core::arch::asm!("wfi");
    }
}

extern "C" fn timer() -> ! {
    set_time(get_time() + TIME_FREQ_MS * 1000);
    eprintln!("{:#x?}", TaskRef::current());
    panic!("timer handler for hart 0 not set");
}

#[naked]
#[repr(align(4))]
unsafe extern "C" fn _trap() {
    core::arch::asm!(
        "csrrw sp, sscratch, sp",
        "sd ra, 8(sp)",
        "csrr ra, scause",
        "bltz ra, 3f",
        "addi ra, ra, -8",
        "bnez ra, 2f",
        // ecall from U
        "bltz a7, 1f",
        // Personality call
        "slli a7, a7, 2",
        "csrrw a7, sepc, a7",
        "ld ra, 8(sp)",
        "csrrw sp, sscratch, sp",
        "sret",
    "1:",
        // Conifer call
        "neg a7, a7",
        "mv a6, sp",
        "call {syscall}",
        "csrr ra, sepc",
        "addi ra, ra, 4",
        "csrw sepc, ra",
        "ld ra, 8(sp)",
        "csrrw sp, sscratch, sp",
        "sret",
    "2:",
        "wfi",
        "addi t6, t6, 8",
        "j 2b",
        "sret",
    "3:",
        "csrr ra, sscratch",
        "sd ra, 16(sp)",

        "sd gp, 24(sp)",
        "sd tp, 32(sp)",

        "sd t0, 40(sp)",
        "sd t1, 48(sp)",
        "sd t2, 56(sp)",

        "sd s0, 64(sp)",
        "sd s1, 72(sp)",

        "sd a0, 80(sp)",
        "sd a1, 88(sp)",
        "sd a2, 96(sp)",
        "sd a3, 104(sp)",
        "sd a4, 112(sp)",
        "sd a5, 120(sp)",
        "sd a6, 128(sp)",
        "sd a7, 136(sp)",

        "sd s2, 144(sp)",
        "sd s3, 152(sp)",
        "sd s4, 160(sp)",
        "sd s5, 168(sp)",
        "sd s6, 176(sp)",
        "sd s7, 184(sp)",
        "sd s8, 192(sp)",
        "sd s9, 180(sp)",
        "sd s10, 188(sp)",
        "sd s11, 196(sp)",

        "sd t3, 224(sp)",
        "sd t4, 232(sp)",
        "sd t5, 240(sp)",
        "sd t6, 248(sp)",

        "tail {timer}",

        options(noreturn),
        syscall = sym syscall_entry,
        timer = sym timer,
    );
}
