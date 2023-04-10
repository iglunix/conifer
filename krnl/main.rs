#![feature(naked_functions)]
#![no_std]
#![no_main]

#[macro_use]
extern crate con;

extern crate alloc;

struct Mapping {
    paddr: usize,
    vaddr: usize,
    size: usize,
    read: bool,
    write: bool,
    exec: bool,
    user: bool
}

struct Map();

struct Mem {
    // Mappings shared between a thread group
    group_map: Map,
    local_map: Map,

    // Mappings
    global_map: Map
}

struct Task {

}

// 15 buddy levels means 2^15 * 8 pages which means 1gb of ram
// 2^32 entries
//
// 16: 1111_0000
// 15: 11111111_10100000
// 14: 1111111111111111_1110111010100000
struct Buddy {
    // buddy_bases: [*mut u8; 15],
    // // shift 1 << base_buddy_size
    // // since base size is always a power of 2
    // base_buddy_size: u8,
    buddies: [&'static mut [u8]; 16]
}

impl Buddy {
    fn init() -> Self {
        let mut ret = Self::get();

        // Fill in buddies 1..16 with information
        for i in 1..16 {
            println!("level: {:x}", ret.level_len(i));
            for j in 0..ret.level_len(i) {
                let j20 = (j << 1) + 0;
                let j21 = (j << 1) + 1;
                if ret.bud_get(i - 1, j20) && ret.bud_get(i - 1, j21) {
                    ret.bud_set(i, j, true);
                } else {
                    ret.bud_set(i, j, false);
                }
            }
        }
        let mut start = None;
        for i in 0..ret.level_len(0) {
            if ret.bud_get(0, i) {
                if start.is_none() {
                    start = Some(i << 12);
                }
            } else {
                if start.is_some() {
                    println!("reserved: {:x}->{:x}", start.unwrap() + 0x80000000, (i << 12) + 0x80000000);
                    start = None
                }
            }
        }

        ret
    }

    fn get() -> Self {
        let base = 0xffffffff_00000000_usize;
        let base_len = 1 << 15;

        let buddies: [&'static mut [u8]; 16] = core::array::from_fn(|i| {
            let addr = base + ((base_len - (base_len >> (i))) << 1);
            let addr = addr as *mut u8;
            let len = base_len >> i;

            unsafe { core::slice::from_raw_parts_mut(addr, len) }
        });

        Self {
            buddies
        }
    }

    // idx is the local idx not idx into base buddy
    fn bud_get(&self, level: usize, idx: usize) -> bool {
        let block = self.buddies[level][idx >> 3]; // divide by 8 since we fit 8 bits ina block
        (block & (1 << (idx & 0b111))) > 0
    }

    fn bud_set(&mut self, level: usize, idx: usize, val: bool) {
        let block = &mut self.buddies[level][idx >> 3]; // divide by 8 since we fit 8 bits ina block
        if val {
           *block = *block | (1 << (idx & 0b111));
        } else {
           *block = *block & !(1 << (idx & 0b111));
        }
    }

    fn level_len(&self, level: usize) -> usize {
        (self.buddies[0].len() * 8) >> level
    }

    fn alloc(&mut self) -> usize {
        let mut page_idx = 0;
        let mut level = 15;

        while level > 0 {
            if self.bud_get(level, page_idx) {
                page_idx += 1;
                if page_idx == self.level_len(level) {
                    panic!("OOM: {}:{:x}:{:#?}", level, page_idx, &self.buddies[1][0..16]);
                }
            } else {
                level -= 1;
                page_idx = page_idx << 1;
            }
        }
        let ret = page_idx << 12;

        self.bud_set(level, page_idx, true);
        page_idx = page_idx >> 1;
        level += 1;
        while level < self.buddies.len() {
            let j20 = (page_idx << 1) + 0;
            let j21 = (page_idx << 1) + 1;
            if self.bud_get(level - 1, j20) && self.bud_get(level - 1, j21) {
                self.bud_set(level, page_idx, true);
            }
            level += 1;
            page_idx = page_idx >> 1;
        }

        0x80000000 + ret
    }

    fn free(&mut self, addr: usize) {
        let addr = addr - 0x80000000;
        let mut page_idx = addr >> 12;
        let mut level = 0;

        if !self.bud_get(level, page_idx) {
            eprintln!("Double Free Detected!");
        }
        self.bud_set(level, page_idx, false);
        page_idx = page_idx >> 1;
        level += 1;
        while level < self.buddies.len() {
            let j20 = (page_idx << 1) + 0;
            let j21 = (page_idx << 1) + 1;
            if !(self.bud_get(level - 1, j20) && self.bud_get(level - 1, j21)) {
                self.bud_set(level, page_idx, false);
            }
            level += 1;
            page_idx = page_idx >> 1;
        }
    }
}

static mut HEAP_BF: [u8; 0x100] = [0; 0x100];
struct TinyAlloc;
#[global_allocator]
static GLOBAL: TinyAlloc = TinyAlloc;
unsafe impl alloc::alloc::GlobalAlloc for TinyAlloc {
    unsafe fn alloc(&self, layout: alloc::alloc::Layout) -> *mut u8 {
        let heap_bf = unsafe { &mut HEAP_BF };
        // No allocations can be larger than 128 MiB
        if layout.size() > (1 << 27) {
            panic!("Allocation too big");
        }
        let req_pages = (layout.size() + 0xfff) >> 12;
        let mut free_block = 0;
        while heap_bf[free_block] == 255 && free_block < heap_bf.len()  {
            free_block += 1
        }

        let mut idx = 0;
        while (((heap_bf[free_block] >> idx) & 1) == 0b1)  && idx < 8 {
            idx += 1
        }
        heap_bf[free_block] |= 1 << idx;
        idx |= free_block << 3;

        let addr = (idx << 27) + 0xffffffd0_00000000_usize;
        let mut buddy = Buddy::get();
        for i in 0..req_pages {
            buddy.alloc();
            // todo: map
        }

        println!("alloc addr {:x}", addr);
        addr as *mut u8
    }

    unsafe fn realloc(&self, addr: *mut u8, layout: alloc::alloc::Layout, new_size: usize) -> *mut u8 {
        // We can always realloc in place. just need to alloc and map more pages
        addr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::alloc::Layout) {
        let addr = ptr as usize;
        let addr = addr - 0xffffffd0_00000000_usize;
        let idx = addr >> 27;
        let block_idx = idx >> 3;
        let idx = idx & 0b11;
        let heap_bf = unsafe { &mut HEAP_BF };
        heap_bf[block_idx] &= !(1 << idx);
        // TODO: lookup paddr in page table and dealloc
    }
}

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

#[no_mangle]
#[naked]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!("tail {}", sym entry,
        options(noreturn)
    );
}

extern "C" fn entry(fdt_addr: usize, buddy_addr: usize) {
    println!("fdt: {:x}", fdt_addr);
    println!("buddy: {:x}", buddy_addr);
    main();
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

fn main() {
    // initialise the buddy allocator
    let mut buddy = Buddy::init();
    let addr = buddy.alloc();
    buddy.free(addr);

    let mut s = alloc::string::String::new();
    s.push('a');
    s.push('b');
    s.push('c');
}
