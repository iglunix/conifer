use crate::println;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Page {
    Empty,
    Taken,
    Last,
}

pub static mut ALLOC_START: usize = 0;
const PAGE_ORDER: usize = 12;
pub const PAGE_SIZE: usize = 1 << 12;

#[repr(transparent)]
pub struct PageDescTable(pub &'static mut [Page]);

impl PageDescTable {
    pub fn init() -> Self {
        unsafe {
            let num_pages = crate::boot::HEAP_SIZE / PAGE_SIZE;
            let ptr = crate::boot::HEAP_START as *mut Page;
            ALLOC_START = (crate::boot::HEAP_START
                + num_pages * core::mem::size_of::<Page>()
                + (1 << PAGE_ORDER)
                - 1)
                & !((1 << PAGE_ORDER) - 1);

            let ret = core::slice::from_raw_parts_mut(ptr, num_pages);
            PageDescTable(ret)
        }
    }

    pub fn clear(&mut self) {
        self.0.iter_mut().for_each(|p| *p = Page::Empty);
    }

    pub fn dump(&self) {
        let mut in_block = false;
        let mut count = 0;
        self.0.iter().for_each(|p| match (in_block, p) {
            (false, Page::Taken) => {
                in_block = true;
                count += 1;
            }
            (true, Page::Taken) => {
                count += 1;
            }
            (_, Page::Last) => {
                count += 1;
                println!("block {}", count);
                count = 0;
            }
            _ => {}
        });
    }

    pub fn alloc<T>(&mut self, pages: usize) -> *mut T {
        use crate::eprintln;
        if pages > 0 {
            let mut count = 0;
            let mut start_index = 0;
            self.0.iter().enumerate().for_each(|(i, p)| match p {
                Page::Empty => {
                    if count == 0 {
                        start_index = i;
                    }
                    count += 1
                }

                _ => count = 0,
            });

            if count >= pages {
                for i in start_index..start_index + pages - 1 {
                    self.0[i] = Page::Taken;
                }
                self.0[start_index + pages - 1] = Page::Last;
                (unsafe { ALLOC_START } + PAGE_SIZE * start_index) as *mut T
            } else {
                core::ptr::null_mut()
            }
        } else {
            core::ptr::null_mut()
        }
    }
}

pub fn alloc(pages: usize) -> *mut u8 {
    assert!(pages > 0);
    core::ptr::null_mut()
}
