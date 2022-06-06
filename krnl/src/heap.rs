use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/* TODO: not thread safe */
pub struct Heap<'a> {
    mem: *mut [u8; 4096],
    next_page: AtomicUsize,
    terminate: usize,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl Heap<'static> {
    pub fn set_global(mem: &'static mut [[u8; 4096]]) {
        unsafe {
            GLOBAL_HEAP = Self::new(mem);
        }
    }
}

impl<'a> Heap<'a> {
    fn new(mem: &'a mut [[u8; 4096]]) -> Self {
        let next_page = AtomicUsize::new(128 * 0x400); /* first 8M reserved by boot and sbi */
        let terminate = mem.len();
        eprintln!("page count: {}", mem.len());
        let free_pages = terminate - 128 * 0x400;
        eprintln!("page count: {}", free_pages);
        Self {
            mem: mem.as_mut_ptr(),
            next_page,
            terminate,
            _phantom: core::marker::PhantomData,
        }
    }

    unsafe fn alloc_pages(&mut self, page_count: usize) -> *mut [u8; 4096] {
        let ret = self
            .mem
            .offset(self.next_page.load(Ordering::Relaxed) as isize);
        *self.next_page.get_mut() += page_count;
        assert!(self.next_page.load(Ordering::Relaxed) < self.terminate);
        ret
    }
}

static mut GLOBAL_HEAP: Heap<'static> = Heap {
    mem: core::ptr::null_mut(),
    next_page: AtomicUsize::new(0),
    terminate: 0,
    _phantom: core::marker::PhantomData,
};

struct HeapAllocator;

#[global_allocator]
static GLOBAL: HeapAllocator = HeapAllocator;
unsafe impl alloc::alloc::GlobalAlloc for HeapAllocator {
    unsafe fn alloc(&self, layout: alloc::alloc::Layout) -> *mut u8 {
        let req_pages = (layout.size() + 0xfff) >> 12;
        eprintln!("HEAP: allocating {} pages", req_pages);
        GLOBAL_HEAP.alloc_pages(req_pages) as *mut u8
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: alloc::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let old_pages = (layout.size() + 0xfff) >> 12;
        let req_pages = (new_size + 0xfff) >> 12;
        if req_pages > old_pages {
            GLOBAL_HEAP.alloc_pages(req_pages) as *mut u8
        } else {
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::alloc::Layout) {
        eprintln!(
            "WARNING: {} pages lost to the ether",
            (layout.size() + 0xfff) >> 12
        );
    }
}
