#![feature(naked_functions)]
#![feature(fn_align)]
#![feature(once_cell)]
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
    user: bool,
}

struct Map();

struct Mem {
    // Mappings shared between a thread group
    group_map: Map,
    local_map: Map,

    // Mappings
    global_map: Map,
}

mod buddy;
mod trap;

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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Context {
    pc: usize, // pc
    ra: usize, // x1
    sp: usize, // x2
    gp: usize, // x3
    tp: usize, // x4
    t0: usize, // x5
    t1: usize, // x6
    t2: usize, // x7
    s0: usize, // x8
    s1: usize, // x9
    a0: usize, // x10
    a1: usize, // x11
    a2: usize, // x12
    a3: usize, // x13
    a4: usize, // x14
    a5: usize, // x15
    a6: usize, // x16
    a7: usize, // x17
    s2: usize, // x18
    s3: usize, // x19
    s4: usize, // x20
    s5: usize, // x21
    s6: usize, // x22
    s7: usize, // x23
    s8: usize, // x24
    s9: usize, // x25
    s10: usize,// x26
    s11: usize,// x27
    t3: usize, // x28
    t4: usize, // x29
    t5: usize, // x30
    t6: usize, // x31
}

impl Context {
    const fn default() -> Self {
        Self {
            pc: 0, // pc/sepc
            ra: 0, // x1
            sp: 0, // x2
            gp: 0, // x3
            tp: 0, // x4
            t0: 0, // x5
            t1: 0, // x6
            t2: 0, // x7
            s0: 0, // x8
            s1: 0, // x9
            a0: 0, // x10
            a1: 0, // x11
            a2: 0, // x12
            a3: 0, // x13
            a4: 0, // x14
            a5: 0, // x15
            a6: 0, // x16
            a7: 0, // x17
            s2: 0, // x18
            s3: 0, // x19
            s4: 0, // x20
            s5: 0, // x21
            s6: 0, // x22
            s7: 0, // x23
            s8: 0, // x24
            s9: 0, // x25
            s10: 0,// x26
            s11: 0,// x27
            t3: 0, // x28
            t4: 0, // x29
            t5: 0, // x30
            t6: 0, // x31
        }
    }
}

/*
#[naked]
unsafe extern "C" fn ctx_switch(old: &mut Context, new: &mut Context) {
    unsafe {
        core::arch::asm!(
            "sd ra, 0(a0)
         sd sp, 8(a0)
         sd s0, 16(a0)
         sd s1, 24(a0)
         sd s2, 32(a0)
         sd s3, 40(a0)
         sd s4, 48(a0)
         sd s5, 56(a0)
         sd s6, 64(a0)
         sd s7, 72(a0)
         sd s8, 80(a0)
         sd s9, 88(a0)
         sd s10, 96(a0)
         sd s11, 104(a0)

         ld ra, 0(a1)
         ld sp, 8(a1)
         ld s0, 16(a1)
         ld s1, 24(a1)
         ld s2, 32(a1)
         ld s3, 40(a1)
         ld s4, 48(a1)
         ld s5, 56(a1)
         ld s6, 64(a1)
         ld s7, 72(a1)
         ld s8, 80(a1)
         ld s9, 88(a1)
         ld s10, 96(a1)
         ld s11, 104(a1)
         ret
         ",
            options(noreturn)
        );
    }
}
*/

const MAX_TASKS: usize = 3;
const STACK_SIZE: usize = 4096;
// TODO: thread local
static mut CUR_TASK: Task = Task(0);
static mut LAST_TASK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static mut TASK_STACKS: [[usize; STACK_SIZE]; MAX_TASKS] = [[0; STACK_SIZE]; MAX_TASKS];
static mut TASK_CTX: [Context; MAX_TASKS] = [Context::default(); MAX_TASKS];
// keep track of what tasks are running. we cant run the same task in parallel
// all tasks are initially set as if they were running. this is so they can't be scheduled
// until they have been created
#[derive(Clone, Copy, Debug)]
struct Task(usize);

impl Task {
    fn new(task: *const ()) -> Self {
        unsafe {
            let tid = LAST_TASK.fetch_add(1, core::sync::atomic::Ordering::SeqCst) + 1;
            TASK_CTX[tid].pc = task as usize;
            TASK_CTX[tid].sp = TASK_STACKS[tid].as_mut_ptr().add(TASK_STACKS[tid].len() - 1) as usize;
            eprintln!("sp: {:p}", TASK_STACKS[tid].as_mut_ptr());
            Self(tid)
        }
    }

    fn current() -> Self {
        unsafe { CUR_TASK }
    }

    fn switch(self) {
        unsafe {
            panic!();
            eprintln!("switching to: {}", self.0);
            let old = &mut TASK_CTX[CUR_TASK.0];
            CUR_TASK = self;
            let new = &mut TASK_CTX[CUR_TASK.0];
            eprintln!("{:#?}", new);
            // ctx_switch(old, new);
        }
    }
}

fn task1() {
    unsafe {
        loop {
            println!("Hi from task 1");
            core::arch::asm!("wfi")
        }
    }
}

fn main() {
    trap::init();
    // initialise the buddy allocator
    let mut buddy = buddy::Buddy::init();
    let addr = buddy.alloc();
    buddy.free(addr);

    // TODO: fix boot not 0 init
    unsafe {
        CUR_TASK = Task(0);
        LAST_TASK = core::sync::atomic::AtomicUsize::new(0);
    }
    let t = Task::new(task1 as *const ());

    unsafe { trap::timer(); }

    unsafe {
        loop {
            println!("Hi from task 0");
            core::arch::asm!("wfi")
        }
    }
}
