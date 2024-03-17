#![no_std]
#![no_main]
#![feature(strict_provenance)]
#![feature(fn_align)]
#![warn(fuzzy_provenance_casts)]
#![feature(naked_functions)]
#![feature(exposed_provenance)]
#![feature(offset_of)]

mod abi;
#[macro_use]
mod con;
mod riscv64;
mod rwlock;
use riscv64 as arch;

// TODO: need some waya of sending capabilities across task boundaries
// should you be able to send them over endpoint capabilities?
enum Calls {
    // locks mut
    //
    // Split a memory rejoin into two seperate capabilities at a line
    // MemSplit(MemCap, line: usize) -> (MemCap, MemCap)
    MemSplit,

    // locks mut
    //
    // Create a task from a memory capability.
    // MemCreateTask(MemCap<2 pages>) -> TaskCap
    MemCreateTask,

    // locks mut
    //
    // Create a thread from a memory capability.
    // MemCreateThread(MemCap<64k? maybe make all  0 or 64k>, Task (initial task), usize (initial pc)) -> ThreadCap
    MemCreateThread,

    // Write to console
    // ConWrite(ConCap, usize, usize, usize, ...)
    ConWrite,

    // locks mut
    //
    // TaskMapMem(TaskCap, MemCap, addr: usize)
    // well also include map level bullshite
    TaskMapMem,

    // locks mut
    //
    // TaskUnmapMem(TaskCap, addr: usize) -> MemCap
    // well also include map level bullshite
    TaskUnmapMem,

    // locks mut
    //
    // TaskMapShared(TaskCap, SharedCap, addr: usize)
    // will increase the ref count
    // well also include map level bullshite
    TaskMapShared,

    // locks mut
    //
    // TaskUnmapShared(TaskCap, addr: usize)
    // will decrease the ref count
    // well also include map level bullshite
    TaskUnmapShared,

    // locks mut
    //
    // TaskMapCap(TaskCap, MemCap, addr: usize)
    // well also include map level bullshite
    TaskMapCap,

    // locks mut
    //
    // TaskUnmapCap(TaskCap, addr: usize) -> MemCap
    // well also include map level bullshite
    TaskUnmapCap,

    // locks mut
    //
    // TaskCreateEndpoint(TaskCap, pc: usize) -> Endpoint
    TaskCreateEndpoint,

    // locks mut
    //
    // TaskCreateMem(TaskCap) -> MemCap<2 pages>
    // reclaim the memory from a task cap that's not needed anymore.
    // will fault if there are still references
    TaskCreateMem,

    // locks mut
    //
    // ThreadCreateMem(ThreadCap) -> MemCap
    ThreadCreateMem,

    // EndpointInvoke()
    EndpointInvoke,

    // forget about a capability drop the reference but don't destroy it in anyway
    CapDrop,

    // locks mut
    //
    // creates a reference counted shared memory capability
    MemCreateShared,

    // locks mut
    //
    // turns a shared cap into a mem cap provided there are no references left.
    SharedCreateMem,
}

#[link_section = ".data._init"]
#[no_mangle]
static mut _init: [u8; include_bytes!("init.bin").len()] = *include_bytes!("init.bin");
