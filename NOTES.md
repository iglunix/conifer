# Notes on Conifer

## TODO
 - vDSO
 - fsd
 - shared code library between init, krnl, etc

## random stuff
 - weak and strong flags for syscall registering
   if weak the syscall can be registered by another process
   and replaced.

 - fsd dispatches io
 - init.elf loads initrd and parses fdt

## Syscalls
TODO: which syscalls should be root only
 - 65536 - `earlycon`
 - 65537 - `getfdt` - Maps fdt into device memory and returns the address.
 - 65538 - `mpp` - Maps physical pages
 - 65539 - `mexecve(void *mem, size_t len, char *const argv[], char *const envp[])` - copies an elf file from user memory and executes it


### MPP
Map Physical memory Pages to the current process. Pages will be rw.
```
void *mpp(void *p_start_addr, size_t page_count);
```

TODO: we should probably dissallow mapping other processes memory or perhaps restrict mapping
other processes memory and kernel memory


### memory map
 - kernel memory 0xffffffcxxxxxxxxx
 - physical memory 0xffffffexxxxxxxxx
 - put initial stack in read only page just above
   the stack


### binfmts
shebang stuff is handled in userspace through `execve` implementation in `fsd`

## Scheduler
 - timer interupts tell scheduler to switch process

 - each hart has a schedule priorty queue
 - every timer interrupt the kernel switches to the next process in the schedule queue;
   the old one is bubbled down (peek_mut) or pushed onto anoher hart's schedule queue depending
   on heuristics

 - every time a process is scheduled its scheduled value is incremented according to priority
   - highest priority processes have their priority incremented the least
 - every time a process is scheduled it's checked  if sleeping. if it is, increment and push
   back without scheduling. if it doesn't need to be anymore it is scheduled 
 - when a new process is created, its schedule value is set to the lowest value in the queue
   - or perhaps lowest value + priority increment
```
// 50 is just a guess. should adjust value to something better
process_increment = 50 + process_priority;
```
 - a configurable priority reduction index?

how to implement sleep?
 - each process has a wake from sleep time attached to it
 - process is only scheduled if not sleeping otherwise it just gets priority incremented
   and bubbled down the heap.
 - the earliest wake from sleep time is kept track of and if it's greater than the current time
   the hart itself sleeps

how is it decided if the task is pushed back in the same queue or switches queues?
 - switching hart queues is a more expensive operation so must be done strategically


## usermode handling of linux syscalls
 - handling process can request pages from the calling process's address space

## security
 - limit access to some syscalls to children of pid 2
 - provide implementations of `init_module(2)` and `finit_module(2)` to
   tell pid 2 to start a process.
