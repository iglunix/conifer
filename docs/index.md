# Conifer

## An overview of the boot process
 - The bootloader loads boot.elf. This is a "prekernel" that setsup the system
   into a higher half mode, reserves basic memory for the main kernel, loads
   the main kernel elf file.

   - Boot starts by filling in the first layer of the buddy allocator.
     (a bitmap of pages currently used)
   - Next boot setup the kernels page table
   - boot then switches to the kernel.

 - The main kernel is the next step of the boot process which will fill in the
   rest of the buddy allocator data structure, fill in the process table

   - The kernel starts by filling in the other layers of the buddy allocator
     tree
   - the kernel then walks the page table and fills in the memory map data
     structures
   - the kernel then sets up and fills in the first entry in the process
     table (pid 1 which is itself at the moment). This process table
     stores the pointer to the top level page table for each process,
     and keeps track of all registers when the process is not running.
   - next the kernel setsup the shared kernel page table. This page table
     is just below the top level page table in ALL processes and includes
     all global kernel state.
   - the kernel then setsup the timer for scheduling

 - The next step is execing a userspace process. The kernel starts up the VFS
   which forks into pid 1 and 2. pid 1 execs /init from the initrd, VFS continues
   as is in pid 2 implementing linux syscalls.

## An overview of memory management

## An overview of scheduling

## An overview of switching between usermode and kernel mode

 - ecall is encountered
 - processor jumps to sepc: the S mode interrupt handler
 - the kernel saves the usermode stack pointer into sscratch
 - the kernel then switches to the kernel stack
 - all registers are pushed onto the current stack
 - the stack pointer value on the stack is changed to the value in sscratch
 - the syscall is executed
 - the stack pointer value is written back to sscratch
 - all registers are popped off the kernel stack
 - the stack pointer value is read from sscratch
 - sret to usermode
