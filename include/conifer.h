#pragma once
/*
 * conifer specific syscalls and APIs
 */
#define SYS_conifer 65536
#define SYS_earlycon (SYS_conifer + 0)
#define SYS_getfdt (SYS_conifer + 1)
#define SYS_mpp (SYS_conifer + 2)
#define SYS_mexecve (SYS_conifer + 3)
#define SYS_register (SYS_conifer + 4)
