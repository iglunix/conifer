#![no_std]
#![no_main]
#![feature(strict_provenance)]
#![feature(fn_align)]
#![warn(fuzzy_provenance_casts)]
#![feature(naked_functions)]
#![feature(exposed_provenance)]

#[macro_use]
mod con;
mod riscv64;
use riscv64 as arch;

#[link_section = ".data._init"]
#[no_mangle]
static mut _init: [u8; include_bytes!("init.bin").len()] = *include_bytes!("init.bin");
