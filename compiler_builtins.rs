// code taken from redox relibc
// SPDX-License-Identifier: MIT
#![compiler_builtins]
#![no_builtins]
#![no_std]
#![allow(internal_features)]
#![feature(compiler_builtins)]

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        *s.add(i) = c as u8;
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(s1: *mut u8, s2: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i + 7 < n {
        *(s1.add(i) as *mut u64) = *(s2.add(i) as *const u64);
        i += 8;
    }
    while i < n {
        *(s1 as *mut u8).add(i) = *(s2 as *const u8).add(i);
        i += 1;
    }
    s1
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(mut a: *const u8, mut b: *const u8, n: usize) -> isize {
    for _ in 0..n {
        if *a != *b {
            return *a as isize - *b as isize;
        }
        a = a.add(1);
        b = b.add(1);
    }
    0
}
