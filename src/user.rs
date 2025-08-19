use core::panic;
use std::ffi::c_char;

use bytemuck::NoUninit;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct new_utsname {
    sysname: [c_char; 65],
    nodename: [c_char; 65],
    release: [c_char; 65],
    version: [c_char; 65],
    machine: [c_char; 65],
    domainname: [c_char; 65],
}

unsafe impl NoUninit for new_utsname {}

fn construct_char_str(value: &str) -> [c_char; 65] {
    if value.len() > 64 {
        panic!("Too long!")
    }
    let mut array = [0; 65];
    for (idx, chr) in value.chars().enumerate() {
        array[idx] = chr as c_char
    }
    array
}

impl Default for new_utsname {
    fn default() -> Self {
        Self {
            sysname: construct_char_str("Linux"),
            nodename: construct_char_str("ubuntu"),
            release: construct_char_str("6.8.0-52-generic"),
            version: construct_char_str("risc-emulator by thealtofwar"),
            machine: construct_char_str("riscv64"),
            domainname: construct_char_str("(none)"),
        }
    }
}
