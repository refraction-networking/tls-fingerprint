mod flow_tracker;
mod tls_parser;
mod cache;
mod common;
mod stats_tracker;

#[macro_use]
extern crate enum_primitive;
extern crate time;
extern crate pnet;
extern crate postgres;

extern crate libc;


use libc::size_t;

use libc::c_char;
use std::ffi::CStr;
use std::str;

use std::os::raw::c_void;
use std::mem::transmute;

use std::slice;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use flow_tracker::FlowTracker;

#[no_mangle]
pub extern "C" fn rust_process_packet(globals_ptr: *mut RustGlobalsStruct,
                                      raw_ethframe: *mut c_void,
                                      frame_len: size_t)
{

    let globals = unsafe { &mut *globals_ptr };
    let mut ft = unsafe { &mut *globals.ft };

    let rust_view = unsafe {
        slice::from_raw_parts_mut(raw_ethframe as *mut u8, frame_len as usize)
    };

    match EthernetPacket::new(rust_view) {
        Some(pkt) => {
            match pkt.get_ethertype() {
                // EtherTypes::Vlan?
                EtherTypes::Ipv4 => ft.handle_ipv4_packet(&pkt),
                EtherTypes::Ipv6 => ft.handle_ipv6_packet(&pkt),
                _ => return,
            }
        }
        None => return,
    };
}

#[no_mangle]
pub extern "C" fn rust_periodic_cleanup(globals_ptr: *mut RustGlobalsStruct)
{

    let globals = unsafe { &mut *globals_ptr };
    let mut ft = unsafe { &mut *globals.ft };

    ft.cleanup();
}

#[no_mangle]
pub extern "C" fn rust_print_avg_stats(globals_ptr: *mut RustGlobalsStruct)
{

    let globals = unsafe { &mut *globals_ptr };
    let mut ft = unsafe { &mut *globals.ft };

    ft.stats.print_avg_stats();
}

#[repr(C)]
pub struct RustGlobalsStruct
{
    ft: *mut FlowTracker,
}

#[no_mangle]
pub extern "C" fn rust_init(core_id: i8, cores_total: i32, dsn_ptr: *const c_char) -> RustGlobalsStruct
{
    let dsn_c_str: &CStr = unsafe { CStr::from_ptr(dsn_ptr) };
    let dsn_string: String = dsn_c_str.to_str().unwrap().to_owned();

    let ft = FlowTracker::new_db(dsn_string, core_id, cores_total);
    RustGlobalsStruct { ft: unsafe { transmute(Box::new(ft))}}
}

#[no_mangle]
pub extern "C" fn rust_cleanup(globals_ptr: *mut RustGlobalsStruct){
    let globals = unsafe { &mut *globals_ptr };
    let mut ft = unsafe { &mut *globals.ft };
    ft.cleanup();
}
