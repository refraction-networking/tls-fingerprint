extern crate time;

use std::collections::{HashSet, HashMap};
use std::mem;
use common::{Flow, ConnectionIPv6, ConnectionIPv4, u8_to_u16_be, u8_to_u32_be, u8array_to_u32_be};
use std::net::IpAddr;
use tls_parser::{ClientHelloFingerprint};


pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const CONNECTION_SID_WAIT_TIMEOUT: i64 = 10; // 10 secs
const HLL_REGS: usize = 128; // Number of registers for HLL struct
const HLL_BITS: usize = 7; // log2(HLL_REGS)
const MASK: u64 = (1<<(8-HLL_BITS)) - 1;
const IDX_MASK: u64 = 0xff ^ MASK;
const H_MASK: u64 = !(IDX_MASK << 56);
// to ease load on db, cache queries
pub struct MeasurementCache {
    pub last_flush: time::Tm,
    // for ClientHello
    measurements: HashMap<(i64, i32), i32>,
    // (cid, timestamp): count
    fingerprints_new: HashMap<i64, ClientHelloFingerprint>,
    fingerprints_flushed: HashSet<i64>,

    // for normalized fingerprint estimation
    norm_fp_counts: HashMap<i64, [u8; HLL_REGS]>,
    dirty_norm_fp_counts: HashMap<i64, [u8; HLL_REGS]>,
    // for connections

    ticket_sizes: HashMap<(i64, i16), i64>, // (ClientHelloID, ticket_size) -> count

    ipv4_connections_seen: HashSet<(i64, u32)>,
    ipv4_connections: HashMap<Flow, ConnectionIPv4>,
    ipv6_connections: HashMap<Flow, ConnectionIPv6>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            measurements: HashMap::new(),
            fingerprints_flushed: HashSet::new(),
            fingerprints_new: HashMap::new(),

            norm_fp_counts: HashMap::new(),
            dirty_norm_fp_counts: HashMap::new(),

            ticket_sizes: HashMap::new(),

            ipv4_connections_seen: HashSet::new(),
            ipv4_connections: HashMap::new(),
            ipv6_connections: HashMap::new(),
        }
    }

    pub fn add_measurement(&mut self, fp_id: i64, ts: i32) {
        let key = (fp_id, ts);
        let counter = self.measurements.entry(key).or_insert(0);
        *counter += 1;
    }

    pub fn add_fingerprint(&mut self, fp_id: i64, fp: ClientHelloFingerprint, norm_fp_id: i64) {
        if !self.fingerprints_flushed.contains(&fp_id) {
            self.fingerprints_new.insert(fp_id, fp);
        }
        self.update_norm_count(norm_fp_id, fp_id);
    }

    fn update_norm_count(&mut self, norm_fp_id: i64, h: i64) {
        let estimate = self.norm_fp_counts.entry(norm_fp_id).or_insert([0; HLL_REGS]); // Get existing estimate or insert new one
        let idx = ((((h as u64)>>56) & IDX_MASK) >> (8-HLL_BITS)) as usize; //Get first byte of 8 byte fp AND with IDX_MASK
        let masked_h = h & H_MASK as i64; //MASK the position bits in nor
        let pos = (masked_h.leading_zeros() - (HLL_BITS as u32) + 1) as u8; // Remove initial positional bytes, increment by one for leading zeros count
        if pos > estimate[idx] {
            estimate[idx] = pos;
        }
        self.dirty_norm_fp_counts.insert(norm_fp_id, *estimate);
    }

    pub fn add_ticket_size(&mut self, cid: i64, ticket_size: i16) {
        let key = (cid, ticket_size);
        let counter = self.ticket_sizes.entry(key).or_insert(0);
        *counter += 1;
    }

    pub fn add_connection(&mut self, flow: &Flow, cid: i64, sni: Vec<u8>, time_sec: i64) {
        match flow.src_ip {
            IpAddr::V4(ip_src) => {
                match flow.dst_ip {
                    IpAddr::V4(ip_dst) => {
                        let serv_ip = u8array_to_u32_be(ip_dst.octets());
                        if self.ipv4_connections_seen.contains(&(cid, serv_ip)) {
                            return
                        }
                        let c = ConnectionIPv4 {
                            anon_cli_ip: u8_to_u16_be(ip_src.octets()[0], ip_src.octets()[1]) as i16,
                            serv_ip: serv_ip,
                            id: cid,
                            sni: sni,
                            sid: 0,
                            time_sec: time_sec,
                        };
                        self.ipv4_connections.insert(*flow, c);
                        self.ipv4_connections_seen.insert((cid, serv_ip));
                        return
                    }
                    IpAddr::V6(_) => {
                        println!("[WARNING] IP versions mismatch! source(ipv4): {}, destination(ipv6): {}",
                                 flow.src_ip, flow.dst_ip);
                    }
                }
            }
            IpAddr::V6(ip_src) => {
                match flow.dst_ip {
                    IpAddr::V6(ip_dst) => {
                        let c = ConnectionIPv6 {
                            anon_cli_ip: u8_to_u32_be(ip_src.octets()[0], ip_src.octets()[1],
                                                      ip_src.octets()[2], ip_src.octets()[3]),
                            serv_ip: ip_dst.octets().to_vec(),
                            id: cid,
                            sni: sni,
                            sid: 0,
                            time_sec: time_sec,
                        };
                        self.ipv6_connections.insert(*flow, c);
                        return
                    }
                    IpAddr::V4(_) => {
                        println!("[WARNING] IP versions mismatch! source(ipv6): {}, destination(ipv4): {}",
                                 flow.src_ip, flow.dst_ip);
                    }
                }
            }
        }
    }

    // returns cached HashMap of measurements, empties it in object
    pub fn flush_measurements(&mut self) -> HashMap<(i64, i32), i32> {
        self.last_flush = time::now();
        mem::replace(&mut self.measurements, HashMap::new())
    }

    // returns cached HashMap of fingerprints, empties it in object
    pub fn flush_fingerprints(&mut self) -> HashMap<i64, ClientHelloFingerprint> {
        self.last_flush = time::now();
        for (fp_id, _) in self.fingerprints_new.iter() {
            self.fingerprints_flushed.insert(*fp_id);
        }
        mem::replace(&mut self.fingerprints_new, HashMap::new())
    }

    pub fn flush_dirty_norm_fps(&mut self) -> HashMap<i64, [u8; HLL_REGS]> {
        mem::replace(&mut self.dirty_norm_fp_counts, HashMap::new())
    }

    fn get_ipv4connections_to_flush(&self) -> HashSet<Flow> {
        let mut hs_flows = HashSet::new();
        let curr_sec = self.last_flush.to_timespec().sec;
        for (flow, conn) in self.ipv4_connections.iter() {
            if conn.sid != 0 || curr_sec - conn.time_sec > CONNECTION_SID_WAIT_TIMEOUT {
                hs_flows.insert(*flow);
            }
        }
        hs_flows
    }

    // returns cached HashMap of ipv4 connections, empties it in object
    pub fn flush_ipv4connections(&mut self) -> HashSet<ConnectionIPv4> {
        self.last_flush = time::now();
        let mut hs_conns = HashSet::new();
        for flow in self.get_ipv4connections_to_flush() {
            hs_conns.insert(self.ipv4_connections.remove(&flow).unwrap());
        }
        hs_conns
    }

    fn get_ipv6connections_to_flush(&self) -> HashSet<Flow> {
        let mut hs_flows = HashSet::new();
        let curr_sec = self.last_flush.to_timespec().sec;
        for (flow, conn) in self.ipv6_connections.iter() {
            if conn.sid != 0 || curr_sec - conn.time_sec > CONNECTION_SID_WAIT_TIMEOUT {
                hs_flows.insert(*flow);
            }
        }
        hs_flows
    }

    // returns cached HashMap of ipv6 connections, empties it in object
    pub fn flush_ipv6connections(&mut self) -> HashSet<ConnectionIPv6> {
        self.last_flush = time::now();
        let mut hs_conns = HashSet::new();
        for flow in self.get_ipv6connections_to_flush() {
            hs_conns.insert(self.ipv6_connections.remove(&flow).unwrap());
        }
        hs_conns
    }

    // returns cached HashMap of ticket sizes, empties it in object
    pub fn flush_ticket_sizes(&mut self) -> HashMap<(i64, i16), i64> {
        self.last_flush = time::now();
        mem::replace(&mut self.ticket_sizes, HashMap::new())
    }
}
