extern crate time;

use std::net::IpAddr;

use std::collections::{HashSet, HashMap, VecDeque};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ethernet::{EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags, ipv4_checksum, ipv6_checksum};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{Packet};

use std::ops::Sub;

use std::time::{Duration, Instant};
use tls_parser::{ClientHelloFingerprint};
use cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use stats_tracker::{StatsTracker};
use common::{TimedFlow, Flow};

use postgres::{Client, NoTls};

use std::thread;


pub struct FlowTracker {
    flow_timeout: Duration,
    write_to_stdout: bool,
    write_to_db: bool,
    dsn: Option<String>,

    cache: MeasurementCache,

    pub stats: StatsTracker,

    // Keys present in this set are flows we parse ClientHello from
    tracked_flows: HashSet<Flow>,
    stale_drops: VecDeque<TimedFlow>,

    // Keys present in this map are flows we parse ServerHello from
    tracked_server_flows: HashMap<Flow, i64>,
    stale_server_drops: VecDeque<TimedFlow>,

    pub gre_offset: usize,
}

impl FlowTracker {
    pub fn new(gre_offset: usize) -> FlowTracker {
        FlowTracker {
            flow_timeout: Duration::from_secs(20),
            tracked_flows: HashSet::new(),
            stale_drops: VecDeque::with_capacity(65536),
            tracked_server_flows: HashMap::new(),
            stale_server_drops: VecDeque::with_capacity(65536),
            write_to_stdout: true,
            write_to_db: false,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            dsn: None,
            gre_offset: gre_offset,
        }
    }

    pub fn new_db(dsn: String, core_id: i8, total_cores: i32, gre_offset: usize) -> FlowTracker {
        // TODO: (convinience) try to connect to DB and run any query, verifying credentials
        // right away

        let mut ft = FlowTracker {
            flow_timeout: Duration::from_secs(20),
            tracked_flows: HashSet::new(),
            stale_drops: VecDeque::with_capacity(65536),
            tracked_server_flows: HashMap::new(),
            stale_server_drops: VecDeque::with_capacity(65536),
            write_to_stdout: false,
            write_to_db: true,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            dsn: Some(dsn),
            gre_offset: gre_offset,
        };
        // flush to db at different time on different cores
        ft.cache.last_flush = ft.cache.last_flush.sub(time::Duration::seconds(
            (core_id as i64) * MEASUREMENT_CACHE_FLUSH / (total_cores as i64)));
        ft
    }

    pub fn handle_ipv4_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.all_packets_total += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv4_pkt = Ipv4Packet::new(eth_pkt.payload());
        if let Some(ipv4_pkt) = ipv4_pkt {
            match ipv4_pkt.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    // taking not the whole payload is a work around PF_RING giving padding as data
                    if let Some(tcp_pkt) = TcpPacket::new(&ipv4_pkt.payload()[0..((ipv4_pkt.get_total_length() as usize)-4*(ipv4_pkt.get_header_length() as usize))]) {
                        if ipv4_checksum(&tcp_pkt, &ipv4_pkt.get_source(), &ipv4_pkt.get_destination()) ==
                            tcp_pkt.get_checksum() {
                            self.handle_tcp_packet(
                                IpAddr::V4(ipv4_pkt.get_source()),
                                IpAddr::V4(ipv4_pkt.get_destination()),
                                &tcp_pkt,
                            )
                        } else {
                            self.stats.bad_checksums += 1;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    pub fn handle_ipv6_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.all_packets_total += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv6_pkt = Ipv6Packet::new(eth_pkt.payload());
        if let Some(ipv6_pkt) = ipv6_pkt {
            match ipv6_pkt.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(ipv6_pkt.payload()) {
                        if ipv6_checksum(&tcp_pkt, &ipv6_pkt.get_source(), &ipv6_pkt.get_destination()) ==
                            tcp_pkt.get_checksum() {
                            self.handle_tcp_packet(
                                IpAddr::V6(ipv6_pkt.get_source()),
                                IpAddr::V6(ipv6_pkt.get_destination()),
                                &tcp_pkt,
                            )
                        } else {
                            self.stats.bad_checksums += 1;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    fn handle_tcp_packet(&mut self, source: IpAddr, destination: IpAddr, tcp_pkt: &TcpPacket) {
        let is_client;
        if tcp_pkt.get_destination() == 443 {
            is_client = true;
        } else if tcp_pkt.get_source() == 443 {
            is_client = false;
        } else {
            return
        }
        let flow = Flow::new(&source, &destination, &tcp_pkt);
        let tcp_flags = tcp_pkt.get_flags();
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
            self.begin_tracking_flow(&flow, tcp_pkt.packet().to_vec());
            return;
        }
        if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
            self.tracked_flows.remove(&flow);
            return;
        }
        if tcp_pkt.payload().len() == 0 {
            return
        }

        // check for ClientHello
        if is_client && self.tracked_flows.contains(&flow) {
            self.stats.fingerprint_checks += 1;
            match ClientHelloFingerprint::from_try(tcp_pkt.payload()) {
                Ok(fp) => {
                    self.stats.fingerprints_seen += 1;
                    let fp_id = fp.get_fingerprint(false);
                    let norm_fp_id = fp.get_fingerprint(true);

                    self.begin_tracking_server_flow(&flow.reversed_clone(), fp_id as i64);

                    let mut curr_time = time::now();

                    if self.write_to_stdout {
                        println!("ClientHello: {{ id: {} t: {} {}}}",
                                 fp_id, curr_time.to_timespec().sec, fp);
                    }

                    if self.write_to_db {
                        // once in a while -- flush everything
                        if curr_time.to_timespec().sec - self.cache.last_flush.to_timespec().sec >
                            MEASUREMENT_CACHE_FLUSH {
                            self.flush_to_db()
                        }

                        // insert size of session ticket, if any
                        fp.ticket_size.map(|size| self.cache.add_ticket_size(fp_id as i64, size));

                        // insert current fingerprint and measurement
                        self.cache.add_connection(&flow, fp_id as i64,
                                                  fp.sni.to_vec(), curr_time.to_timespec().sec);
                        self.cache.add_fingerprint(fp_id as i64, fp, norm_fp_id as i64);

                        curr_time.tm_nsec = 0; // privacy
                        curr_time.tm_sec = 0;
                        curr_time.tm_min = 0;
                        self.cache.add_measurement(fp_id as i64, norm_fp_id as i64, curr_time.to_timespec().sec as i32);
                    }
                }
                Err(err) => {
                    self.stats.store_clienthello_error(err);
                }
            }
            self.tracked_flows.remove(&flow);
            return;
        }
    }

    fn flush_to_db(&mut self) {
        let client_mcache = self.cache.flush_measurements(false);
        let client_mcache_norm = self.cache.flush_measurements(true);
        let client_fcache = self.cache.flush_fingerprints();
        let client_ccache = self.cache.flush_dirty_norm_fps();
        let c4cache = self.cache.flush_ipv4connections();
        let c6cache = self.cache.flush_ipv6connections();
        let ticket_sizes = self.cache.flush_ticket_sizes();

        let dsn = self.dsn.clone().unwrap();

        // Update the HLL count map
        self.cache.update_raw_fingerprint_count(dsn.clone());

        thread::spawn(move || {
            let inserter_thread_start = time::now();
            let mut thread_db_conn = Client::connect(&dsn, NoTls).unwrap();

            let insert_fingerprint_original = match thread_db_conn.prepare(
                "INSERT
                INTO fingerprints (
                    id,
                    record_tls_version,
                    ch_tls_version,
                    cipher_suites,
                    compression_methods,
                    extensions,
                    named_groups,
                    ec_point_fmt,
                    sig_algs,
                    alpn,
                    key_share,
                    psk_key_exchange_modes,
                    supported_versions,
                    cert_compression_algs,
                    record_size_limit
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (id) DO NOTHING;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_fingerprint_original failed: {}", e);
                    return;
                }
            };

            let insert_fingerprint_norm_ext = match thread_db_conn.prepare(
                "INSERT
                INTO fingerprints_norm_ext (
                    id,
                    record_tls_version,
                    ch_tls_version,
                    cipher_suites,
                    compression_methods,
                    normalized_extensions,
                    named_groups,
                    ec_point_fmt,
                    sig_algs,
                    alpn,
                    key_share,
                    psk_key_exchange_modes,
                    supported_versions,
                    cert_compression_algs,
                    record_size_limit
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (id) DO NOTHING;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_fingerprint_norm_ext failed: {}", e);
                    return;
                }
            };

            let insert_fingerprint_count_est = match thread_db_conn.prepare(
                "INSERT
                INTO fingerprint_count_est (
                    norm_fp_id,
                    regs
                )
                VALUES ($1, $2)
                ON CONFLICT (norm_fp_id) DO UPDATE
                SET regs = greatest_bytea(fingerprint_count_est.regs, $2);"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_fingerprint_count_est failed: {}", e);
                    return;
                }
            };

            let insert_fingerprint_mapping = match thread_db_conn.prepare(
                "INSERT
                INTO fingerprint_map (
                    id,
                    norm_ext_id,
                    extensions
                )
                VALUES ($1, $2, $3)
                ON CONFLICT ON CONSTRAINT fingerprint_map_pkey DO UPDATE
                SET count = fingerprint_map.count + 1;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_fingerprint_map failed: {}", e);
                    return;
                }
            };

            let insert_measurement = match thread_db_conn.prepare(
                "INSERT
                INTO measurements (
                    unixtime,
                    id,
                    count
                )
                VALUES ($1, $2, $3)
                ON CONFLICT ON CONSTRAINT measurements_pkey1 DO UPDATE
                SET count = measurements.count + $4;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_measurement failed: {}", e);
                    return;
                }
            };

            let insert_measurement_norm_ext = match thread_db_conn.prepare(
                "INSERT
                INTO measurements_norm_ext (
                    unixtime,
                    id,
                    count
                )
                VALUES ($1, $2, $3)
                ON CONFLICT ON CONSTRAINT measurements_norm_ext_pkey DO UPDATE
                SET count = measurements_norm_ext.count + $4;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_measurement_norm_ext failed: {}", e);
                    return;
                }
            };

            let insert_ipv4conn = match thread_db_conn.prepare(
                "INSERT
                INTO ipv4connections (
                    id,
                    sid,
                    anon_cli_ip,
                    server_ip,
                    SNI
                )
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO NOTHING;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_ipv4conn failed: {}", e);
                    return;
                }
            };

            let insert_ipv6conn = match thread_db_conn.prepare(
                "INSERT
                INTO ipv6connections (
                    id,
                    sid,
                    anon_cli_ip,
                    server_ip,
                    SNI
                )
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT DO NOTHING;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_ipv6conn failed: {}", e);
                    return;
                }
            };

            let insert_ticket_size = match thread_db_conn.prepare(
                "INSERT
                INTO ticket_sizes (
                    id,
                    size,
                    count
                )
                VALUES ($1, $2, $3)
                ON CONFLICT ON CONSTRAINT ticket_sizes_pkey DO UPDATE
                SET count = ticket_sizes.count + $4;"
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    println!("Preparing insert_ticket_size failed: {}", e);
                    return;
                }
            };

            for (fp_id, fp) in client_fcache {
                // insert original signature
                let mut updated_rows = thread_db_conn.execute(&insert_fingerprint_original, &[
                    &(fp_id as i64),
                    &(fp.record_tls_version as i16), &(fp.ch_tls_version as i16),
                    &fp.cipher_suites, &fp.compression_methods, &fp.extensions,
                    &fp.named_groups, &fp.ec_point_fmt, &fp.sig_algs, &fp.alpn,
                    &fp.key_share, &fp.psk_key_exchange_modes, &fp.supported_versions,
                    &fp.cert_compression_algs, &fp.record_size_limit,
                ]);
                if updated_rows.is_err() {
                    println!("Error updating fingerprints: {:?}", updated_rows);
                }

                // generate normalized extension fingerprint
                let norm_ext_fp_id = fp.get_fingerprint(true);

                // insert normalized extension list signature
                updated_rows = thread_db_conn.execute(&insert_fingerprint_norm_ext, &[
                    &(norm_ext_fp_id as i64),
                    &(fp.record_tls_version as i16), &(fp.ch_tls_version as i16),
                    &fp.cipher_suites, &fp.compression_methods, &fp.extensions_norm,
                    &fp.named_groups, &fp.ec_point_fmt, &fp.sig_algs, &fp.alpn,
                    &fp.key_share, &fp.psk_key_exchange_modes, &fp.supported_versions,
                    &fp.cert_compression_algs, &fp.record_size_limit,
                ]);
                if updated_rows.is_err() {
                    println!("Error updating normalized extension fingerprints: {:?}", updated_rows);
                }

                // insert normalized vs original fingerprint mapping
                updated_rows = thread_db_conn.execute(&insert_fingerprint_mapping, &[
                    &(fp_id as i64),
                    &(norm_ext_fp_id as i64),
                    &fp.extensions,
                ]);
                if updated_rows.is_err() {
                    println!("Error updating normalized extension fingerprints: {:?}", updated_rows);
                }
            }

            for (fp_id, regs) in client_ccache {
                let updated_rows = thread_db_conn.execute(&insert_fingerprint_count_est, &[&(fp_id), &(regs).to_vec()]);
                if updated_rows.is_err() {
                    println!("Error updating normalized fp count estimate: {:?}", updated_rows);
                }
            } 

            for (k, count) in client_mcache {
                let updated_rows = thread_db_conn.execute(&insert_measurement, &[&(k.1), &(k.0),
                    &(count), &(count)]);
                if updated_rows.is_err() {
                    println!("Error updating measurements: {:?}", updated_rows);
                }
            }

            for (k, count) in client_mcache_norm {
                let updated_rows = thread_db_conn.execute(&insert_measurement_norm_ext, &[&(k.1), &(k.0),
                    &(count), &(count)]);
                if updated_rows.is_err() {
                    println!("Error updating measurements_norm_ext: {:?}", updated_rows);
                }
            }

            for ipv4c in c4cache {
                let updated_rows = thread_db_conn.execute(&insert_ipv4conn, &[&(ipv4c.id as i64), &(ipv4c.sid as i64),
                    &(ipv4c.anon_cli_ip), &(ipv4c.serv_ip), &(ipv4c.sni)]);
                if updated_rows.is_err() {
                    println!("Error updating ipv4connections: {:?}", updated_rows);
                }
            }

            for ipv6c in c6cache {
                let updated_rows = thread_db_conn.execute(&insert_ipv6conn, &[&(ipv6c.id as i64), &(ipv6c.sid as i64),
                    &(ipv6c.anon_cli_ip), &(ipv6c.serv_ip), &(ipv6c.sni)]);
                if updated_rows.is_err() {
                    println!("Error updating ipv6connections: {:?}", updated_rows);
                }
            }

            for (k, count) in ticket_sizes {
                let updated_rows = thread_db_conn.execute(&insert_ticket_size, &[&(k.0 as i64),
                    &(k.1 as i16), &(count), &(count)]);
                if updated_rows.is_err() {
                    println!("Error updating ticket sizes: {:?}", updated_rows);
                }
            }

            let inserter_thread_end = time::now();
            println!("Updating DB took {:?} ns in separate thread",
                     inserter_thread_end.sub(inserter_thread_start).num_nanoseconds());
        });
    }

    fn begin_tracking_flow(&mut self, flow: &Flow, _syn_data: Vec<u8>) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_flows.insert(*flow);
    }

    fn begin_tracking_server_flow(&mut self, flow: &Flow, cid: i64) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_server_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_server_flows.insert(*flow, cid);
    }

    // not called internally, has to be called externally
    pub fn cleanup(&mut self) {
        while !self.stale_drops.is_empty() && // is_empty: condition for unwraps
            self.stale_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_drops.pop_front().unwrap();
            self.tracked_flows.remove(&cur.flow);
        }
        while !self.stale_server_drops.is_empty() && // is_empty: condition for unwraps
            self.stale_server_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_server_drops.pop_front().unwrap();
            self.tracked_server_flows.remove(&cur.flow);
        }
    }

    pub fn debug_print(&mut self) {
        println!("[DEBUG] tracked_flows: {} stale_drops: {} \
                tracked_server_flows: {}, stale_server_drops: {}",
                 self.tracked_flows.len(), self.stale_drops.len(),
                 self.tracked_server_flows.len(), self.stale_server_drops.len());
        self.stats.print_avg_stats();
    }
}
