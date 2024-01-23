mod flow_tracker;
mod tls_parser;
mod cache;
mod common;
mod stats_tracker;

#[macro_use]
extern crate enum_primitive;
extern crate time;
extern crate pnet;
extern crate pcap;
extern crate postgres;
extern crate pcap_file;
extern crate rand;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::env;
use std::process;
use std::time::{Instant, Duration};
use pcap::Capture;
use flow_tracker::FlowTracker;

fn main() {
    if env::args().len() < 2 {
        println!("Usage: ./tls_fingerprint interface_name");
        process::exit(255);
    }
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let mut ft = FlowTracker::new(0, 100);

    let from_pcap_file = false;
    let pcap_filename = "TMP";
    if from_pcap_file {
        let mut cap = Capture::from_file(pcap_filename) // open the "default" interface
            .unwrap(); // assume activation worked

        while let Ok(cap_pkt) = cap.next() {
            let pnet_pkt = pnet::packet::ethernet::EthernetPacket::new(cap_pkt.data);
            match pnet_pkt {
                Some(eth_pkt) => {
                    match eth_pkt.get_ethertype() {
                        // EtherTypes::Vlan?
                        EtherTypes::Ipv4 => ft.handle_ipv4_packet(&eth_pkt),
                        EtherTypes::Ipv6 => ft.handle_ipv6_packet(&eth_pkt),
                        _ => println!("[Warning] Could not parse packet"),
                    }
                }
                None => {
                    println!("[Warning] Could not parse packet");
                }
            }
        }
    }

    // Create a new channel, dealing with layer 2 packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            println!("Unhandled channel type");
            return
        }
        Err(e) => {
            println!("An error occurred when creating the datalink channel: {}", e);
            return
        }
    };

    let cleanup_frequency = Duration::from_secs(1);
    let mut last_cleanup = Instant::now();

    loop {
        match rx.next() {
            Ok(packet) => {
                match EthernetPacket::new(packet) {
                    Some(eth_pkt) => {
                        match eth_pkt.get_ethertype() {
                            // EtherTypes::Vlan?
                            EtherTypes::Ipv4 => ft.handle_ipv4_packet(&eth_pkt),
                            EtherTypes::Ipv6 => ft.handle_ipv6_packet(&eth_pkt),
                            _ => continue,
                        }
                    }
                    None => {
                        println!("[Warning] Could not parse packet: {:?}", packet);
                        continue;
                    }
                }
                if last_cleanup.elapsed() >= cleanup_frequency {
                    ft.cleanup();
                    last_cleanup = Instant::now();
                    ft.debug_print();
                }
            }
            Err(e) => {
                println!("[ERROR] An error occurred while reading: {}", e);
            }
        }
    }
}
