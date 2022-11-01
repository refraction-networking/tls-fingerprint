extern crate time;
extern crate crypto;

use std::net::IpAddr;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags, ipv4_checksum, ipv6_checksum};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{Packet, PacketSize};
use self::crypto::digest::Digest;
use std::time::{Duration, Instant};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HelloParseError {
    ShortBuffer,
    NotAHandshake,
    UnknownRecordTLSVersion,
    ShortOuterRecord,
    NotAClientHello,
    InnerOuterRecordLenContradict,
    UnknownChTLSVersion,
    SessionIDLenExceedBuf,
    CiphersuiteLenMisparse,
    CompressionLenExceedBuf,
    ExtensionsLenExceedBuf,
    ShortExtensionHeader,
    ExtensionLenExceedBuf,

    NotAServerHello,

    KeyShareExtShort,
    KeyShareExtLong,
    KeyShareExtLenMisparse,
    PskKeyExchangeModesExtShort,
    PskKeyExchangeModesExtLenMisparse,
    SupportedVersionsExtShort,
    SupportedVersionsExtLenMisparse,
}

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

pub struct TimedFlow
{
    pub event_time: Instant,
    pub flow: Flow,
}

impl Flow {
    pub fn new(src_ip: &IpAddr, dst_ip: &IpAddr, tcp_pkt: &TcpPacket) -> Flow {
        Flow {
            src_ip: *src_ip,
            dst_ip: *dst_ip,
            src_port: tcp_pkt.get_source(),
            dst_port: tcp_pkt.get_destination(),
        }
    }
    pub fn reversed_clone(&self) -> Flow {
        Flow{src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}


#[derive(PartialEq, Eq, Hash)]
pub struct ConnectionIPv6 {
    pub id: i64,
    pub sid: i64,
    pub time_sec: i64,
    pub sni: Vec<u8>,
    pub serv_ip: Vec<u8>,
    pub anon_cli_ip: u32,
}

#[derive(PartialEq, Eq, Hash)]
pub struct ConnectionIPv4 {
    pub id: i64,
    pub sid: i64,
    pub time_sec: i64,
    pub anon_cli_ip: i16,
    pub serv_ip: u32,
    pub sni: Vec<u8>,
}


// TODO: better done as a trait on Digest
pub fn hash_u32<D: Digest>(h: &mut D, n: u32) {
    h.input(&[((n >> 24) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8]);
}

pub fn u8_to_u16_be(first_byte: u8, second_byte: u8) -> u16 {
    (first_byte as u16) << 8 | (second_byte as u16)
}

pub fn u8_to_u32_be(first_byte: u8, second_byte: u8, third_byte: u8, forth_byte: u8) -> u32 {
    (first_byte as u32) << 24 | (second_byte as u32) << 16 | (third_byte as u32) << 8 |
        (forth_byte as u32)
}

pub fn u8array_to_u32_be(oct: [u8; 4]) -> u32 {
    (oct[0] as u32) << 24 | (oct[1] as u32) << 16 | (oct[2] as u32) << 8 | (oct[3] as u32)
}


// Doesn't check that a.len() % 2 == 1.
pub fn vec_u8_to_vec_u16_be(a: &Vec<u8>) -> Vec<u16> {
    let mut result = Vec::with_capacity(a.len() / 2);
    for i in 0..result.capacity() {
        result.push(u8_to_u16_be(a[2 * i], a[2 * i + 1]));
    }
    result
}