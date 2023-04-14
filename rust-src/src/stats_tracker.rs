extern crate time;

use std::ops::Sub;
use common::{HelloParseError};

pub struct StatsTracker {
    pub last_print: time::Tm,
    pub fingerprints_seen: u64,
    pub fingerprint_checks: u64,

    pub sfingerprints_seen: u64,
    pub sfingerprint_checks: u64,

    pub all_packets_total: u64,
    pub bad_checksums: u64,
    pub bytes_processed: u64,
    pub not_a_clienthello: u64,
    pub extension_misparsed: u64,
    pub client_hello_misparsed: u64,
}

impl StatsTracker {
    pub fn new() -> StatsTracker {
        StatsTracker {
            last_print: time::now(),
            fingerprints_seen: 0,
            fingerprint_checks: 0,
            sfingerprints_seen: 0,
            sfingerprint_checks: 0,
            all_packets_total: 0,
            bad_checksums: 0,
            bytes_processed: 0,
            not_a_clienthello: 0,
            extension_misparsed: 0,
            client_hello_misparsed: 0,
        }
    }

    pub fn print_avg_stats(&mut self) {
        let curr_time = time::now();
        let diff = curr_time.sub(self.last_print);
        let diff_float = match diff.num_nanoseconds() {
            Some(diff_float) => diff_float as f64 * 0.000000001,
            None => {
                println!("[WARNING] stats time diff is too big!");
                return
            }
        };
        if diff_float < 10e-3 {
            println!("[WARNING] print stats slower!");
            return
        }

        const BYTES_TO_GBPS: f64 = (1000 * 1000 * 1000 / 8) as f64;

        let percent_misparsed;
        if self.fingerprint_checks != 0 {
            percent_misparsed = self.client_hello_misparsed as f64 / self.fingerprint_checks as f64;
        } else {
            percent_misparsed = 0 as f64;
        }

        println!("[STATS] fingerprints: found {:.2} with {:.2} checks; \
         not a CH: {:.2} misparsed CH: {:.2} misparsed extention: {:2}; \
         sfingerprints: found {:.2} with {:.2} checks; \
         packets: {:.2} (bad_checksums: {:.2}); Gbps: {:.4}",
                 self.fingerprints_seen as f64 / diff_float,
                 self.fingerprint_checks as f64 / diff_float,
                 self.not_a_clienthello as f64 / diff_float,
                 self.client_hello_misparsed as f64 / diff_float,
                 self.extension_misparsed as f64 / diff_float,
                 self.sfingerprints_seen as f64 / diff_float,
                 self.sfingerprint_checks as f64 / diff_float,
                 self.all_packets_total as f64 / diff_float,
                 self.bad_checksums as f64 / diff_float,
                 self.bytes_processed as f64 / (BYTES_TO_GBPS * diff_float),
        );

        self.fingerprints_seen = 0;
        self.fingerprint_checks = 0;
        self.sfingerprints_seen = 0;
        self.sfingerprint_checks = 0;
        self.all_packets_total = 0;
        self.bad_checksums = 0;
        self.bytes_processed = 0;
        self.not_a_clienthello = 0;
        self.extension_misparsed = 0;
        self.client_hello_misparsed = 0;

        self.last_print = curr_time;
    }

    pub fn store_clienthello_error(&mut self, err: HelloParseError) {
        match err {
            HelloParseError::ShortBuffer |
            HelloParseError::NotAHandshake |
            HelloParseError::UnknownRecordTLSVersion |
            HelloParseError::ShortOuterRecord |
            HelloParseError::NotAClientHello => {
                self.not_a_clienthello += 1;
            }
            HelloParseError::InnerOuterRecordLenContradict |
            HelloParseError::UnknownChTLSVersion |
            HelloParseError::SessionIDLenExceedBuf |
            HelloParseError::CiphersuiteLenMisparse |
            HelloParseError::CompressionLenExceedBuf |
            HelloParseError::ExtensionsLenExceedBuf |
            HelloParseError::ShortExtensionHeader |
            HelloParseError::ExtensionLenExceedBuf => {
                self.client_hello_misparsed += 1;
            }
            HelloParseError::KeyShareExtShort |
            HelloParseError::KeyShareExtLong |
            HelloParseError::KeyShareExtLenMisparse |
            HelloParseError::PskKeyExchangeModesExtShort |
            HelloParseError::PskKeyExchangeModesExtLenMisparse |
            HelloParseError::SupportedVersionsExtShort |
            HelloParseError::SupportedVersionsExtLenMisparse => {
                println!("{:?}", err);
                self.extension_misparsed += 1;
            }
            HelloParseError::NotAServerHello => {
                panic!("Got NotAServerHello error from parsing ClientHello")
            }
        }
    }
}
