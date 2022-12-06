

use postgres::{Client, NoTls};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use byteorder::{ByteOrder, BigEndian};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut client = Client::connect("host=localhost user=postgres", NoTls)?;


    let insert_fingerprint_norm_ext = match client.prepare(
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
            return Err(Box::new(e))
        }
    };

    let insert_fingerprint_mapping = match client.prepare(
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
            return Err(Box::new(e));
        }
    };

    for row in client.query(
        "SELECT
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
        FROM
            fingerprints", 
        &[]
    )? {
        let id_raw: i64 = row.get(0);
        let id = id_raw as u64;
        let record_tls_version: i16 = row.get(1);
        let ch_tls_version: i16 = row.get(2);
        let cipher_suites_raw: Option<&[u8]> = row.get(3);
        let cipher_suites: Vec<u8> = cipher_suites_raw.unwrap().to_vec();

        let compression_methods_raw: Option<&[u8]> = row.get(4);
        let compression_methods: Vec<u8> = compression_methods_raw.unwrap().to_vec();
        let extensions_raw: Option<&[u8]> = row.get(5);
        let extensions: Vec<u8> = extensions_raw.unwrap().to_vec();
        let named_groups_raw: Option<&[u8]> = row.get(6);
        let named_groups: Vec<u8> = named_groups_raw.unwrap().to_vec();
        let ec_point_fmt_raw: Option<&[u8]> = row.get(7);
        let ec_point_fmt: Vec<u8> = ec_point_fmt_raw.unwrap().to_vec();
        let sig_algs_raw: Option<&[u8]> = row.get(8);
        let sig_algs: Vec<u8> = sig_algs_raw.unwrap().to_vec();
        let alpn_raw: Option<&[u8]> = row.get(9);
        let alpn: Vec<u8> = alpn_raw.unwrap().to_vec();
        let key_share_raw: Option<&[u8]> = row.get(10);
        let key_share: Vec<u8> = key_share_raw.unwrap().to_vec();
        let psk_key_exchange_modes_raw: Option<&[u8]> = row.get(11);
        let psk_key_exchange_modes: Vec<u8> = psk_key_exchange_modes_raw.unwrap().to_vec();
        let supported_versions_raw: Option<&[u8]> = row.get(12);
        let supported_versions: Vec<u8> = supported_versions_raw.unwrap().to_vec();
        let cert_compression_algs_raw: Option<&[u8]> = row.get(13);
        let cert_compression_algs: Vec<u8> = cert_compression_algs_raw.unwrap().to_vec();
        let record_size_limit_raw: Option<&[u8]> = row.get(14);
        let record_size_limit: Vec<u8> = record_size_limit_raw.unwrap().to_vec();
        let sorted_extensions: Vec<u8> = sort_extensions(&extensions);

        let original_fingerprint = get_fingerprint(
            record_tls_version,
            ch_tls_version,
            &cipher_suites,
            &compression_methods,
            &extensions,
            &named_groups,
            &ec_point_fmt,
            &sig_algs,
            &alpn,
            &key_share,
            &psk_key_exchange_modes,
            &supported_versions,
            &cert_compression_algs,
            &record_size_limit,
        );

        let normalized_fingerprint = get_fingerprint(
            record_tls_version,
            ch_tls_version,
            &cipher_suites,
            &compression_methods,
            &sorted_extensions,
            &named_groups,
            &ec_point_fmt,
            &sig_algs,
            &alpn,
            &key_share,
            &psk_key_exchange_modes,
            &supported_versions,
            &cert_compression_algs,
            &record_size_limit,
        );

        let mut updated_rows = client.execute(&insert_fingerprint_norm_ext, &[
            &(normalized_fingerprint as i64),
            &(record_tls_version as i16), &(ch_tls_version as i16),
            &cipher_suites, &compression_methods, &sorted_extensions,
            &named_groups, &ec_point_fmt, &sig_algs, &alpn,
            &key_share, &psk_key_exchange_modes, &supported_versions,
            &cert_compression_algs, &record_size_limit,
        ]);
        if updated_rows.is_err() {
            println!("Error updating normalized extension fingerprints: {:?}", updated_rows);
        }

        updated_rows = client.execute(&insert_fingerprint_mapping, &[
            &(original_fingerprint as i64),
            &(normalized_fingerprint as i64),
            &extensions,
        ]);
        if updated_rows.is_err() {
            println!("Error updating normalized extension fingerprints: {:?}", updated_rows);
        }
    }
    Ok(())
}


pub fn get_fingerprint(
    record_tls_version: i16,
    ch_tls_version: i16,
    cipher_suites: &Vec<u8>,
    compression_methods: &Vec<u8>,
    extensions: &Vec<u8>,
    named_groups: &Vec<u8>,
    ec_point_fmt: &Vec<u8>,
    sig_algs: &Vec<u8>,
    alpn: &Vec<u8>,
    key_share: &Vec<u8>,
    psk_key_exchange_modes: &Vec<u8>,
    supported_versions: &Vec<u8>,
    cert_compression_algs: &Vec<u8>,
    record_size_limit: &Vec<u8>,
) -> u64 {
    //let mut s = DefaultHasher::new(); // This is SipHasher13, nobody uses this...
    //let mut s = SipHasher24::new_with_keys(0, 0);
    // Fuck Rust's deprecated "holier than thou" bullshit attitude
    // We'll use SHA1 instead...

    let mut hasher = Sha1::new();
    let versions = (record_tls_version as u32) << 16 | (ch_tls_version as u32);
    hash_u32(&mut hasher, versions);


    hash_u32(&mut hasher, cipher_suites.len() as u32);
    hasher.input(cipher_suites);

    hash_u32(&mut hasher, compression_methods.len() as u32);
    hasher.input(compression_methods);

    hash_u32(&mut hasher, extensions.len() as u32);
    hasher.input(extensions);

    hash_u32(&mut hasher, named_groups.len() as u32);
    hasher.input(named_groups);

    hash_u32(&mut hasher, ec_point_fmt.len() as u32);
    hasher.input(ec_point_fmt);

    hash_u32(&mut hasher, sig_algs.len() as u32);
    hasher.input(sig_algs);

    hash_u32(&mut hasher, alpn.len() as u32);
    hasher.input(alpn);

    hash_u32(&mut hasher, key_share.len() as u32);
    hasher.input(key_share);

    hash_u32(&mut hasher, psk_key_exchange_modes.len() as u32);
    hasher.input(psk_key_exchange_modes);

    hash_u32(&mut hasher, supported_versions.len() as u32);
    hasher.input(supported_versions);

    hash_u32(&mut hasher, cert_compression_algs.len() as u32);
    hasher.input(cert_compression_algs);

    hash_u32(&mut hasher, record_size_limit.len() as u32);
    hasher.input(record_size_limit);

    let mut result = [0; 20];
    hasher.result(&mut result);
    BigEndian::read_u64(&result[0..8])
}

pub fn hash_u32<D: Digest>(h: &mut D, n: u32) {
    h.input(&[((n >> 24) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8]);
}

pub fn u8_to_u16_be(first_byte: u8, second_byte: u8) -> u16 {
    (first_byte as u16) << 8 | (second_byte as u16)
}

pub fn u16_to_u8_be(double: u16) -> Vec<u8> {
    let mut res = Vec::new();
    res.push((double >> 8) as u8);
    res.push((double & 0x00ff) as u8);
    res
}

pub fn vec_u8_to_vec_u16_be(a: &Vec<u8>) -> Vec<u16> {
    let mut result = Vec::with_capacity(a.len() / 2);
    for i in 0..result.capacity() {
        result.push(u8_to_u16_be(a[2 * i], a[2 * i + 1]));
    }
    result
}

pub fn vec_u16_to_vec_u8_be(a: &Vec<u16>) -> Vec<u8> {
    let mut result = Vec::with_capacity(a.len() * 2);
    for i in a {
        result.append(&mut u16_to_u8_be(*i));
    }
    result
}

pub fn sort_extensions(extensions_raw: &Vec<u8>) -> Vec<u8> {
    let mut extensions = vec_u8_to_vec_u16_be(extensions_raw);
    extensions.sort();
    vec_u16_to_vec_u8_be(&extensions)
}