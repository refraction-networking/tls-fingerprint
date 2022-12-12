use postgres::{Client, NoTls};
use std::error::Error;
use std::collections::HashMap;

const HLL_REGS: usize = 128; // Number of registers for HLL struct
const HLL_BITS: usize = 7; // log2(HLL_REGS)
const MASK: u8 = (1<<(8-HLL_BITS)) - 1;
const IDX_MASK: u8 = 0xff ^ MASK;

fn main() -> Result<(), Box<dyn Error>> {
    let mut norm_fp_counts = HashMap::new();

    let mut client = Client::connect("host=localhost dbname=tls_clienthellos13 user=postgres", NoTls)?;

    let insert_fingerprint_count_est = match client.prepare(
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
            return Err(Box::new(e))
        }
    };

    for row in client.query(
        "SELECT
            id,
            norm_ext_id
        FROM
            fingerprint_map", 
        &[]
    )? {
        let id: i64 = row.get(0);
        let norm_fp_id: i64 = row.get(1);

        update_norm_count(norm_fp_id, id, &mut norm_fp_counts);
    }

    println!("Done populating HashMap, inserting into DB");
    
    let mut count = 0;
    for (norm_fp_id, regs) in norm_fp_counts {
        let updated_rows = client.execute(&insert_fingerprint_count_est, &[
            &(norm_fp_id),
            &regs.to_vec(),
        ]);
        if updated_rows.is_err() {
            println!("Error updating normalized extension fingerprints: {:?}", updated_rows);
        }
        count += 1;
        if count % 100000 == 0 {
            println!("Rows inserted: {:?}", count);
        }
    }
    Ok(())
}

fn update_norm_count(norm_fp_id: i64, h: i64, map: &mut HashMap<i64, [u8; HLL_REGS]>) {
    let estimate = map.entry(norm_fp_id).or_insert([0; HLL_REGS]); // Get existing estimate or insert new one
    let idx = ((((h>>56) as u8) & IDX_MASK) >> (8-HLL_BITS)) as usize; //Get first byte of 8 byte fp AND with IDX_MASK
    let masked_h = h & (((MASK as u64) << 56) as i64); //MASK the position bits in nor
    let pos = (masked_h.leading_zeros() - (HLL_BITS as u32) + 1) as u8; // Remove initial positional bytes, increment by one for leading zeros count
    if pos > estimate[idx] {
        estimate[idx] = pos;
    }
}
