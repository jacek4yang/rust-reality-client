//! Isolate the old Vec::drain compaction versus an accepted-prefix cursor.
//! This is a buffer-operation microbenchmark, NOT a network throughput claim.
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let template: Vec<u8> = (0..8192).map(|n| (n % 251) as u8).collect();
    for chunk in [1_usize, 16, 128, 8192] {
        let mut expected = None;
        for (trial, cursor) in [false, true, true, false].into_iter().enumerate() {
            let started = Instant::now();
            let mut checksum = 0_u64;
            let mut compacted_bytes = 0_u64;
            for _ in 0..1024 {
                let mut buffer = black_box(template.clone());
                if cursor {
                    let mut at = 0;
                    while at < buffer.len() {
                        checksum += u64::from(black_box(&buffer[at..])[0]);
                        at += chunk.min(buffer.len() - at);
                    }
                } else {
                    while !buffer.is_empty() {
                        checksum += u64::from(black_box(&buffer[..])[0]);
                        let count = chunk.min(buffer.len());
                        compacted_bytes += (buffer.len()-count) as u64;
                        buffer.drain(..count);
                    }
                }
                black_box(buffer);
            }
            if let Some(value) = expected { assert_eq!(checksum, value); }
            expected = Some(checksum);
            println!("{{\"chunk\":{chunk},\"trial\":{trial},\"cursor\":{cursor},\"seconds\":{},\"verified_checksum\":{checksum},\"accepted_bytes\":8388608,\"tail_bytes_compacted\":{compacted_bytes}}}", started.elapsed().as_secs_f64());
        }
    }
}
