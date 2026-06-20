//! Canonicalize nfdump/nfcapd binary flow files into the canonical NetFlow
//! schema.
//!
//! The binary container is parsed by [`crate::nfdump::NfdumpFlowReader`], which
//! yields only flow-bearing fields (in nfdump's epoch-millisecond convention)
//! and surfaces any truncation or corruption as an error. This module is the
//! thin canonicalization layer on top: it converts units (epoch ms ->
//! microseconds, duration ms -> seconds), stringifies addresses, and zero-fills
//! the backward direction for single-counter (non-biflow) records — the same
//! conventions the CSV and OCSF readers use.
//!
//! A record that fails to parse aborts the whole conversion (loud failure); a
//! file with zero convertible flows is reported as an error so an empty parquet
//! never looks like success.

use std::fs::File;

use crate::nfdump::{NfdumpFlow, NfdumpFlowReader};
use crate::schema::{CanonicalFlow, flows_to_batch};
use crate::writer::write_parquet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn nfcapd_to_parquet(input: &str, output: &str) -> Result<usize> {
    let file = File::open(input)?;
    let mut reader = NfdumpFlowReader::new(file)
        .map_err(|e| format!("{input} is not a readable nfdump/nfcapd file: {e}"))?;

    let mut flows = Vec::new();
    loop {
        match reader.next_flow() {
            Ok(Some(flow)) => flows.push(to_canonical(&flow)),
            Ok(None) => break,
            Err(e) => return Err(format!("error reading nfdump records from {input}: {e}").into()),
        }
    }

    if flows.is_empty() {
        return Err(format!(
            "no convertible flow records in {input} \
             (pre-1.6 'common v0' records are not supported)"
        )
        .into());
    }

    eprintln!("nfcapd: {} flows converted", flows.len());

    let batch = flows_to_batch(&flows)?;
    write_parquet(&batch, output)?;
    Ok(batch.num_rows())
}

/// Map one nfdump flow (epoch-ms times) onto the canonical schema (epoch-µs
/// timestamp, float-second duration). Backward counters are zero-filled for
/// single-counter records, matching the canonical convention.
fn to_canonical(f: &NfdumpFlow) -> CanonicalFlow {
    CanonicalFlow {
        timestamp: f.first_ms as i64 * 1000, // epoch ms -> µs
        src_ip: f.src_ip.to_string(),
        dest_ip: f.dst_ip.to_string(),
        src_port: f.src_port as i32,
        dest_port: f.dst_port as i32,
        fwd_bytes: f.fwd_bytes as i64,
        bwd_bytes: f.bwd_bytes.unwrap_or(0) as i64,
        fwd_pkts: Some(f.fwd_pkts as i64),
        bwd_pkts: f.bwd_pkts.map(|p| p as i64),
        // Clamp the rare last-before-first record rather than emit a negative
        // duration; ms -> s.
        flow_dur: (f.last_ms as i64 - f.first_ms as i64).max(0) as f64 / 1000.0,
        protocol: Some(f.protocol as i32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn flow() -> NfdumpFlow {
        NfdumpFlow {
            first_ms: 1_699_999_900_000,
            last_ms: 1_699_999_902_500,
            src_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2).into(),
            src_port: 44321,
            dst_port: 443,
            protocol: 6,
            fwd_bytes: 1200,
            fwd_pkts: 8,
            bwd_bytes: None,
            bwd_pkts: None,
        }
    }

    #[test]
    fn converts_units_and_single_counter() {
        let c = to_canonical(&flow());
        assert_eq!(c.timestamp, 1_699_999_900_000_000); // ms -> µs
        assert_eq!(c.flow_dur, 2.5); // 2500 ms -> s
        assert_eq!(
            (c.src_ip.as_str(), c.dest_ip.as_str()),
            ("10.0.0.1", "10.0.0.2")
        );
        assert_eq!((c.fwd_bytes, c.bwd_bytes), (1200, 0)); // bwd zero-filled
        assert_eq!((c.fwd_pkts, c.bwd_pkts), (Some(8), None));
        assert_eq!(c.protocol, Some(6));
    }

    #[test]
    fn biflow_reverse_counter_maps_to_bwd() {
        let mut f = flow();
        f.bwd_bytes = Some(34000);
        f.bwd_pkts = Some(12);
        let c = to_canonical(&f);
        assert_eq!((c.fwd_bytes, c.bwd_bytes), (1200, 34000));
        assert_eq!((c.fwd_pkts, c.bwd_pkts), (Some(8), Some(12)));
    }

    #[test]
    fn last_before_first_clamps_duration() {
        let mut f = flow();
        f.last_ms = f.first_ms - 5; // pathological ordering
        assert_eq!(to_canonical(&f).flow_dur, 0.0);
    }
}
