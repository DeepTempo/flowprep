//! nfdump/nfcapd binary flow-file reader.
//!
//! nfcapd files are nfdump's native on-disk format: a typed binary container
//! of already-aggregated flow records (NetFlow v5/v9, IPFIX, sFlow collected by
//! `nfcapd`), not packets. So unlike the pcap reader there is no 5-tuple
//! aggregation here — each stored flow maps to exactly one canonical flow.
//!
//! Parsing the *container* (file header, data blocks, LZO/BZ2/LZ4/ZSTD block
//! decompression, the appendix, and the two record layouts that exist in the
//! wild — the V1 "common" record written by nfdump 1.6.x and the V2 "v3"
//! extension record written by 1.7.x) is delegated to the `nfdump` crate, the
//! same way the pcap reader delegates pcap/pcapng framing to `pcap-parser`.
//! flowprep stays the canonicalization layer rather than re-implementing every
//! binary container.
//!
//! nfdump stores per-direction records: a record carries one direction's
//! byte/packet totals. Biflow-capable V3 exporters add a reverse counter
//! (`cnt_flow`), which maps to `bwd_*`; single-counter records zero-fill
//! `bwd_*`, the same convention the CSV and OCSF readers use. A record that
//! genuinely lacks IP addresses (or a generic-flow block) is counted and
//! skipped, but if *every* record is unconvertible the output would be empty —
//! that is reported as an error so a silent zero-row parquet never looks like
//! success.
//!
//! Limitation: the very old pre-1.6 "common v0" record type is not decoded by
//! the underlying reader; files containing only those records convert to zero
//! flows and are reported as an error rather than a silent empty file.

use std::fs::File;

use crate::nfdump::NfFileReader;
use crate::nfdump::error::NfdumpError;
use crate::nfdump::nfx_v3::RecordV3;
use crate::nfdump::record::{Record, RecordKind};

use crate::schema::{CanonicalFlow, flows_to_batch};
use crate::writer::write_parquet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Tally reported to stderr so a conversion that drops records is visible.
#[derive(Default)]
struct Summary {
    converted: usize,
    skipped_no_ip: usize,
}

pub fn nfcapd_to_parquet(input: &str, output: &str) -> Result<usize> {
    let file = File::open(input)?;
    let mut reader = NfFileReader::new(file)
        .map_err(|e| format!("{input} is not a readable nfdump/nfcapd file: {e}"))?;

    let mut summary = Summary::default();
    let mut flows = Vec::new();
    loop {
        match reader.read_record() {
            // read_record() yields only flow records (it consumes extension
            // maps, exporters, stat/ident blocks internally); the catch-all
            // below stays defensive against future record kinds.
            Ok(RecordKind::Record(r)) => push(record_to_canonical(&r), &mut flows, &mut summary),
            Ok(RecordKind::RecordV3(r)) => {
                push(record_v3_to_canonical(&r), &mut flows, &mut summary)
            }
            Ok(_) => {}
            Err(NfdumpError::EOF) => break,
            Err(e) => return Err(format!("error reading nfdump records from {input}: {e}").into()),
        }
    }

    if flows.is_empty() {
        return Err(format!(
            "no convertible flow records in {input} \
             ({} records skipped for missing IP addresses); \
             pre-1.6 'common v0' records are not supported",
            summary.skipped_no_ip
        )
        .into());
    }

    eprintln!(
        "nfcapd: {} flows converted{}",
        summary.converted,
        if summary.skipped_no_ip > 0 {
            format!(" ({} skipped: no IP addresses)", summary.skipped_no_ip)
        } else {
            String::new()
        }
    );

    let batch = flows_to_batch(&flows)?;
    write_parquet(&batch, output)?;
    Ok(batch.num_rows())
}

fn push(flow: Option<CanonicalFlow>, flows: &mut Vec<CanonicalFlow>, summary: &mut Summary) {
    match flow {
        Some(f) => {
            flows.push(f);
            summary.converted += 1;
        }
        None => summary.skipped_no_ip += 1,
    }
}

/// Non-negative elapsed milliseconds as canonical float seconds. Clamps the
/// rare last-before-first record rather than emitting a negative duration.
fn dur_secs(first_ms: i64, last_ms: i64) -> f64 {
    (last_ms - first_ms).max(0) as f64 / 1000.0
}

/// V2/V3 extension record (nfdump 1.7.x). Endpoints come from the IPv4 or IPv6
/// flow block; ports, counters, proto, and millisecond-epoch times from the
/// generic-flow block. The optional `cnt_flow` block is the reverse direction.
fn record_v3_to_canonical(r: &RecordV3) -> Option<CanonicalFlow> {
    let g = r.generic_flow.as_ref()?;
    let (src_ip, dest_ip) = if let Some(v4) = &r.ipv4_flow {
        (v4.src_addr.to_string(), v4.dst_addr.to_string())
    } else if let Some(v6) = &r.ipv6_flow {
        (v6.src_addr.to_string(), v6.dst_addr.to_string())
    } else {
        return None;
    };
    let (bwd_bytes, bwd_pkts) = match &r.cnt_flow {
        Some(c) => (c.out_bytes as i64, Some(c.out_packets as i64)),
        None => (0, None),
    };
    Some(CanonicalFlow {
        timestamp: (g.msec_first as i64) * 1000, // epoch ms -> µs
        src_ip,
        dest_ip,
        src_port: g.src_port as i32,
        dest_port: g.dst_port as i32,
        fwd_bytes: g.in_bytes as i64,
        bwd_bytes,
        fwd_pkts: Some(g.in_packets as i64),
        bwd_pkts,
        flow_dur: dur_secs(g.msec_first as i64, g.msec_last as i64), // ms -> s
        protocol: Some(g.proto as i32),
    })
}

/// V1 "common" record (nfdump 1.6.x). Time is split into epoch seconds
/// (`first`/`last`) plus a millisecond component (`msec_first`/`msec_last`).
/// V1 records are single-counter, so `bwd_*` is zero-filled.
fn record_to_canonical(r: &Record) -> Option<CanonicalFlow> {
    let first_ms = r.first as i64 * 1000 + r.msec_first as i64;
    let last_ms = r.last as i64 * 1000 + r.msec_last as i64;
    Some(CanonicalFlow {
        timestamp: first_ms * 1000, // ms -> µs
        src_ip: r.src_addr.to_string(),
        dest_ip: r.dst_addr.to_string(),
        src_port: r.src_port as i32,
        dest_port: r.dst_port as i32,
        fwd_bytes: r.bytes as i64,
        bwd_bytes: 0,
        fwd_pkts: Some(r.packets as i64),
        bwd_pkts: None,
        flow_dur: dur_secs(first_ms, last_ms),
        protocol: Some(r.prot as i32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfdump::nfx_v3::{ExCntFlow, ExGenericFlow, ExIpv4Flow, ExIpv6Flow, RecordHeaderV3};
    use crate::nfdump::record::NfFileRecordHeader;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn generic(msec_first: u64, msec_last: u64, in_packets: u64, in_bytes: u64) -> ExGenericFlow {
        ExGenericFlow {
            msec_first,
            msec_last,
            msec_received: msec_first,
            in_packets,
            in_bytes,
            src_port: 44321,
            dst_port: 443,
            proto: 6,
            tcp_flags: 0,
            fwd_status: 0,
            src_tos: 0,
        }
    }

    fn v3(
        generic_flow: Option<ExGenericFlow>,
        ipv4_flow: Option<ExIpv4Flow>,
        ipv6_flow: Option<ExIpv6Flow>,
        cnt_flow: Option<ExCntFlow>,
    ) -> RecordV3 {
        RecordV3 {
            head: RecordHeaderV3 {
                header: NfFileRecordHeader { rtype: 11, size: 0 },
                num_elements: 0,
                engine_type: 0,
                engine_id: 0,
                exporter_id: 0,
                flags: 0,
                nf_version: 9,
            },
            generic_flow,
            ipv4_flow,
            ipv6_flow,
            flow_misc: None,
            cnt_flow,
            vlan: None,
            as_routing: None,
            sampler_info: None,
            nsel_xlate_port: None,
            bgp_next_hop_ipv4: None,
            bgp_next_hop_ipv6: None,
            ip_next_hop_ipv4: None,
            ip_next_hop_ipv6: None,
            ip_received_ipv4: None,
            ip_received_ipv6: None,
            in_payload: None,
            mac_address: None,
            layer2: None,
            mpls: None,
            tun_ipv4: None,
            tun_ipv6: None,
        }
    }

    #[test]
    fn v3_converts_units_and_biflow_counter() {
        let r = v3(
            Some(generic(1_699_999_900_000, 1_699_999_902_500, 8, 1200)),
            Some(ExIpv4Flow {
                src_addr: Ipv4Addr::new(10, 0, 0, 1),
                dst_addr: Ipv4Addr::new(10, 0, 0, 2),
            }),
            None,
            Some(ExCntFlow {
                flows: 1,
                out_packets: 12,
                out_bytes: 34000,
            }),
        );
        let f = record_v3_to_canonical(&r).unwrap();
        assert_eq!(f.timestamp, 1_699_999_900_000_000); // ms -> µs
        assert_eq!(f.flow_dur, 2.5); // (last-first) ms -> s
        assert_eq!((&f.src_ip[..], &f.dest_ip[..]), ("10.0.0.1", "10.0.0.2"));
        assert_eq!((f.src_port, f.dest_port), (44321, 443));
        assert_eq!((f.fwd_bytes, f.bwd_bytes), (1200, 34000));
        assert_eq!((f.fwd_pkts, f.bwd_pkts), (Some(8), Some(12)));
        assert_eq!(f.protocol, Some(6));
    }

    #[test]
    fn v3_single_counter_zero_fills_bwd() {
        let r = v3(
            Some(generic(1_000, 1_000, 1, 64)),
            Some(ExIpv4Flow {
                src_addr: Ipv4Addr::new(192, 168, 1, 10),
                dst_addr: Ipv4Addr::new(8, 8, 8, 8),
            }),
            None,
            None,
        );
        let f = record_v3_to_canonical(&r).unwrap();
        assert_eq!((f.fwd_bytes, f.bwd_bytes), (64, 0));
        assert_eq!((f.fwd_pkts, f.bwd_pkts), (Some(1), None));
        assert_eq!(f.flow_dur, 0.0);
    }

    #[test]
    fn v3_reads_ipv6_endpoints() {
        let r = v3(
            Some(generic(1_000, 2_000, 3, 300)),
            None,
            Some(ExIpv6Flow {
                src_addr: Ipv6Addr::LOCALHOST,
                dst_addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            }),
            None,
        );
        let f = record_v3_to_canonical(&r).unwrap();
        assert_eq!(&f.dest_ip[..], "2001:db8::1");
        assert_eq!(f.flow_dur, 1.0);
    }

    #[test]
    fn v3_without_endpoints_is_skipped() {
        let r = v3(Some(generic(1_000, 2_000, 1, 1)), None, None, None);
        assert!(record_v3_to_canonical(&r).is_none());
    }

    #[test]
    fn v1_common_record_splits_epoch_and_msec() {
        let r = Record {
            head: NfFileRecordHeader { rtype: 10, size: 0 },
            flags: 0,
            ext_map: 0,
            msec_first: 250,
            msec_last: 750,
            first: 1_699_999_900,
            last: 1_699_999_902,
            fwd_status: 0,
            tcp_flags: 0,
            prot: 17,
            tos: 0,
            src_port: 51000,
            dst_port: 53,
            exporter_sysid: 1,
            bi_flow_dir: 0,
            flow_end_reason: 0,
            src_addr: Ipv4Addr::new(192, 168, 1, 10).into(),
            dst_addr: Ipv4Addr::new(8, 8, 8, 8).into(),
            packets: 4,
            bytes: 512,
            input: None,
            output: None,
            src_as: None,
            dst_as: None,
        };
        let f = record_to_canonical(&r).unwrap();
        // (1_699_999_900*1000 + 250) ms -> µs
        assert_eq!(f.timestamp, 1_699_999_900_250_000);
        // (902_750 - 900_250) ms = 2.5 s
        assert_eq!(f.flow_dur, 2.5);
        assert_eq!((f.fwd_bytes, f.bwd_bytes), (512, 0));
        assert_eq!((f.fwd_pkts, f.bwd_pkts), (Some(4), None));
        assert_eq!(f.protocol, Some(17));
    }
}
