//! PCAP/PCAPNG packet extraction and 5-tuple flow aggregation.
//!
//! Streams the capture (constant memory in the packet path; flow state is
//! bounded by active-flow count). Flows are bidirectional: keys are
//! direction-normalized so both halves of a conversation aggregate into one
//! record, with fwd_*/bwd_* counters split by which side matches the key.
//! Flows split on idle timeout (60s) and max duration (1h).

use std::collections::HashMap;
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{Block, PcapBlockOwned, PcapError, create_reader};

use crate::schema::{CanonicalFlow, PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP, flows_to_batch};
use crate::writer::write_parquet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const IDLE_TIMEOUT_USEC: i64 = 60 * 1_000_000;
const MAX_FLOW_DURATION_USEC: i64 = 3600 * 1_000_000;

const LINKTYPE_ETHERNET: u16 = 1;

struct Packet {
    timestamp: i64, // epoch microseconds
    src_ip: String,
    dest_ip: String,
    src_port: u16,
    dest_port: u16,
    protocol: u8,
    packet_bytes: i64,
}

type FlowKey = (String, String, u16, u16, u8);

struct FlowState {
    first_timestamp: i64,
    last_timestamp: i64,
    fwd_bytes: i64,
    fwd_pkts: i64,
    bwd_bytes: i64,
    bwd_pkts: i64,
}

struct FlowRecord {
    key: FlowKey,
    state: FlowState,
}

pub fn pcap_to_parquet(input: &str, output: &str) -> Result<usize> {
    let mut flows: Vec<FlowRecord> = Vec::new();
    let mut active: HashMap<FlowKey, FlowState> = HashMap::new();

    let file = File::open(input)?;
    let mut reader = create_reader(1 << 20, file)?;
    let mut linktype: u16 = LINKTYPE_ETHERNET;
    let mut legacy_nanos = false;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network.0 as u16;
                        legacy_nanos = hdr.magic_number == 0xa1b2_3c4d;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let frac_usec = if legacy_nanos {
                            (b.ts_usec / 1000) as i64
                        } else {
                            b.ts_usec as i64
                        };
                        let ts = b.ts_sec as i64 * 1_000_000 + frac_usec;
                        if let Some(p) = parse_packet(b.data, linktype, ts, b.origlen as i64) {
                            ingest_packet(p, &mut active, &mut flows);
                        }
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        linktype = idb.linktype.0 as u16;
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        // Default if_tsresol (1e-6); per-interface overrides
                        // are out of spike scope.
                        let ts = ((epb.ts_high as i64) << 32) | epb.ts_low as i64;
                        if let Some(p) = parse_packet(epb.data, linktype, ts, epb.origlen as i64) {
                            ingest_packet(p, &mut active, &mut flows);
                        }
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                // refill's error borrows the reader buffer; drop it and
                // surface an owned error instead.
                if reader.refill().is_err() {
                    return Err("pcap refill failed (truncated capture?)".into());
                }
            }
            Err(e) => return Err(format!("pcap parse error: {e:?}").into()),
        }
    }

    flows.extend(
        active
            .into_iter()
            .map(|(key, state)| FlowRecord { key, state }),
    );
    // HashMap drain order is nondeterministic; sort for stable output.
    flows.sort_by_key(|f| (f.state.first_timestamp, f.key.clone()));

    let canonical: Vec<CanonicalFlow> = flows.iter().map(flow_to_canonical).collect();
    let batch = flows_to_batch(&canonical)?;
    write_parquet(&batch, output)?;
    Ok(batch.num_rows())
}

fn flow_to_canonical(flow: &FlowRecord) -> CanonicalFlow {
    let s = &flow.state;
    CanonicalFlow {
        timestamp: s.first_timestamp,
        src_ip: flow.key.0.clone(),
        dest_ip: flow.key.1.clone(),
        src_port: flow.key.2 as i32,
        dest_port: flow.key.3 as i32,
        fwd_bytes: s.fwd_bytes,
        bwd_bytes: s.bwd_bytes,
        fwd_pkts: Some(s.fwd_pkts),
        bwd_pkts: Some(s.bwd_pkts),
        flow_dur: (s.last_timestamp - s.first_timestamp) as f64 / 1e6,
        protocol: Some(flow.key.4 as i32),
    }
}

fn parse_packet(data: &[u8], linktype: u16, timestamp: i64, origlen: i64) -> Option<Packet> {
    let sliced = if linktype == LINKTYPE_ETHERNET {
        SlicedPacket::from_ethernet(data).ok()?
    } else {
        SlicedPacket::from_ip(data).ok()?
    };

    let (src_ip, dest_ip, ip_protocol) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(v4) => {
            let h = v4.header();
            (
                Ipv4Addr::from(h.source()).to_string(),
                Ipv4Addr::from(h.destination()).to_string(),
                h.protocol().0,
            )
        }
        NetSlice::Ipv6(v6) => {
            let h = v6.header();
            (
                Ipv6Addr::from(h.source()).to_string(),
                Ipv6Addr::from(h.destination()).to_string(),
                h.next_header().0,
            )
        }
        _ => return None,
    };

    let (src_port, dest_port, protocol) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port(), PROTOCOL_TCP),
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port(), PROTOCOL_UDP),
        // ICMP has no ports; type/code stand in so flows still key cleanly.
        Some(TransportSlice::Icmpv4(icmp)) => {
            (icmp.type_u8() as u16, icmp.code_u8() as u16, PROTOCOL_ICMP)
        }
        _ => (0, 0, ip_protocol),
    };

    Some(Packet {
        timestamp,
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        protocol,
        packet_bytes: origlen,
    })
}

fn make_flow_key(p: &Packet) -> FlowKey {
    if (p.src_ip.as_str(), p.src_port) <= (p.dest_ip.as_str(), p.dest_port) {
        (
            p.src_ip.clone(),
            p.dest_ip.clone(),
            p.src_port,
            p.dest_port,
            p.protocol,
        )
    } else {
        (
            p.dest_ip.clone(),
            p.src_ip.clone(),
            p.dest_port,
            p.src_port,
            p.protocol,
        )
    }
}

fn ingest_packet(
    packet: Packet,
    active: &mut HashMap<FlowKey, FlowState>,
    flows: &mut Vec<FlowRecord>,
) {
    let key = make_flow_key(&packet);
    let ts = packet.timestamp;

    if let Some(state) = active.get(&key) {
        if ts - state.last_timestamp > IDLE_TIMEOUT_USEC
            || ts - state.first_timestamp > MAX_FLOW_DURATION_USEC
        {
            let state = active.remove(&key).unwrap();
            flows.push(FlowRecord {
                key: key.clone(),
                state,
            });
        }
    }

    let state = active.entry(key.clone()).or_insert(FlowState {
        first_timestamp: ts,
        last_timestamp: ts,
        fwd_bytes: 0,
        fwd_pkts: 0,
        bwd_bytes: 0,
        bwd_pkts: 0,
    });

    // max(): captures can carry slightly out-of-order packets
    state.last_timestamp = state.last_timestamp.max(ts);

    let is_forward = (packet.src_ip.as_str(), packet.src_port) == (key.0.as_str(), key.2);
    if is_forward {
        state.fwd_bytes += packet.packet_bytes;
        state.fwd_pkts += 1;
    } else {
        state.bwd_bytes += packet.packet_bytes;
        state.bwd_pkts += 1;
    }
}


