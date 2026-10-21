//! PCAP/PCAPNG packet extraction and 5-tuple flow aggregation.
//!
//! Streams the capture (constant memory in the packet path; flow state is
//! bounded by active-flow count). Flows are bidirectional: keys are
//! direction-normalized so both halves of a conversation aggregate into one
//! record, with fwd_*/bwd_* counters split by which side matches the key.
//! Flows split on inactive timeout (default 15s) and active timeout
//! (default 60s).
//!
//! By default a record's src is the key's lower-sorting endpoint, so src → dst
//! says nothing about who opened the flow. With `initiator_order` src is the
//! initiator instead (see [`InitiatorBasis`]) and fwd_* counts initiator →
//! responder. Aggregation is the same either way; only the written row differs.

use std::collections::HashMap;
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{Block, PcapBlockOwned, PcapError, create_reader};

use crate::schema::{CanonicalFlow, PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP, flows_to_batch};
use crate::writer::write_parquet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Default active timeout (seconds): max age of an open flow record.
pub const DEFAULT_ACTIVE_TIMEOUT_SECS: u64 = 60;
/// Default inactive timeout (seconds): idle gap before closing a flow record.
pub const DEFAULT_INACTIVE_TIMEOUT_SECS: u64 = 15;

const LINKTYPE_ETHERNET: u16 = 1;

/// Active/inactive timeouts for PCAP flow aggregation (microseconds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowTimeouts {
    pub active_usec: i64,
    pub inactive_usec: i64,
}

impl FlowTimeouts {
    /// Build timeouts from integer seconds. Both must be `> 0` and
    /// `inactive_secs <= active_secs`.
    pub fn from_secs(active_secs: u64, inactive_secs: u64) -> Result<Self> {
        if active_secs == 0 || inactive_secs == 0 {
            return Err("active and inactive timeouts must be > 0 seconds".into());
        }
        if inactive_secs > active_secs {
            return Err(format!(
                "inactive timeout ({inactive_secs}s) must be <= active timeout ({active_secs}s)"
            )
            .into());
        }
        Ok(Self {
            active_usec: (active_secs as i64) * 1_000_000,
            inactive_usec: (inactive_secs as i64) * 1_000_000,
        })
    }
}

struct Packet {
    timestamp: i64, // epoch microseconds
    src_ip: String,
    dest_ip: String,
    src_port: u16,
    dest_port: u16,
    protocol: u8,
    packet_bytes: i64,
    syn: bool, // TCP flags; false for other protocols
    ack: bool,
}

/// How a flow's initiator was decided, weakest first. Each flow starts from
/// its first packet's sender and takes a stronger signal when one arrives (a
/// SYN can follow a stray ACK or RST, or arrive out of order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum InitiatorBasis {
    /// The sender of the first packet seen: UDP, ICMP, or TCP joined mid-stream.
    /// Often wrong for flows already open when the capture started.
    FirstPacket,
    /// The receiver of a SYN-ACK: the capture missed the SYN.
    SynAck,
    /// The sender of a SYN without ACK.
    Syn,
}

fn initiator_basis(p: &Packet) -> InitiatorBasis {
    match (p.syn, p.ack) {
        (true, false) => InitiatorBasis::Syn,
        (true, true) => InitiatorBasis::SynAck,
        _ => InitiatorBasis::FirstPacket,
    }
}

fn initiator_of(p: &Packet, basis: InitiatorBasis) -> (String, u16) {
    if basis == InitiatorBasis::SynAck {
        (p.dest_ip.clone(), p.dest_port)
    } else {
        (p.src_ip.clone(), p.src_port)
    }
}

type FlowKey = (String, String, u16, u16, u8);

struct FlowState {
    first_timestamp: i64,
    last_timestamp: i64,
    fwd_bytes: i64,
    fwd_pkts: i64,
    bwd_bytes: i64,
    bwd_pkts: i64,
    initiator: (String, u16),
    basis: InitiatorBasis,
}

struct FlowRecord {
    key: FlowKey,
    state: FlowState,
}

pub fn pcap_to_parquet(
    input: &str,
    output: &str,
    timeouts: FlowTimeouts,
    initiator_order: bool,
) -> Result<usize> {
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
                            ingest_packet(p, &mut active, &mut flows, timeouts);
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
                            ingest_packet(p, &mut active, &mut flows, timeouts);
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

    let canonical: Vec<CanonicalFlow> = flows
        .iter()
        .map(|f| flow_to_canonical(f, initiator_order))
        .collect();
    let batch = flows_to_batch(&canonical)?;
    write_parquet(&batch, output)?;
    Ok(batch.num_rows())
}

fn flow_to_canonical(flow: &FlowRecord, initiator_order: bool) -> CanonicalFlow {
    let s = &flow.state;
    let k = &flow.key;
    // Flows between two ports of one address keep sorted order: consumers that
    // orient flows by address can't tell those endpoints apart.
    let swap = initiator_order
        && k.0 != k.1
        && (s.initiator.0.as_str(), s.initiator.1) != (k.0.as_str(), k.2);
    let (src_ip, dest_ip, src_port, dest_port) = if swap {
        (&k.1, &k.0, k.3, k.2)
    } else {
        (&k.0, &k.1, k.2, k.3)
    };
    let (fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts) = if swap {
        (s.bwd_bytes, s.fwd_bytes, s.bwd_pkts, s.fwd_pkts)
    } else {
        (s.fwd_bytes, s.bwd_bytes, s.fwd_pkts, s.bwd_pkts)
    };
    CanonicalFlow {
        timestamp: s.first_timestamp,
        src_ip: src_ip.clone(),
        dest_ip: dest_ip.clone(),
        src_port: src_port as i32,
        dest_port: dest_port as i32,
        fwd_bytes,
        bwd_bytes,
        fwd_pkts: Some(fwd_pkts),
        bwd_pkts: Some(bwd_pkts),
        flow_dur: (s.last_timestamp - s.first_timestamp) as f64 / 1e6,
        protocol: Some(k.4 as i32),
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

    let (mut syn, mut ack) = (false, false);
    let (src_port, dest_port, protocol) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            (syn, ack) = (tcp.syn(), tcp.ack());
            (tcp.source_port(), tcp.destination_port(), PROTOCOL_TCP)
        }
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
        syn,
        ack,
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
    timeouts: FlowTimeouts,
) {
    let key = make_flow_key(&packet);
    let ts = packet.timestamp;

    // A record closed by the active timeout is continued by the next one, which
    // keeps its initiator; after an idle gap the next record decides afresh.
    let mut continued = None;
    if let Some(state) = active.get(&key) {
        let idle = ts - state.last_timestamp > timeouts.inactive_usec;
        if idle || ts - state.first_timestamp > timeouts.active_usec {
            let state = active.remove(&key).unwrap();
            if !idle {
                continued = Some((state.initiator.clone(), state.basis));
            }
            flows.push(FlowRecord {
                key: key.clone(),
                state,
            });
        }
    }

    let basis = initiator_basis(&packet);
    let state = active.entry(key.clone()).or_insert_with(|| {
        let (initiator, basis) = continued.unwrap_or_else(|| (initiator_of(&packet, basis), basis));
        FlowState {
            first_timestamp: ts,
            last_timestamp: ts,
            fwd_bytes: 0,
            fwd_pkts: 0,
            bwd_bytes: 0,
            bwd_pkts: 0,
            initiator,
            basis,
        }
    });
    if basis > state.basis {
        state.initiator = initiator_of(&packet, basis);
        state.basis = basis;
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(ts_usec: i64) -> Packet {
        Packet {
            timestamp: ts_usec,
            src_ip: "10.0.0.1".into(),
            dest_ip: "10.0.0.2".into(),
            src_port: 12345,
            dest_port: 80,
            protocol: PROTOCOL_TCP,
            packet_bytes: 100,
            syn: false,
            ack: true,
        }
    }

    fn aggregate(packets: Vec<Packet>, timeouts: FlowTimeouts) -> Vec<FlowRecord> {
        let mut flows = Vec::new();
        let mut active = HashMap::new();
        for p in packets {
            ingest_packet(p, &mut active, &mut flows, timeouts);
        }
        flows.extend(
            active
                .into_iter()
                .map(|(key, state)| FlowRecord { key, state }),
        );
        flows.sort_by_key(|f| (f.state.first_timestamp, f.key.clone()));
        flows
    }

    fn defaults() -> FlowTimeouts {
        FlowTimeouts::from_secs(DEFAULT_ACTIVE_TIMEOUT_SECS, DEFAULT_INACTIVE_TIMEOUT_SECS)
            .expect("default timeouts are valid")
    }

    #[test]
    fn default_timeouts_are_60s_active_15s_inactive() {
        let t = defaults();
        assert_eq!(t.active_usec, 60 * 1_000_000);
        assert_eq!(t.inactive_usec, 15 * 1_000_000);
        assert_eq!(DEFAULT_ACTIVE_TIMEOUT_SECS, 60);
        assert_eq!(DEFAULT_INACTIVE_TIMEOUT_SECS, 15);
    }

    #[test]
    fn from_secs_rejects_zero_and_inactive_gt_active() {
        assert!(FlowTimeouts::from_secs(0, 15).is_err());
        assert!(FlowTimeouts::from_secs(60, 0).is_err());
        assert!(FlowTimeouts::from_secs(15, 60).is_err());
        assert!(FlowTimeouts::from_secs(60, 60).is_ok());
    }

    #[test]
    fn inactive_timeout_splits_after_idle_gap() {
        // Defaults: inactive 15s. Gap of exactly 15s must NOT split (`>`);
        // gap of 15s + 1µs must.
        let timeouts = defaults();
        let no_split = aggregate(vec![pkt(0), pkt(15_000_000)], timeouts);
        assert_eq!(no_split.len(), 1);
        assert_eq!(no_split[0].state.fwd_pkts, 2);

        let split = aggregate(vec![pkt(0), pkt(15_000_001)], timeouts);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0].state.fwd_pkts, 1);
        assert_eq!(split[1].state.fwd_pkts, 1);
    }

    #[test]
    fn active_timeout_splits_long_continuous_flow() {
        // Defaults: active 60s. Keep inter-packet gaps under inactive (15s)
        // so only the active axis can fire. Age exactly 60s must NOT split;
        // age of 60s + 1µs must.
        let timeouts = defaults();
        let continuous: Vec<Packet> = (0..=6).map(|i| pkt(i * 10_000_000)).collect();
        let no_split = aggregate(continuous, timeouts);
        assert_eq!(no_split.len(), 1);
        assert_eq!(no_split[0].state.fwd_pkts, 7);

        let mut continuous_then_over = (0..=5).map(|i| pkt(i * 10_000_000)).collect::<Vec<_>>();
        continuous_then_over.push(pkt(60_000_001));
        let split = aggregate(continuous_then_over, timeouts);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0].state.fwd_pkts, 6);
        assert_eq!(split[1].state.fwd_pkts, 1);
    }

    // ── initiator order ──────────────────────────────────────────────────────

    const CLIENT: &str = "10.0.0.9"; // sorts after SERVER: "10.0.0.10" < "10.0.0.9"
    const SERVER: &str = "10.0.0.10";

    fn tcp(ts: i64, from_client: bool, syn: bool, ack: bool, bytes: i64) -> Packet {
        let (src, dst, sport, dport) = if from_client {
            (CLIENT, SERVER, 51000, 443)
        } else {
            (SERVER, CLIENT, 443, 51000)
        };
        Packet {
            timestamp: ts,
            src_ip: src.into(),
            dest_ip: dst.into(),
            src_port: sport,
            dest_port: dport,
            protocol: PROTOCOL_TCP,
            packet_bytes: bytes,
            syn,
            ack,
        }
    }

    fn rows(packets: Vec<Packet>, initiator_order: bool) -> Vec<CanonicalFlow> {
        aggregate(packets, defaults())
            .iter()
            .map(|f| flow_to_canonical(f, initiator_order))
            .collect()
    }

    fn handshake() -> Vec<Packet> {
        vec![
            tcp(0, true, true, false, 60),    // SYN
            tcp(1, false, true, true, 60),    // SYN-ACK
            tcp(2, true, false, true, 500),   // request
            tcp(3, false, false, true, 9000), // response
        ]
    }

    #[test]
    fn initiator_order_puts_the_client_in_src() {
        let r = &rows(handshake(), true)[0];
        assert_eq!((r.src_ip.as_str(), r.src_port), (CLIENT, 51000));
        assert_eq!((r.dest_ip.as_str(), r.dest_port), (SERVER, 443));
        assert_eq!((r.fwd_pkts, r.bwd_pkts), (Some(2), Some(2)));
        assert_eq!((r.fwd_bytes, r.bwd_bytes), (560, 9060)); // client → server, server → client
    }

    #[test]
    fn without_the_option_src_is_the_lower_sorting_endpoint() {
        let r = &rows(handshake(), false)[0];
        assert_eq!((r.src_ip.as_str(), r.src_port), (SERVER, 443));
        assert_eq!((r.fwd_bytes, r.bwd_bytes), (9060, 560));
    }

    #[test]
    fn a_syn_ack_without_its_syn_names_its_receiver() {
        let p = vec![tcp(0, false, true, true, 60), tcp(1, true, false, true, 60)];
        assert_eq!(rows(p, true)[0].src_ip, CLIENT);
    }

    #[test]
    fn a_syn_after_a_stray_packet_wins() {
        let p = vec![
            tcp(0, false, false, true, 60), // a late ACK from the server
            tcp(1, true, true, false, 60),
            tcp(2, false, true, true, 60),
        ];
        assert_eq!(rows(p, true)[0].src_ip, CLIENT);
    }

    #[test]
    fn mid_stream_tcp_and_udp_take_the_first_packets_sender() {
        let mid = vec![
            tcp(0, false, false, true, 60),
            tcp(1, true, false, true, 60),
        ];
        assert_eq!(rows(mid, true)[0].src_ip, SERVER); // a guess, and here a wrong one

        let mut dns = tcp(0, true, false, false, 80);
        dns.protocol = PROTOCOL_UDP;
        dns.dest_port = 53;
        let r = &rows(vec![dns], true)[0];
        assert_eq!((r.src_ip.as_str(), r.dest_port), (CLIENT, 53));
    }

    #[test]
    fn icmp_request_and_reply_are_one_way_flows_from_their_senders() {
        let icmp = |ts, from_client: bool, icmp_type| {
            let mut p = tcp(ts, from_client, false, false, 84);
            p.protocol = PROTOCOL_ICMP;
            (p.src_port, p.dest_port) = (icmp_type, 0);
            p
        };
        let r = rows(vec![icmp(0, true, 8), icmp(1, false, 0)], true);
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].src_ip.as_str(), r[0].src_port, r[0].fwd_pkts),
            (CLIENT, 8, Some(1))
        );
        assert_eq!(
            (r[1].src_ip.as_str(), r[1].src_port, r[1].fwd_pkts),
            (SERVER, 0, Some(1))
        );
    }

    #[test]
    fn flows_within_one_address_keep_sorted_order() {
        let mut p = tcp(0, true, true, false, 60);
        (p.src_ip, p.dest_ip, p.src_port, p.dest_port) =
            ("10.0.0.1".into(), "10.0.0.1".into(), 5000, 80);
        let r = &rows(vec![p], true)[0];
        assert_eq!((r.src_port, r.dest_port), (80, 5000)); // as without the option
    }

    #[test]
    fn an_active_timeout_split_keeps_the_initiator() {
        let mut p = handshake();
        p.extend((1..=6).map(|i| tcp(i * 10_000_000, true, false, true, 100)));
        p.push(tcp(60_000_001, false, false, true, 100)); // the continuation starts with the server
        let r = rows(p, true);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].src_ip, CLIENT);
        assert_eq!((r[1].fwd_pkts, r[1].bwd_pkts), (Some(0), Some(1)));
    }

    #[test]
    fn a_flow_restarted_after_an_idle_gap_decides_again() {
        let mut p = handshake();
        p.push(tcp(16_000_000, false, false, true, 100)); // > 15s idle, server first
        let r = rows(p, true);
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].src_ip.as_str(), r[1].src_ip.as_str()),
            (CLIENT, SERVER)
        );
    }
}
