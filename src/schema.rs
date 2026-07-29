//! Canonical NetFlow schema: Arrow schema, alias resolution, unit detection.
//!
//! The alias map and duration-unit rules are loaded at compile time from
//! the canonical schema artifact (schemas/netflow/v1/schema.json), so the
//! schema definition lives in one declarative file rather than in code.

use std::collections::HashMap;
use std::sync::Arc;

use arrow::array::{ArrayRef, Float64Array, Int32Array, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;
use serde_json::Value;

const SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/netflow/v1/schema.json"
));

pub const REQUIRED_FIELDS: &[&str] = &[
    "timestamp",
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "fwd_bytes",
    "flow_dur",
];

pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
pub const PROTOCOL_ICMP: u8 = 1;

pub fn canonical_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("timestamp", DataType::Int64, false), // epoch microseconds
        Field::new("src_ip", DataType::Utf8, false),
        Field::new("dest_ip", DataType::Utf8, false),
        Field::new("src_port", DataType::Int32, false),
        Field::new("dest_port", DataType::Int32, false),
        Field::new("fwd_bytes", DataType::Int64, false),
        Field::new("bwd_bytes", DataType::Int64, false),
        Field::new("fwd_pkts", DataType::Int64, true),
        Field::new("bwd_pkts", DataType::Int64, true),
        Field::new("flow_dur", DataType::Float64, false), // seconds
        Field::new("protocol", DataType::Int32, true),
    ]))
}

/// One canonical flow record, already in canonical units (timestamp epoch
/// microseconds, flow_dur seconds). Every reader produces these; the batch
/// assembly below is the single place that knows the column order and Arrow
/// types, so a new reader never re-derives the canonical layout.
pub struct CanonicalFlow {
    pub timestamp: i64,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_port: i32,
    pub dest_port: i32,
    pub fwd_bytes: i64,
    pub bwd_bytes: i64,
    pub fwd_pkts: Option<i64>,
    pub bwd_pkts: Option<i64>,
    pub flow_dur: f64,
    pub protocol: Option<i32>,
}

/// Assemble canonical flow records into a `canonical_schema()` RecordBatch.
/// Shared by every reader (pcap, ocsf, …) so column order and types live in
/// exactly one place.
pub fn flows_to_batch(flows: &[CanonicalFlow]) -> std::result::Result<RecordBatch, ArrowError> {
    let columns: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from_iter_values(
            flows.iter().map(|f| f.timestamp),
        )),
        Arc::new(StringArray::from_iter_values(
            flows.iter().map(|f| f.src_ip.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            flows.iter().map(|f| f.dest_ip.as_str()),
        )),
        Arc::new(Int32Array::from_iter_values(
            flows.iter().map(|f| f.src_port),
        )),
        Arc::new(Int32Array::from_iter_values(
            flows.iter().map(|f| f.dest_port),
        )),
        Arc::new(Int64Array::from_iter_values(
            flows.iter().map(|f| f.fwd_bytes),
        )),
        Arc::new(Int64Array::from_iter_values(
            flows.iter().map(|f| f.bwd_bytes),
        )),
        Arc::new(Int64Array::from(
            flows.iter().map(|f| f.fwd_pkts).collect::<Vec<_>>(),
        )),
        Arc::new(Int64Array::from(
            flows.iter().map(|f| f.bwd_pkts).collect::<Vec<_>>(),
        )),
        Arc::new(Float64Array::from_iter_values(
            flows.iter().map(|f| f.flow_dur),
        )),
        Arc::new(Int32Array::from(
            flows.iter().map(|f| f.protocol).collect::<Vec<_>>(),
        )),
    ];
    RecordBatch::try_new(canonical_schema(), columns)
}

/// Parsed view of the canonical schema JSON.
pub struct SchemaSpec {
    /// canonical field name -> source-column aliases (normalized spelling)
    pub aliases: Vec<(String, Vec<String>)>,
    /// normalized duration column name -> divisor to seconds
    pub duration_divisors: HashMap<String, f64>,
    /// ground-truth columns carried through unchanged when present
    pub passthrough: Vec<String>,
}

pub fn load_schema_spec() -> SchemaSpec {
    let root: Value = serde_json::from_str(SCHEMA_JSON).expect("embedded schema JSON is valid");
    let fields = &root["canonical_fields"];

    let mut aliases = Vec::new();
    for section in ["required", "optional"] {
        if let Some(map) = fields[section].as_object() {
            for (canonical, spec) in map {
                let names: Vec<String> = spec["aliases"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .map(normalize_name)
                            .collect()
                    })
                    .unwrap_or_default();
                aliases.push((canonical.clone(), names));
            }
        }
    }

    let mut duration_divisors = HashMap::new();
    if let Some(units) = fields["required"]["flow_dur"]["unit_detection"].as_object() {
        for (unit, names) in units {
            let divisor = match unit.as_str() {
                "seconds" => 1.0,
                "milliseconds" => 1e3,
                "microseconds" => 1e6,
                "nanoseconds" => 1e9,
                _ => continue,
            };
            if let Some(arr) = names.as_array() {
                for name in arr.iter().filter_map(|v| v.as_str()) {
                    duration_divisors.insert(normalize_name(name), divisor);
                }
            }
        }
    }

    let mut passthrough: Vec<String> = fields["label_fields"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    passthrough.push("label".to_string());

    SchemaSpec {
        aliases,
        duration_divisors,
        passthrough,
    }
}

pub fn normalize_name(name: &str) -> String {
    let mut name = name.trim();
    // tstat exports prefix the first header column with "#" or "#N#"
    // (e.g. "#c_ip:1" in log_udp_complete, "#15#c_ip:1" in log_tcp_complete).
    if let Some(rest) = name.strip_prefix('#') {
        name = rest;
        if let Some((index, tail)) = name.split_once('#') {
            if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) {
                name = tail;
            }
        }
    }
    // tstat exports suffix every column with its 1-based index (e.g. "c_bytes_all:9").
    if let Some((head, index)) = name.rsplit_once(':') {
        if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) {
            name = head;
        }
    }
    name.trim().to_lowercase().replace([' ', '-'], "_")
}

/// Resolve a protocol name (or a numeric string) to its IANA protocol number.
///
/// NOTE: this lowercases and trims but deliberately does NOT use
/// `normalize_name`, so hyphens survive. Keys must be written as the exporter
/// spells them — `"ipv6-icmp"`, not `"ipv6_icmp"`, which would never match.
///
/// `None` means "no IANA IP protocol number", which covers two different cases:
/// an unrecognized string, and a value that is genuinely not an IP protocol.
/// Argus reports link-layer and application protocols in the same column —
/// `arp` and `rarp` are layer 2 (EtherType, not IP), while `rtp`, `rtcp` and
/// `udt` ride over UDP and have no protocol number of their own. Those are
/// deliberately left unmapped; do not invent numbers for them. They surface
/// downstream as a null protocol alongside a zero port, which is a detectable
/// signature for a data-quality check rather than something to paper over here.
pub fn protocol_number(name: &str) -> Option<i32> {
    match name.trim().to_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        // 58 has three spellings in the wild: IANA's official `ipv6-icmp`, and
        // the colloquial `icmpv6`/`icmp6`. Real Argus captures use the first.
        "ipv6-icmp" | "icmpv6" | "icmp6" => Some(58),
        "igmp" => Some(2),
        "ipv6" => Some(41),
        "pim" => Some(103),
        "gre" => Some(47),
        "esp" => Some(50),
        other => other.parse::<i32>().ok(),
    }
}

impl SchemaSpec {
    /// Return {canonical_name -> source column name} for resolvable fields.
    pub fn resolve_columns(&self, source_names: &[String]) -> HashMap<String, String> {
        let normalized: HashMap<String, &String> = source_names
            .iter()
            .map(|n| (normalize_name(n), n))
            .collect();
        let mut resolved = HashMap::new();
        for (canonical, aliases) in &self.aliases {
            for alias in aliases {
                if let Some(source) = normalized.get(alias) {
                    resolved.insert(canonical.clone(), (*source).clone());
                    break;
                }
            }
        }
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_ip_protocol_names_and_spellings() {
        assert_eq!(protocol_number("tcp"), Some(6));
        assert_eq!(protocol_number("UDP"), Some(17));
        assert_eq!(protocol_number("  TCP  "), Some(6), "values arrive padded");
        assert_eq!(protocol_number("igmp"), Some(2));
        assert_eq!(protocol_number("ipv6"), Some(41));
        assert_eq!(protocol_number("pim"), Some(103));
        // All three spellings of 58, including IANA's hyphenated official name.
        for spelling in ["ipv6-icmp", "icmpv6", "icmp6", "IPv6-ICMP"] {
            assert_eq!(protocol_number(spelling), Some(58), "{spelling}");
        }
        // Numeric passthrough for exporters that already emit the number.
        assert_eq!(protocol_number("6"), Some(6));
        assert_eq!(protocol_number("132"), Some(132));
    }

    /// Argus reports link-layer and application protocols in the same column.
    /// None of these has an IANA IP protocol number, so `None` is the correct
    /// answer — not a gap to be filled with an invented value.
    #[test]
    fn leaves_non_ip_protocols_unmapped() {
        for not_ip in ["arp", "rarp", "rtp", "rtcp", "udt", "ipx/spx"] {
            assert_eq!(
                protocol_number(not_ip),
                None,
                "{not_ip} is not an IP protocol and must not be given a number"
            );
        }
        assert_eq!(protocol_number(""), None);
        assert_eq!(protocol_number("nonsense"), None);
    }

    #[test]
    fn normalize_strips_tstat_decorations() {
        assert_eq!(normalize_name("#15#c_ip:1"), "c_ip");
        assert_eq!(normalize_name("#c_ip:1"), "c_ip");
        assert_eq!(normalize_name("c_bytes_all:9"), "c_bytes_all");
        assert_eq!(normalize_name("durat:31"), "durat");
        assert_eq!(normalize_name("c_tls_SNI:116"), "c_tls_sni");
    }

    #[test]
    fn normalize_keeps_plain_names() {
        assert_eq!(
            normalize_name(" Total Length of Fwd Packets"),
            "total_length_of_fwd_packets"
        );
        assert_eq!(normalize_name("id.orig_h"), "id.orig_h");
    }

    /// In tstat the client (`c_*`) is the connection initiator, i.e. the
    /// canonical source — corroborated by real AIT rows where `c_ip` equals
    /// `ipv4_address_cli`. The alias table used to read `s_` as "source",
    /// which flipped the topology and counted client bytes as forward while
    /// calling the server the source. Pin the coherent mapping.
    #[test]
    fn tstat_client_is_source_and_forward() {
        let spec = load_schema_spec();
        let header: Vec<String> = [
            "#15#c_ip:1",
            "c_port:2",
            "c_pkts_all:3",
            "c_bytes_all:9",
            "s_ip:15",
            "s_port:16",
            "s_pkts_all:17",
            "s_bytes_all:23",
            "durat:31",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let resolved = spec.resolve_columns(&header);
        assert_eq!(resolved["src_ip"], "#15#c_ip:1");
        assert_eq!(resolved["src_port"], "c_port:2");
        assert_eq!(resolved["fwd_bytes"], "c_bytes_all:9");
        assert_eq!(resolved["fwd_pkts"], "c_pkts_all:3");
        assert_eq!(resolved["dest_ip"], "s_ip:15");
        assert_eq!(resolved["dest_port"], "s_port:16");
        assert_eq!(resolved["bwd_bytes"], "s_bytes_all:23");
        assert_eq!(resolved["bwd_pkts"], "s_pkts_all:17");
        assert_eq!(resolved["flow_dur"], "durat:31");
    }

    /// tstat durations are milliseconds: in real log_tcp_complete rows,
    /// `durat` equals `last - first` which are epoch-millisecond stamps
    /// (e.g. durat=2188.354 for a flow whose first/last differ by 2188 ms).
    /// log_udp_complete has no `durat`; its per-side `c_durat` is also ms.
    #[test]
    fn tstat_durations_are_milliseconds() {
        let spec = load_schema_spec();
        assert_eq!(spec.duration_divisors.get("durat"), Some(&1e3));
        assert_eq!(spec.duration_divisors.get("c_durat"), Some(&1e3));
    }

    /// `protocol_number` lowercases and trims but does NOT apply
    /// `normalize_name`, so hyphens survive. A key written with an underscore
    /// would never match what an exporter emits.
    #[test]
    fn protocol_lookup_does_not_normalize_hyphens() {
        assert_eq!(normalize_name("ipv6-icmp"), "ipv6_icmp");
        assert_eq!(protocol_number("ipv6-icmp"), Some(58));
        assert_eq!(
            protocol_number("ipv6_icmp"),
            None,
            "the underscored form is not what exporters write; \
             new entries must use the hyphenated spelling"
        );
    }
}
