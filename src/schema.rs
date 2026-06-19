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
    name.trim().to_lowercase().replace([' ', '-'], "_")
}

pub fn protocol_number(name: &str) -> Option<i32> {
    match name.trim().to_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
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
