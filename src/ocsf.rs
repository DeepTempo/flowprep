//! OCSF Network Activity (class_uid 4001) event reader.
//!
//! OCSF is a standard, not a vendor dialect, so events are deserialized into a
//! typed view of the Network Activity shape rather than navigated as loose
//! JSON: endpoints, byte/packet counts, and the millisecond `time`/`duration`
//! fields all have known positions and types. Only flow-close events
//! (`activity_id` 2 / `activity_name` "Closed") of class 4001 are converted,
//! since those carry the final byte totals. Input may be NDJSON (one event per
//! line), a JSON array, or a single object.
//!
//! Records that fail to parse, or close events missing required fields, are
//! surfaced as errors rather than silently dropped — partial or empty output
//! must never look like success. A small set of non-standard exporter fields
//! (Juniper's top-level byte counters and `elapsed_time`) are accepted as
//! explicit, documented fallbacks; everything else is strict OCSF.

use serde::Deserialize;

use crate::schema::{CanonicalFlow, flows_to_batch, protocol_number};
use crate::writer::write_parquet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const NETWORK_ACTIVITY_CLASS_UID: i64 = 4001;
const ACTIVITY_ID_CLOSE: i64 = 2;
/// Below this magnitude an OCSF `time` is treated as epoch milliseconds and
/// scaled to microseconds; at or above it the value is assumed to already be
/// microseconds. ~Nov 2286 in ms, so real ms timestamps never reach it.
const MICROSECOND_THRESHOLD: i64 = 1_000_000_000_000_000;

/// Typed view of the subset of OCSF Network Activity we consume. Unknown
/// fields are ignored (OCSF events carry far more than this); every field is
/// optional so classification can run before required-field validation.
#[derive(Deserialize)]
struct OcsfEvent {
    class_uid: Option<i64>,
    activity_id: Option<i64>,
    activity_name: Option<String>,
    /// Event/flow-start time, epoch milliseconds (OCSF convention).
    time: Option<i64>,
    /// Flow duration in milliseconds. `elapsed_time` is a Juniper exporter alias.
    #[serde(alias = "elapsed_time")]
    duration: Option<f64>,
    src_endpoint: Option<Endpoint>,
    dst_endpoint: Option<Endpoint>,
    traffic: Option<Traffic>,
    connection_info: Option<ConnectionInfo>,
    // Non-standard exporter (Juniper) fallbacks for byte counters.
    bytes_from_client: Option<i64>,
    bytes_from_server: Option<i64>,
}

#[derive(Deserialize)]
struct Endpoint {
    ip: Option<String>,
    port: Option<i32>,
}

#[derive(Deserialize)]
struct Traffic {
    bytes_in: Option<i64>,
    bytes_out: Option<i64>,
    packets_in: Option<i64>,
    packets_out: Option<i64>,
}

#[derive(Deserialize)]
struct ConnectionInfo {
    protocol_num: Option<i32>,
    protocol_name: Option<String>,
}

/// Tally of what happened to each input record, reported to stderr so a
/// conversion that drops most of its input is visible, not silent.
#[derive(Default)]
struct Summary {
    total: usize,
    skipped_non_activity: usize,
    skipped_non_close: usize,
    converted: usize,
}

pub fn ocsf_to_parquet(input: &str, output: &str) -> Result<usize> {
    let text = std::fs::read_to_string(input)?;
    let events = parse_events(&text)?;

    let mut summary = Summary {
        total: events.len(),
        ..Default::default()
    };
    let mut flows = Vec::new();
    for (i, event) in events.iter().enumerate() {
        if !event.is_network_activity() {
            summary.skipped_non_activity += 1;
            continue;
        }
        if !event.is_flow_close() {
            summary.skipped_non_close += 1;
            continue;
        }
        // A close event we set out to convert that lacks required data is data
        // loss, not a routine skip — fail loudly with the offending record.
        let flow = event.to_canonical().map_err(|reason| {
            format!("OCSF close event {} is missing required data: {reason}", i + 1)
        })?;
        flows.push(flow);
    }
    summary.converted = flows.len();

    if flows.is_empty() {
        return Err(format!(
            "no OCSF Network Activity close events in {input} \
             ({} records read: {} non-activity, {} non-close)",
            summary.total, summary.skipped_non_activity, summary.skipped_non_close
        )
        .into());
    }

    eprintln!(
        "ocsf: {} records -> {} flows ({} skipped: {} non-activity, {} non-close)",
        summary.total,
        summary.converted,
        summary.skipped_non_activity + summary.skipped_non_close,
        summary.skipped_non_activity,
        summary.skipped_non_close
    );

    let batch = flows_to_batch(&flows)?;
    write_parquet(&batch, output)?;
    Ok(batch.num_rows())
}

/// Deserialize events from a JSON array, a single object, or NDJSON (one event
/// per line). Parse failures are returned as errors with a line number, never
/// skipped.
fn parse_events(text: &str) -> Result<Vec<OcsfEvent>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("input is empty".into());
    }
    if trimmed.starts_with('[') {
        let events = serde_json::from_str(trimmed)
            .map_err(|e| format!("input is a JSON array but failed to parse: {e}"))?;
        return Ok(events);
    }
    // A single, possibly multi-line, JSON object. NDJSON of objects fails this
    // (serde rejects trailing content after the first value) and falls through.
    if let Ok(event) = serde_json::from_str::<OcsfEvent>(trimmed) {
        return Ok(vec![event]);
    }
    let mut events = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let event = serde_json::from_str(line)
            .map_err(|e| format!("malformed JSON on line {}: {e}", i + 1))?;
        events.push(event);
    }
    if events.is_empty() {
        return Err("input contained no JSON records".into());
    }
    Ok(events)
}

impl OcsfEvent {
    /// `class_uid` is authoritative when present; minimal exporters omit it, in
    /// which case the event is treated as a candidate and filtered on activity.
    fn is_network_activity(&self) -> bool {
        self.class_uid
            .is_none_or(|uid| uid == NETWORK_ACTIVITY_CLASS_UID)
    }

    fn is_flow_close(&self) -> bool {
        if self.activity_id == Some(ACTIVITY_ID_CLOSE) {
            return true;
        }
        matches!(
            self.activity_name
                .as_deref()
                .map(|n| n.trim().to_ascii_lowercase())
                .as_deref(),
            Some("close") | Some("closed")
        )
    }

    fn to_canonical(&self) -> std::result::Result<CanonicalFlow, String> {
        let src = self.src_endpoint.as_ref();
        let dst = self.dst_endpoint.as_ref();
        let src_ip = src
            .and_then(|e| e.ip.clone())
            .ok_or("missing src_endpoint.ip")?;
        let dest_ip = dst
            .and_then(|e| e.ip.clone())
            .ok_or("missing dst_endpoint.ip")?;
        let time_ms = self.time.ok_or("missing time")?;
        let timestamp = if time_ms < MICROSECOND_THRESHOLD {
            time_ms * 1000
        } else {
            time_ms
        };

        let traffic = self.traffic.as_ref();
        // traffic.* is canonical OCSF; the top-level counters are the Juniper
        // fallback.
        let fwd_bytes = traffic
            .and_then(|t| t.bytes_in)
            .or(self.bytes_from_client)
            .unwrap_or(0);
        let bwd_bytes = traffic
            .and_then(|t| t.bytes_out)
            .or(self.bytes_from_server)
            .unwrap_or(0);

        let protocol = self.connection_info.as_ref().and_then(|c| {
            c.protocol_num
                .or_else(|| c.protocol_name.as_deref().and_then(protocol_number))
        });

        Ok(CanonicalFlow {
            timestamp,
            src_ip,
            dest_ip,
            // Ports are absent for some flows (e.g. ICMP); 0 stands in, matching
            // the pcap reader.
            src_port: src.and_then(|e| e.port).unwrap_or(0),
            dest_port: dst.and_then(|e| e.port).unwrap_or(0),
            fwd_bytes,
            bwd_bytes,
            fwd_pkts: traffic.and_then(|t| t.packets_in),
            bwd_pkts: traffic.and_then(|t| t.packets_out),
            // OCSF duration is milliseconds; canonical flow_dur is seconds.
            flow_dur: self.duration.unwrap_or(0.0) / 1000.0,
            protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(json: &str) -> OcsfEvent {
        serde_json::from_str(json).expect("valid OcsfEvent")
    }

    #[test]
    fn classifies_close_network_activity() {
        assert!(event(r#"{"class_uid":4001,"activity_name":"Closed"}"#).is_flow_close());
        assert!(event(r#"{"activity_id":2}"#).is_flow_close());
        assert!(!event(r#"{"class_uid":4001,"activity_name":"Opened"}"#).is_flow_close());
        // No activity metadata at all is not a flow-close.
        assert!(!event(r#"{"src_endpoint":{"ip":"1.1.1.1"}}"#).is_flow_close());
    }

    #[test]
    fn enforces_class_boundary() {
        // Authentication (3002) is not Network Activity.
        assert!(!event(r#"{"class_uid":3002,"activity_id":2}"#).is_network_activity());
        // Absent class_uid is treated as a candidate.
        assert!(event(r#"{"activity_id":2}"#).is_network_activity());
        assert!(event(r#"{"class_uid":4001}"#).is_network_activity());
    }

    #[test]
    fn converts_units_and_nested_fields() {
        let f = event(
            r#"{"class_uid":4001,"activity_id":2,"time":1750000000000,"duration":2500,
                "src_endpoint":{"ip":"10.0.0.1","port":44321},
                "dst_endpoint":{"ip":"10.0.0.2","port":443},
                "traffic":{"bytes_in":1200,"bytes_out":34000,"packets_in":8,"packets_out":12},
                "connection_info":{"protocol_name":"tcp"}}"#,
        )
        .to_canonical()
        .unwrap();
        assert_eq!(f.timestamp, 1_750_000_000_000_000); // ms -> us
        assert_eq!(f.flow_dur, 2.5); // ms -> s
        assert_eq!((f.fwd_bytes, f.bwd_bytes), (1200, 34000));
        assert_eq!((f.fwd_pkts, f.bwd_pkts), (Some(8), Some(12)));
        assert_eq!(f.protocol, Some(6)); // tcp -> 6
    }

    #[test]
    fn applies_vendor_fallbacks() {
        let f = event(
            r#"{"activity_id":2,"time":1750000010000,"elapsed_time":150,
                "src_endpoint":{"ip":"10.0.0.3"},"dst_endpoint":{"ip":"8.8.8.8"},
                "bytes_from_client":90,"bytes_from_server":0,
                "connection_info":{"protocol_num":17}}"#,
        )
        .to_canonical()
        .unwrap();
        assert_eq!(f.flow_dur, 0.15); // elapsed_time ms -> s
        assert_eq!(f.fwd_bytes, 90); // top-level byte fallback
        assert_eq!((f.src_port, f.dest_port), (0, 0)); // absent ports -> 0
        assert_eq!((f.fwd_pkts, f.protocol), (None, Some(17)));
    }

    #[test]
    fn missing_required_fields_error() {
        // Missing time.
        assert!(
            event(r#"{"activity_id":2,"src_endpoint":{"ip":"1.1.1.1"},"dst_endpoint":{"ip":"2.2.2.2"}}"#)
                .to_canonical()
                .is_err()
        );
        // Missing source ip.
        assert!(
            event(r#"{"activity_id":2,"time":1,"dst_endpoint":{"ip":"2.2.2.2"}}"#)
                .to_canonical()
                .is_err()
        );
    }

    #[test]
    fn parses_ndjson_array_and_single_object() {
        assert_eq!(parse_events("{\"a\":1}\n{\"b\":2}\n").unwrap().len(), 2);
        assert_eq!(parse_events("[{\"a\":1},{\"b\":2}]").unwrap().len(), 2);
        assert_eq!(parse_events("{\n  \"activity_id\": 2\n}").unwrap().len(), 1);
    }

    #[test]
    fn empty_and_malformed_input_error() {
        assert!(parse_events("   ").is_err());
        assert!(parse_events("{\"a\":1}\nnot json\n").is_err());
    }

    #[test]
    fn rejects_non_numeric_typed_fields() {
        // A port sent as a string is rejected, not silently coerced.
        assert!(serde_json::from_str::<OcsfEvent>(r#"{"src_endpoint":{"port":"443"}}"#).is_err());
    }
}
