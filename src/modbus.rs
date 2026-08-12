//! Passive Modbus/TCP decoding from offline PCAP/PCAPNG captures.
//!
//! This module deliberately writes a protocol-observation schema rather than
//! adding application fields to canonical NetFlow. Direction is inferred only
//! from a configured server port (502 by default); the decoder never connects
//! to, polls, or otherwise interacts with an OT device.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanArray, BooleanBuilder, Int32Array, Int32Builder, Int64Array, ListBuilder,
    StringArray,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{Block, PcapBlockOwned, PcapError, create_reader};
use serde_json::Value;

use crate::writer::write_parquet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LINKTYPE_ETHERNET: u16 = 1;
const MAX_MODBUS_LENGTH: usize = 254; // unit identifier + PDU
const MAX_PENDING_STREAM_BYTES: usize = 1024 * 1024;
const SCHEMA_VERSION: &str = "modbus_observation/v1";
const DIRECTION_BASIS: &str = "configured_server_port";

const SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/modbus/v1/schema.json"
));

#[derive(Debug, Default, Clone)]
pub struct DecodeSummary {
    pub observations: usize,
    pub complete: usize,
    pub request_only: usize,
    pub response_only: usize,
    pub exceptions: usize,
    pub tcp_payload_packets: usize,
    pub request_adus: usize,
    pub response_adus: usize,
    pub malformed_bytes: usize,
    pub retransmitted_segments: usize,
    pub out_of_order_segments: usize,
    pub forced_stream_gaps: usize,
    pub incomplete_streams: usize,
}

impl std::fmt::Display for DecodeSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} observations ({} complete, {} request-only, {} response-only, {} exceptions); \
             {} request/{} response ADUs; {} malformed bytes skipped; {} retransmissions, \
             {} out-of-order segments, {} forced gaps, {} incomplete streams",
            self.observations,
            self.complete,
            self.request_only,
            self.response_only,
            self.exceptions,
            self.request_adus,
            self.response_adus,
            self.malformed_bytes,
            self.retransmitted_segments,
            self.out_of_order_segments,
            self.forced_stream_gaps,
            self.incomplete_streams,
        )
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct ConversationKey {
    client_ip: String,
    client_port: u16,
    server_ip: String,
    server_port: u16,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct StreamKey {
    conversation: ConversationKey,
    direction: Direction,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct TransactionKey {
    conversation: ConversationKey,
    transaction_id: u16,
    unit_id: u8,
}

struct TcpPayloadPacket {
    timestamp: i64,
    packet_number: i64,
    src_ip: String,
    dest_ip: String,
    src_port: u16,
    dest_port: u16,
    sequence_number: u32,
    syn: bool,
    fin: bool,
    rst: bool,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct RawAdu {
    transaction_id: u16,
    unit_id: u8,
    pdu: Vec<u8>,
    warning: Option<String>,
}

#[derive(Default)]
struct FeedReport {
    retransmitted_segments: usize,
    out_of_order_segments: usize,
    forced_stream_gaps: usize,
}

#[derive(Default)]
struct ExtractReport {
    adus: Vec<RawAdu>,
    malformed_bytes: usize,
}

#[derive(Default)]
struct TcpStreamState {
    next_sequence: Option<u64>,
    pending_segments: BTreeMap<u64, Vec<u8>>,
    decoded_bytes: Vec<u8>,
    pending_warning: Option<String>,
}

impl TcpStreamState {
    fn has_incomplete_data(&self) -> bool {
        !self.pending_segments.is_empty() || !self.decoded_bytes.is_empty()
    }

    fn feed(&mut self, sequence: u32, payload: &[u8]) -> FeedReport {
        let mut report = FeedReport::default();
        if payload.is_empty() {
            return report;
        }

        let expected = *self.next_sequence.get_or_insert(sequence as u64);
        let mut start = unwrap_sequence(sequence, expected);
        let mut data = payload;
        let end = start.saturating_add(data.len() as u64);

        if end <= expected {
            report.retransmitted_segments += 1;
            return report;
        }
        if start < expected {
            report.retransmitted_segments += 1;
            let overlap = (expected - start) as usize;
            data = &data[overlap..];
            start = expected;
        } else if start > expected {
            report.out_of_order_segments += 1;
        }

        self.pending_segments
            .entry(start)
            .and_modify(|existing| {
                if data.len() > existing.len() {
                    existing.clear();
                    existing.extend_from_slice(data);
                }
            })
            .or_insert_with(|| data.to_vec());
        self.drain_contiguous();

        let pending_bytes: usize = self.pending_segments.values().map(Vec::len).sum();
        if pending_bytes > MAX_PENDING_STREAM_BYTES {
            if let Some((&first_start, _)) = self.pending_segments.first_key_value() {
                // A missing TCP segment must not allow unbounded memory growth. If
                // the cap is reached, discard the incomplete ADU and resume at the
                // next observed segment while marking the next record explicitly.
                self.decoded_bytes.clear();
                self.next_sequence = Some(first_start);
                add_warning(&mut self.pending_warning, "tcp_gap_forced_resync");
                report.forced_stream_gaps += 1;
                self.drain_contiguous();
            }
        }
        report
    }

    fn drain_contiguous(&mut self) {
        while let Some(expected) = self.next_sequence {
            let Some((&start, _)) = self.pending_segments.range(..=expected).next_back() else {
                break;
            };
            let data = self.pending_segments.remove(&start).unwrap();
            let end = start + data.len() as u64;
            if end <= expected {
                continue;
            }
            let offset = (expected - start) as usize;
            self.decoded_bytes.extend_from_slice(&data[offset..]);
            self.next_sequence = Some(end);
        }
    }

    fn extract_adus(&mut self) -> ExtractReport {
        let mut report = ExtractReport::default();
        loop {
            if self.decoded_bytes.len() < 7 {
                break;
            }

            if !plausible_mbap_header(&self.decoded_bytes, 0) {
                if let Some(offset) = find_next_mbap_header(&self.decoded_bytes) {
                    self.decoded_bytes.drain(..offset);
                    report.malformed_bytes += offset;
                    add_warning(&mut self.pending_warning, "mbap_resynchronized");
                    continue;
                }

                // Preserve the final six bytes because they may be the start
                // of a header split across TCP segments.
                let discard = self.decoded_bytes.len().saturating_sub(6);
                if discard > 0 {
                    self.decoded_bytes.drain(..discard);
                    report.malformed_bytes += discard;
                    add_warning(&mut self.pending_warning, "mbap_resynchronized");
                }
                break;
            }

            let length =
                u16::from_be_bytes([self.decoded_bytes[4], self.decoded_bytes[5]]) as usize;
            let frame_length = 6 + length;
            if self.decoded_bytes.len() < frame_length {
                break;
            }

            let frame: Vec<u8> = self.decoded_bytes.drain(..frame_length).collect();
            report.adus.push(RawAdu {
                transaction_id: u16::from_be_bytes([frame[0], frame[1]]),
                unit_id: frame[6],
                pdu: frame[7..].to_vec(),
                warning: self.pending_warning.take(),
            });
        }
        report
    }
}

fn unwrap_sequence(sequence: u32, reference: u64) -> u64 {
    const SPACE: u64 = 1_u64 << 32;
    const HALF: u64 = 1_u64 << 31;
    let base = reference & !(SPACE - 1);
    let mut candidate = base | sequence as u64;
    if candidate.saturating_add(HALF) < reference {
        candidate = candidate.saturating_add(SPACE);
    } else if candidate > reference.saturating_add(HALF) && candidate >= SPACE {
        candidate -= SPACE;
    }
    candidate
}

fn plausible_mbap_header(bytes: &[u8], offset: usize) -> bool {
    if bytes.len() < offset + 7 {
        return false;
    }
    let protocol_id = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
    let length = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]) as usize;
    if protocol_id != 0 || !(2..=MAX_MODBUS_LENGTH).contains(&length) {
        return false;
    }
    // When the function byte is already present, zero cannot be a valid
    // Modbus function and is useful protection against false resynchronization.
    bytes.get(offset + 7).is_none_or(|function| *function != 0)
}

fn find_next_mbap_header(bytes: &[u8]) -> Option<usize> {
    (1..bytes.len().saturating_sub(6)).find(|offset| plausible_mbap_header(bytes, *offset))
}

#[derive(Clone, Debug, Default)]
struct Identity {
    vendor_name: Option<String>,
    product_code: Option<String>,
    revision: Option<String>,
    vendor_url: Option<String>,
    product_name: Option<String>,
    model_name: Option<String>,
    user_application_name: Option<String>,
}

#[derive(Debug)]
struct DecodedRequest {
    function_code: u8,
    function_name: &'static str,
    operation: &'static str,
    address: Option<u16>,
    quantity: Option<u16>,
    write_address: Option<u16>,
    write_quantity: Option<u16>,
    coil_values: Option<Vec<bool>>,
    register_values: Option<Vec<u16>>,
    diagnostic_subfunction: Option<u16>,
    device_id_code: Option<u8>,
    device_id_object: Option<u8>,
    warning: Option<String>,
}

fn decode_request(pdu: &[u8]) -> DecodedRequest {
    let raw_function = pdu.first().copied().unwrap_or_default();
    let function_code = raw_function & 0x7f;
    let mut decoded = DecodedRequest {
        function_code,
        function_name: function_name(function_code, pdu),
        operation: operation_name(function_code, pdu),
        address: None,
        quantity: None,
        write_address: None,
        write_quantity: None,
        coil_values: None,
        register_values: None,
        diagnostic_subfunction: None,
        device_id_code: None,
        device_id_object: None,
        warning: None,
    };

    if raw_function & 0x80 != 0 {
        add_warning(
            &mut decoded.warning,
            "exception_function_in_request_direction",
        );
    }

    match function_code {
        1..=4 => {
            decoded.address = read_u16(pdu, 1);
            decoded.quantity = read_u16(pdu, 3);
            require_pdu_len(pdu, 5, &mut decoded.warning);
        }
        5 => {
            decoded.address = read_u16(pdu, 1);
            decoded.quantity = Some(1);
            require_pdu_len(pdu, 5, &mut decoded.warning);
            decoded.coil_values = decode_single_coil_value(pdu, &mut decoded.warning);
        }
        6 => {
            decoded.address = read_u16(pdu, 1);
            decoded.quantity = Some(1);
            require_pdu_len(pdu, 5, &mut decoded.warning);
            decoded.register_values = read_u16(pdu, 3).map(|value| vec![value]);
        }
        8 => {
            decoded.diagnostic_subfunction = read_u16(pdu, 1);
            require_pdu_len(pdu, 3, &mut decoded.warning);
        }
        15 => {
            decoded.address = read_u16(pdu, 1);
            decoded.quantity = read_u16(pdu, 3);
            decoded.coil_values =
                decode_coil_values(pdu, decoded.quantity, 5, 6, &mut decoded.warning);
        }
        16 => {
            decoded.address = read_u16(pdu, 1);
            decoded.quantity = read_u16(pdu, 3);
            decoded.register_values =
                decode_register_values(pdu, decoded.quantity, 5, 6, &mut decoded.warning);
        }
        22 => {
            decoded.address = read_u16(pdu, 1);
            decoded.quantity = Some(1);
            require_pdu_len(pdu, 7, &mut decoded.warning);
        }
        23 => {
            decoded.address = read_u16(pdu, 1);
            decoded.quantity = read_u16(pdu, 3);
            decoded.write_address = read_u16(pdu, 5);
            decoded.write_quantity = read_u16(pdu, 7);
            decoded.register_values =
                decode_register_values(pdu, decoded.write_quantity, 9, 10, &mut decoded.warning);
        }
        24 => {
            decoded.address = read_u16(pdu, 1);
            require_pdu_len(pdu, 3, &mut decoded.warning);
        }
        43 if pdu.get(1) == Some(&0x0e) => {
            decoded.device_id_code = pdu.get(2).copied();
            decoded.device_id_object = pdu.get(3).copied();
            require_pdu_len(pdu, 4, &mut decoded.warning);
        }
        _ => {}
    }
    decoded
}

fn require_pdu_len(pdu: &[u8], required: usize, warning: &mut Option<String>) {
    if pdu.len() < required {
        add_warning(warning, "truncated_function_payload");
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

fn decode_single_coil_value(pdu: &[u8], warning: &mut Option<String>) -> Option<Vec<bool>> {
    match read_u16(pdu, 3)? {
        0x0000 => Some(vec![false]),
        0xff00 => Some(vec![true]),
        _ => {
            add_warning(warning, "invalid_single_coil_value");
            None
        }
    }
}

fn decode_coil_values(
    pdu: &[u8],
    quantity: Option<u16>,
    byte_count_offset: usize,
    values_offset: usize,
    warning: &mut Option<String>,
) -> Option<Vec<bool>> {
    require_pdu_len(pdu, values_offset, warning);
    let quantity = quantity? as usize;
    let byte_count = *pdu.get(byte_count_offset)? as usize;
    let expected_byte_count = quantity.div_ceil(8);
    if byte_count != expected_byte_count {
        add_warning(warning, "coil_write_byte_count_mismatch");
        return None;
    }

    let required = values_offset + byte_count;
    require_pdu_len(pdu, required, warning);
    let packed = pdu.get(values_offset..required)?;
    Some(
        (0..quantity)
            .map(|index| packed[index / 8] & (1_u8 << (index % 8)) != 0)
            .collect(),
    )
}

fn decode_register_values(
    pdu: &[u8],
    quantity: Option<u16>,
    byte_count_offset: usize,
    values_offset: usize,
    warning: &mut Option<String>,
) -> Option<Vec<u16>> {
    require_pdu_len(pdu, values_offset, warning);
    let quantity = quantity? as usize;
    let byte_count = *pdu.get(byte_count_offset)? as usize;
    let expected_byte_count = quantity * 2;
    if byte_count != expected_byte_count {
        add_warning(warning, "register_write_byte_count_mismatch");
        return None;
    }

    let required = values_offset + byte_count;
    require_pdu_len(pdu, required, warning);
    let encoded = pdu.get(values_offset..required)?;
    Some(
        encoded
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect(),
    )
}

fn validate_response_pdu(pdu: &[u8]) -> Option<String> {
    let mut warning = None;
    let raw_function = pdu.first().copied().unwrap_or_default();
    if raw_function & 0x80 != 0 {
        require_pdu_len(pdu, 2, &mut warning);
        return warning;
    }
    let function = raw_function & 0x7f;
    match function {
        1..=4 | 23 => {
            require_pdu_len(pdu, 2, &mut warning);
            if let Some(byte_count) = pdu.get(1) {
                require_pdu_len(pdu, 2 + *byte_count as usize, &mut warning);
            }
        }
        5 | 6 | 15 | 16 => require_pdu_len(pdu, 5, &mut warning),
        7 => require_pdu_len(pdu, 2, &mut warning),
        8 => require_pdu_len(pdu, 3, &mut warning),
        22 => require_pdu_len(pdu, 7, &mut warning),
        _ => {}
    }
    warning
}

fn function_name(function: u8, pdu: &[u8]) -> &'static str {
    match function {
        1 => "read_coils",
        2 => "read_discrete_inputs",
        3 => "read_holding_registers",
        4 => "read_input_registers",
        5 => "write_single_coil",
        6 => "write_single_register",
        7 => "read_exception_status",
        8 => "diagnostics",
        11 => "get_communication_event_counter",
        12 => "get_communication_event_log",
        15 => "write_multiple_coils",
        16 => "write_multiple_registers",
        17 => "report_server_id",
        20 => "read_file_record",
        21 => "write_file_record",
        22 => "mask_write_register",
        23 => "read_write_multiple_registers",
        24 => "read_fifo_queue",
        43 if pdu.get(1) == Some(&0x0e) => "read_device_identification",
        43 => "encapsulated_interface_transport",
        _ => "unknown",
    }
}

fn operation_name(function: u8, pdu: &[u8]) -> &'static str {
    match function {
        1..=4 | 7 | 11 | 12 | 17 | 20 | 24 => "read",
        5 | 6 | 15 | 16 | 21 | 22 => "write",
        23 => "read_write",
        8 => "diagnostic",
        43 if pdu.get(1) == Some(&0x0e) => "device_identification",
        43 => "encapsulated",
        _ => "other",
    }
}

fn parse_identity_response(pdu: &[u8]) -> (Identity, Option<String>) {
    let mut identity = Identity::default();
    let mut warning = None;
    if pdu.len() < 7 || pdu.first() != Some(&43) || pdu.get(1) != Some(&0x0e) {
        add_warning(&mut warning, "truncated_device_identification_response");
        return (identity, warning);
    }

    let object_count = pdu[6] as usize;
    let mut offset = 7;
    for _ in 0..object_count {
        if pdu.len() < offset + 2 {
            add_warning(&mut warning, "truncated_device_identification_object");
            break;
        }
        let object_id = pdu[offset];
        let object_length = pdu[offset + 1] as usize;
        offset += 2;
        let Some(raw_value) = pdu.get(offset..offset + object_length) else {
            add_warning(&mut warning, "truncated_device_identification_object");
            break;
        };
        offset += object_length;
        let value = sanitize_identity_value(raw_value);
        if value.is_empty() {
            continue;
        }
        match object_id {
            0x00 => identity.vendor_name = Some(value),
            0x01 => identity.product_code = Some(value),
            0x02 => identity.revision = Some(value),
            0x03 => identity.vendor_url = Some(value),
            0x04 => identity.product_name = Some(value),
            0x05 => identity.model_name = Some(value),
            0x06 => identity.user_application_name = Some(value),
            _ => {}
        }
    }
    (identity, warning)
}

fn sanitize_identity_value(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn exception_name(code: u8) -> &'static str {
    match code {
        1 => "illegal_function",
        2 => "illegal_data_address",
        3 => "illegal_data_value",
        4 => "server_device_failure",
        5 => "acknowledge",
        6 => "server_device_busy",
        8 => "memory_parity_error",
        10 => "gateway_path_unavailable",
        11 => "gateway_target_failed_to_respond",
        _ => "unknown",
    }
}

#[derive(Clone, Debug)]
struct Observation {
    timestamp: i64,
    conversation: ConversationKey,
    transaction_id: u16,
    unit_id: u8,
    function_code: u8,
    function_name: String,
    operation: String,
    address: Option<u16>,
    quantity: Option<u16>,
    write_address: Option<u16>,
    write_quantity: Option<u16>,
    coil_values: Option<Vec<bool>>,
    register_values: Option<Vec<u16>>,
    diagnostic_subfunction: Option<u16>,
    device_id_code: Option<u8>,
    device_id_object: Option<u8>,
    request_seen: bool,
    response_seen: bool,
    request_timestamp: Option<i64>,
    response_timestamp: Option<i64>,
    latency_usec: Option<i64>,
    response_status: String,
    exception_code: Option<u8>,
    exception_name: Option<String>,
    identity: Identity,
    request_packet: Option<i64>,
    response_packet: Option<i64>,
    parser_warning: Option<String>,
}

impl Observation {
    fn from_request(
        conversation: ConversationKey,
        adu: &RawAdu,
        decoded: DecodedRequest,
        timestamp: i64,
        packet_number: i64,
    ) -> Self {
        let mut parser_warning = adu.warning.clone();
        if let Some(warning) = decoded.warning {
            add_warning(&mut parser_warning, &warning);
        }
        Self {
            timestamp,
            conversation,
            transaction_id: adu.transaction_id,
            unit_id: adu.unit_id,
            function_code: decoded.function_code,
            function_name: decoded.function_name.to_string(),
            operation: decoded.operation.to_string(),
            address: decoded.address,
            quantity: decoded.quantity,
            write_address: decoded.write_address,
            write_quantity: decoded.write_quantity,
            coil_values: decoded.coil_values,
            register_values: decoded.register_values,
            diagnostic_subfunction: decoded.diagnostic_subfunction,
            device_id_code: decoded.device_id_code,
            device_id_object: decoded.device_id_object,
            request_seen: true,
            response_seen: false,
            request_timestamp: Some(timestamp),
            response_timestamp: None,
            latency_usec: None,
            response_status: "missing_response".to_string(),
            exception_code: None,
            exception_name: None,
            identity: Identity::default(),
            request_packet: Some(packet_number),
            response_packet: None,
            parser_warning,
        }
    }

    fn from_orphan_response(
        conversation: ConversationKey,
        adu: &RawAdu,
        timestamp: i64,
        packet_number: i64,
    ) -> Self {
        let raw_function = adu.pdu[0];
        let function_code = raw_function & 0x7f;
        let (identity, identity_warning) = if function_code == 43 && raw_function & 0x80 == 0 {
            parse_identity_response(&adu.pdu)
        } else {
            (Identity::default(), None)
        };
        let mut parser_warning = adu.warning.clone();
        if let Some(warning) = validate_response_pdu(&adu.pdu) {
            add_warning(&mut parser_warning, &warning);
        }
        if let Some(warning) = identity_warning {
            add_warning(&mut parser_warning, &warning);
        }
        let exception_code = (raw_function & 0x80 != 0)
            .then(|| adu.pdu.get(1).copied())
            .flatten();
        if raw_function & 0x80 != 0 && exception_code.is_none() {
            add_warning(&mut parser_warning, "truncated_exception_response");
        }
        Self {
            timestamp,
            conversation,
            transaction_id: adu.transaction_id,
            unit_id: adu.unit_id,
            function_code,
            function_name: function_name(function_code, &adu.pdu).to_string(),
            operation: operation_name(function_code, &adu.pdu).to_string(),
            address: None,
            quantity: None,
            write_address: None,
            write_quantity: None,
            coil_values: None,
            register_values: None,
            diagnostic_subfunction: None,
            device_id_code: None,
            device_id_object: None,
            request_seen: false,
            response_seen: true,
            request_timestamp: None,
            response_timestamp: Some(timestamp),
            latency_usec: None,
            response_status: "orphan_response".to_string(),
            exception_code,
            exception_name: exception_code.map(exception_name).map(str::to_string),
            identity,
            request_packet: None,
            response_packet: Some(packet_number),
            parser_warning,
        }
    }
}

struct Decoder {
    server_port: u16,
    streams: HashMap<StreamKey, TcpStreamState>,
    pending: HashMap<TransactionKey, Observation>,
    observations: Vec<Observation>,
    summary: DecodeSummary,
}

impl Decoder {
    fn new(server_port: u16) -> Self {
        Self {
            server_port,
            streams: HashMap::new(),
            pending: HashMap::new(),
            observations: Vec::new(),
            summary: DecodeSummary::default(),
        }
    }

    fn ingest(&mut self, packet: TcpPayloadPacket) {
        let direction = match (
            packet.src_port == self.server_port,
            packet.dest_port == self.server_port,
        ) {
            (false, true) => Direction::Request,
            (true, false) => Direction::Response,
            _ => return,
        };
        let conversation = match direction {
            Direction::Request => ConversationKey {
                client_ip: packet.src_ip.clone(),
                client_port: packet.src_port,
                server_ip: packet.dest_ip.clone(),
                server_port: packet.dest_port,
            },
            Direction::Response => ConversationKey {
                client_ip: packet.dest_ip.clone(),
                client_port: packet.dest_port,
                server_ip: packet.src_ip.clone(),
                server_port: packet.src_port,
            },
        };
        let stream_key = StreamKey {
            conversation: conversation.clone(),
            direction,
        };

        if packet.syn {
            if self
                .streams
                .get(&stream_key)
                .is_some_and(TcpStreamState::has_incomplete_data)
            {
                self.summary.incomplete_streams += 1;
            }
            self.streams.remove(&stream_key);
        }

        let payload_sequence = packet.sequence_number.wrapping_add(u32::from(packet.syn));
        let extract = if packet.payload.is_empty() {
            ExtractReport::default()
        } else {
            self.summary.tcp_payload_packets += 1;
            let stream = self.streams.entry(stream_key.clone()).or_default();
            let feed = stream.feed(payload_sequence, &packet.payload);
            self.summary.retransmitted_segments += feed.retransmitted_segments;
            self.summary.out_of_order_segments += feed.out_of_order_segments;
            self.summary.forced_stream_gaps += feed.forced_stream_gaps;
            stream.extract_adus()
        };
        self.summary.malformed_bytes += extract.malformed_bytes;

        for adu in extract.adus {
            match direction {
                Direction::Request => {
                    self.summary.request_adus += 1;
                    self.handle_request(
                        conversation.clone(),
                        adu,
                        packet.timestamp,
                        packet.packet_number,
                    );
                }
                Direction::Response => {
                    self.summary.response_adus += 1;
                    self.handle_response(
                        conversation.clone(),
                        adu,
                        packet.timestamp,
                        packet.packet_number,
                    );
                }
            }
        }

        if packet.fin || packet.rst {
            let incomplete = self
                .streams
                .remove(&stream_key)
                .is_some_and(|stream| stream.has_incomplete_data());
            self.summary.incomplete_streams += usize::from(incomplete);
        }
    }

    fn handle_request(
        &mut self,
        conversation: ConversationKey,
        adu: RawAdu,
        timestamp: i64,
        packet_number: i64,
    ) {
        let decoded = decode_request(&adu.pdu);
        let key = TransactionKey {
            conversation: conversation.clone(),
            transaction_id: adu.transaction_id,
            unit_id: adu.unit_id,
        };
        let observation =
            Observation::from_request(conversation, &adu, decoded, timestamp, packet_number);
        if let Some(mut replaced) = self.pending.insert(key, observation) {
            add_warning(
                &mut replaced.parser_warning,
                "transaction_id_reused_before_response",
            );
            self.observations.push(replaced);
        }
    }

    fn handle_response(
        &mut self,
        conversation: ConversationKey,
        adu: RawAdu,
        timestamp: i64,
        packet_number: i64,
    ) {
        let key = TransactionKey {
            conversation: conversation.clone(),
            transaction_id: adu.transaction_id,
            unit_id: adu.unit_id,
        };
        let Some(mut observation) = self.pending.remove(&key) else {
            self.observations.push(Observation::from_orphan_response(
                conversation,
                &adu,
                timestamp,
                packet_number,
            ));
            return;
        };

        let raw_function = adu.pdu[0];
        let response_function = raw_function & 0x7f;
        observation.response_seen = true;
        observation.response_timestamp = Some(timestamp);
        observation.response_packet = Some(packet_number);
        observation.latency_usec = observation
            .request_timestamp
            .and_then(|request| timestamp.checked_sub(request))
            .filter(|latency| *latency >= 0);
        if observation
            .request_timestamp
            .is_some_and(|request| timestamp < request)
        {
            add_warning(
                &mut observation.parser_warning,
                "response_timestamp_precedes_request",
            );
        }
        if let Some(warning) = adu.warning.as_deref() {
            add_warning(&mut observation.parser_warning, warning);
        }
        if let Some(warning) = validate_response_pdu(&adu.pdu) {
            add_warning(&mut observation.parser_warning, &warning);
        }

        if response_function != observation.function_code {
            observation.response_status = "function_mismatch".to_string();
            add_warning(
                &mut observation.parser_warning,
                "response_function_does_not_match_request",
            );
        } else if raw_function & 0x80 != 0 {
            observation.response_status = "exception".to_string();
            observation.exception_code = adu.pdu.get(1).copied();
            observation.exception_name = observation
                .exception_code
                .map(exception_name)
                .map(str::to_string);
            if observation.exception_code.is_none() {
                add_warning(
                    &mut observation.parser_warning,
                    "truncated_exception_response",
                );
            }
        } else {
            observation.response_status = "ok".to_string();
        }

        if response_function == 43 && raw_function & 0x80 == 0 {
            let (identity, warning) = parse_identity_response(&adu.pdu);
            observation.identity = identity;
            if let Some(warning) = warning {
                add_warning(&mut observation.parser_warning, &warning);
            }
        }
        self.observations.push(observation);
    }

    fn finish(mut self) -> (Vec<Observation>, DecodeSummary) {
        self.summary.incomplete_streams += self
            .streams
            .values()
            .filter(|stream| stream.has_incomplete_data())
            .count();
        self.observations.extend(self.pending.into_values());
        self.observations.sort_by_key(|observation| {
            (
                observation.timestamp,
                observation.conversation.clone(),
                observation.transaction_id,
                observation.unit_id,
            )
        });

        self.summary.observations = self.observations.len();
        self.summary.complete = self
            .observations
            .iter()
            .filter(|observation| observation.request_seen && observation.response_seen)
            .count();
        self.summary.request_only = self
            .observations
            .iter()
            .filter(|observation| observation.request_seen && !observation.response_seen)
            .count();
        self.summary.response_only = self
            .observations
            .iter()
            .filter(|observation| !observation.request_seen && observation.response_seen)
            .count();
        self.summary.exceptions = self
            .observations
            .iter()
            .filter(|observation| observation.response_status == "exception")
            .count();
        (self.observations, self.summary)
    }
}

pub fn modbus_to_parquet(input: &str, output: &str, server_port: u16) -> Result<DecodeSummary> {
    if server_port == 0 {
        return Err("Modbus server port must be between 1 and 65535".into());
    }

    let file = File::open(input)?;
    let mut reader = create_reader(1 << 20, file)?;
    let mut decoder = Decoder::new(server_port);
    let mut linktype = LINKTYPE_ETHERNET;
    let mut legacy_nanos = false;
    let mut packet_number = 0_i64;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        linktype = header.network.0 as u16;
                        legacy_nanos = header.magic_number == 0xa1b2_3c4d;
                    }
                    PcapBlockOwned::Legacy(packet) => {
                        packet_number += 1;
                        let fractional_usec = if legacy_nanos {
                            (packet.ts_usec / 1000) as i64
                        } else {
                            packet.ts_usec as i64
                        };
                        let timestamp = packet.ts_sec as i64 * 1_000_000 + fractional_usec;
                        if let Some(packet) =
                            parse_tcp_payload(packet.data, linktype, timestamp, packet_number)
                        {
                            decoder.ingest(packet);
                        }
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(description)) => {
                        linktype = description.linktype.0 as u16;
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                        packet_number += 1;
                        // pcapng's default if_tsresol is microseconds, matching
                        // the existing flow reader. Interface-specific options
                        // are intentionally left for a later capture-layer pass.
                        let timestamp = ((packet.ts_high as i64) << 32) | packet.ts_low as i64;
                        if let Some(packet) =
                            parse_tcp_payload(packet.data, linktype, timestamp, packet_number)
                        {
                            decoder.ingest(packet);
                        }
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    return Err("pcap refill failed (truncated capture?)".into());
                }
            }
            Err(error) => return Err(format!("pcap parse error: {error:?}").into()),
        }
    }

    let (observations, summary) = decoder.finish();
    if observations.is_empty() {
        return Err(format!(
            "no decodable Modbus/TCP observations found on server port {server_port} \
             ({} payload packets, {} malformed bytes, {} incomplete streams)",
            summary.tcp_payload_packets, summary.malformed_bytes, summary.incomplete_streams,
        )
        .into());
    }
    let batch = observations_to_batch(&observations)?;
    write_parquet(&batch, output)?;
    Ok(summary)
}

fn parse_tcp_payload(
    data: &[u8],
    linktype: u16,
    timestamp: i64,
    packet_number: i64,
) -> Option<TcpPayloadPacket> {
    let sliced = if linktype == LINKTYPE_ETHERNET {
        SlicedPacket::from_ethernet(data).ok()?
    } else {
        SlicedPacket::from_ip(data).ok()?
    };
    let (src_ip, dest_ip) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ipv4) => (
            Ipv4Addr::from(ipv4.header().source()).to_string(),
            Ipv4Addr::from(ipv4.header().destination()).to_string(),
        ),
        NetSlice::Ipv6(ipv6) => (
            Ipv6Addr::from(ipv6.header().source()).to_string(),
            Ipv6Addr::from(ipv6.header().destination()).to_string(),
        ),
        _ => return None,
    };
    let Some(TransportSlice::Tcp(tcp)) = sliced.transport else {
        return None;
    };
    Some(TcpPayloadPacket {
        timestamp,
        packet_number,
        src_ip,
        dest_ip,
        src_port: tcp.source_port(),
        dest_port: tcp.destination_port(),
        sequence_number: tcp.sequence_number(),
        syn: tcp.syn(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        payload: tcp.payload().to_vec(),
    })
}

fn modbus_schema() -> Arc<Schema> {
    let spec: Value = serde_json::from_str(SCHEMA_JSON).expect("embedded Modbus schema is valid");
    let declared_version = spec["schema_version"]
        .as_str()
        .expect("Modbus schema declares schema_version");
    assert_eq!(declared_version, SCHEMA_VERSION);
    let metadata = HashMap::from([
        ("deeptempo.schema".to_string(), SCHEMA_VERSION.to_string()),
        ("deeptempo.decoder".to_string(), "passive".to_string()),
        (
            "deeptempo.direction_basis".to_string(),
            DIRECTION_BASIS.to_string(),
        ),
    ]);
    Arc::new(Schema::new_with_metadata(
        vec![
            Field::new("schema_version", DataType::Utf8, false),
            Field::new("timestamp", DataType::Int64, false),
            Field::new("client_ip", DataType::Utf8, false),
            Field::new("client_port", DataType::Int32, false),
            Field::new("server_ip", DataType::Utf8, false),
            Field::new("server_port", DataType::Int32, false),
            Field::new("transaction_id", DataType::Int32, false),
            Field::new("unit_id", DataType::Int32, false),
            Field::new("function_code", DataType::Int32, false),
            Field::new("function_name", DataType::Utf8, false),
            Field::new("operation", DataType::Utf8, false),
            Field::new("address", DataType::Int32, true),
            Field::new("quantity", DataType::Int32, true),
            Field::new("write_address", DataType::Int32, true),
            Field::new("write_quantity", DataType::Int32, true),
            Field::new(
                "coil_values",
                DataType::List(Arc::new(Field::new("item", DataType::Boolean, false))),
                true,
            ),
            Field::new(
                "register_values",
                DataType::List(Arc::new(Field::new("item", DataType::Int32, false))),
                true,
            ),
            Field::new("diagnostic_subfunction", DataType::Int32, true),
            Field::new("device_id_code", DataType::Int32, true),
            Field::new("device_id_object", DataType::Int32, true),
            Field::new("request_seen", DataType::Boolean, false),
            Field::new("response_seen", DataType::Boolean, false),
            Field::new("request_timestamp", DataType::Int64, true),
            Field::new("response_timestamp", DataType::Int64, true),
            Field::new("latency_usec", DataType::Int64, true),
            Field::new("response_status", DataType::Utf8, false),
            Field::new("exception_code", DataType::Int32, true),
            Field::new("exception_name", DataType::Utf8, true),
            Field::new("vendor_name", DataType::Utf8, true),
            Field::new("product_code", DataType::Utf8, true),
            Field::new("revision", DataType::Utf8, true),
            Field::new("vendor_url", DataType::Utf8, true),
            Field::new("product_name", DataType::Utf8, true),
            Field::new("model_name", DataType::Utf8, true),
            Field::new("user_application_name", DataType::Utf8, true),
            Field::new("request_packet", DataType::Int64, true),
            Field::new("response_packet", DataType::Int64, true),
            Field::new("direction_basis", DataType::Utf8, false),
            Field::new("parser_warning", DataType::Utf8, true),
        ],
        metadata,
    ))
}

fn observations_to_batch(
    observations: &[Observation],
) -> std::result::Result<RecordBatch, ArrowError> {
    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from_iter_values(
            observations.iter().map(|_| SCHEMA_VERSION),
        )),
        Arc::new(Int64Array::from_iter_values(
            observations.iter().map(|observation| observation.timestamp),
        )),
        Arc::new(StringArray::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.conversation.client_ip.as_str()),
        )),
        Arc::new(Int32Array::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.conversation.client_port as i32),
        )),
        Arc::new(StringArray::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.conversation.server_ip.as_str()),
        )),
        Arc::new(Int32Array::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.conversation.server_port as i32),
        )),
        Arc::new(Int32Array::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.transaction_id as i32),
        )),
        Arc::new(Int32Array::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.unit_id as i32),
        )),
        Arc::new(Int32Array::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.function_code as i32),
        )),
        Arc::new(StringArray::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.function_name.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.operation.as_str()),
        )),
        optional_u16_array(observations.iter().map(|observation| observation.address)),
        optional_u16_array(observations.iter().map(|observation| observation.quantity)),
        optional_u16_array(
            observations
                .iter()
                .map(|observation| observation.write_address),
        ),
        optional_u16_array(
            observations
                .iter()
                .map(|observation| observation.write_quantity),
        ),
        optional_bool_list_array(
            observations
                .iter()
                .map(|observation| observation.coil_values.as_deref()),
        ),
        optional_u16_list_array(
            observations
                .iter()
                .map(|observation| observation.register_values.as_deref()),
        ),
        optional_u16_array(
            observations
                .iter()
                .map(|observation| observation.diagnostic_subfunction),
        ),
        optional_u8_array(
            observations
                .iter()
                .map(|observation| observation.device_id_code),
        ),
        optional_u8_array(
            observations
                .iter()
                .map(|observation| observation.device_id_object),
        ),
        Arc::new(BooleanArray::from(
            observations
                .iter()
                .map(|observation| observation.request_seen)
                .collect::<Vec<_>>(),
        )),
        Arc::new(BooleanArray::from(
            observations
                .iter()
                .map(|observation| observation.response_seen)
                .collect::<Vec<_>>(),
        )),
        Arc::new(Int64Array::from(
            observations
                .iter()
                .map(|observation| observation.request_timestamp)
                .collect::<Vec<_>>(),
        )),
        Arc::new(Int64Array::from(
            observations
                .iter()
                .map(|observation| observation.response_timestamp)
                .collect::<Vec<_>>(),
        )),
        Arc::new(Int64Array::from(
            observations
                .iter()
                .map(|observation| observation.latency_usec)
                .collect::<Vec<_>>(),
        )),
        Arc::new(StringArray::from_iter_values(
            observations
                .iter()
                .map(|observation| observation.response_status.as_str()),
        )),
        optional_u8_array(
            observations
                .iter()
                .map(|observation| observation.exception_code),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.exception_name.as_deref()),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.identity.vendor_name.as_deref()),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.identity.product_code.as_deref()),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.identity.revision.as_deref()),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.identity.vendor_url.as_deref()),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.identity.product_name.as_deref()),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.identity.model_name.as_deref()),
        ),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.identity.user_application_name.as_deref()),
        ),
        Arc::new(Int64Array::from(
            observations
                .iter()
                .map(|observation| observation.request_packet)
                .collect::<Vec<_>>(),
        )),
        Arc::new(Int64Array::from(
            observations
                .iter()
                .map(|observation| observation.response_packet)
                .collect::<Vec<_>>(),
        )),
        Arc::new(StringArray::from_iter_values(
            observations.iter().map(|_| DIRECTION_BASIS),
        )),
        optional_string_array(
            observations
                .iter()
                .map(|observation| observation.parser_warning.as_deref()),
        ),
    ];
    RecordBatch::try_new(modbus_schema(), columns)
}

fn optional_u16_array(values: impl Iterator<Item = Option<u16>>) -> ArrayRef {
    Arc::new(Int32Array::from(
        values.map(|value| value.map(i32::from)).collect::<Vec<_>>(),
    ))
}

fn optional_u8_array(values: impl Iterator<Item = Option<u8>>) -> ArrayRef {
    Arc::new(Int32Array::from(
        values.map(|value| value.map(i32::from)).collect::<Vec<_>>(),
    ))
}

fn optional_bool_list_array<'a>(values: impl Iterator<Item = Option<&'a [bool]>>) -> ArrayRef {
    let mut builder = ListBuilder::new(BooleanBuilder::new()).with_field(Field::new(
        "item",
        DataType::Boolean,
        false,
    ));
    for values in values {
        match values {
            Some(values) => {
                for value in values {
                    builder.values().append_value(*value);
                }
                builder.append(true);
            }
            None => builder.append(false),
        }
    }
    Arc::new(builder.finish())
}

fn optional_u16_list_array<'a>(values: impl Iterator<Item = Option<&'a [u16]>>) -> ArrayRef {
    let mut builder = ListBuilder::new(Int32Builder::new()).with_field(Field::new(
        "item",
        DataType::Int32,
        false,
    ));
    for values in values {
        match values {
            Some(values) => {
                for value in values {
                    builder.values().append_value(i32::from(*value));
                }
                builder.append(true);
            }
            None => builder.append(false),
        }
    }
    Arc::new(builder.finish())
}

fn optional_string_array<'a>(values: impl Iterator<Item = Option<&'a str>>) -> ArrayRef {
    Arc::new(StringArray::from_iter(values))
}

fn add_warning(target: &mut Option<String>, warning: &str) {
    if warning.is_empty() {
        return;
    }
    match target {
        Some(existing) if !existing.split(';').any(|part| part == warning) => {
            existing.push(';');
            existing.push_str(warning);
        }
        None => *target = Some(warning.to_string()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adu(transaction_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
        let length = (1 + pdu.len()) as u16;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&transaction_id.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(unit_id);
        bytes.extend_from_slice(pdu);
        bytes
    }

    #[test]
    fn reassembles_fragmented_and_coalesced_adus() {
        let first = adu(1, 7, &[3, 0, 10, 0, 2]);
        let second = adu(2, 7, &[6, 0, 20, 0, 1]);
        let mut stream = TcpStreamState::default();

        stream.feed(1000, &first[..8]);
        assert!(stream.extract_adus().adus.is_empty());
        stream.feed(1008, &[first[8..].to_vec(), second.clone()].concat());
        let extracted = stream.extract_adus();
        assert_eq!(extracted.adus.len(), 2);
        assert_eq!(extracted.adus[0].transaction_id, 1);
        assert_eq!(extracted.adus[1].transaction_id, 2);
    }

    #[test]
    fn handles_out_of_order_tail_and_retransmission() {
        let frame = adu(9, 1, &[3, 0, 1, 0, 4]);
        let mut stream = TcpStreamState::default();
        stream.feed(50, &frame[..6]);
        let out_of_order = stream.feed(59, &frame[9..]);
        assert_eq!(out_of_order.out_of_order_segments, 1);
        assert!(stream.extract_adus().adus.is_empty());
        stream.feed(56, &frame[6..9]);
        let extracted = stream.extract_adus();
        assert_eq!(extracted.adus.len(), 1);
        let retransmission = stream.feed(50, &frame);
        assert_eq!(retransmission.retransmitted_segments, 1);
        assert!(stream.extract_adus().adus.is_empty());
    }

    #[test]
    fn resynchronizes_after_malformed_prefix() {
        let frame = adu(5, 1, &[16, 0, 100, 0, 2, 4, 0, 1, 0, 2]);
        let mut stream = TcpStreamState::default();
        stream.feed(0, &[vec![0xff, 0xaa], frame].concat());
        let extracted = stream.extract_adus();
        assert_eq!(extracted.malformed_bytes, 2);
        assert_eq!(extracted.adus.len(), 1);
        assert_eq!(
            extracted.adus[0].warning.as_deref(),
            Some("mbap_resynchronized")
        );
    }

    #[test]
    fn decodes_read_write_and_device_identification_requests() {
        let read = decode_request(&[3, 0x12, 0x34, 0, 8]);
        assert_eq!(read.function_name, "read_holding_registers");
        assert_eq!(read.address, Some(0x1234));
        assert_eq!(read.quantity, Some(8));

        let read_write = decode_request(&[23, 0, 10, 0, 2, 0, 20, 0, 3, 6, 0, 1, 0, 2, 0, 3]);
        assert_eq!(read_write.operation, "read_write");
        assert_eq!(read_write.address, Some(10));
        assert_eq!(read_write.write_address, Some(20));
        assert_eq!(read_write.write_quantity, Some(3));
        assert_eq!(read_write.register_values, Some(vec![1, 2, 3]));

        let identity = decode_request(&[43, 14, 1, 0]);
        assert_eq!(identity.operation, "device_identification");
        assert_eq!(identity.device_id_code, Some(1));
        assert_eq!(identity.device_id_object, Some(0));
    }

    #[test]
    fn decodes_write_values_without_treating_mask_writes_as_final_values() {
        let single_coil_on = decode_request(&[5, 0, 7, 0xff, 0]);
        assert_eq!(single_coil_on.coil_values, Some(vec![true]));

        let single_coil_off = decode_request(&[5, 0, 7, 0, 0]);
        assert_eq!(single_coil_off.coil_values, Some(vec![false]));

        let invalid_single_coil = decode_request(&[5, 0, 7, 0x12, 0x34]);
        assert_eq!(invalid_single_coil.coil_values, None);
        assert_eq!(
            invalid_single_coil.warning.as_deref(),
            Some("invalid_single_coil_value")
        );

        let multiple_coils = decode_request(&[15, 0, 20, 0, 10, 2, 0x55, 0x03]);
        assert_eq!(
            multiple_coils.coil_values,
            Some(vec![
                true, false, true, false, true, false, true, false, true, true,
            ])
        );

        let single_register = decode_request(&[6, 0x04, 0x01, 0, 10]);
        assert_eq!(single_register.address, Some(1025));
        assert_eq!(single_register.register_values, Some(vec![10]));

        let multiple_registers = decode_request(&[16, 0, 30, 0, 2, 4, 0, 10, 0, 20]);
        assert_eq!(multiple_registers.register_values, Some(vec![10, 20]));

        let mask_write = decode_request(&[22, 0, 40, 0xff, 0, 0, 0xff]);
        assert_eq!(mask_write.register_values, None);
    }

    #[test]
    fn rejects_incomplete_or_inconsistent_write_value_lists() {
        let truncated = decode_request(&[16, 0, 10, 0, 2, 4, 0, 1]);
        assert_eq!(truncated.register_values, None);
        assert_eq!(
            truncated.warning.as_deref(),
            Some("truncated_function_payload")
        );

        let register_mismatch = decode_request(&[16, 0, 10, 0, 2, 2, 0, 1]);
        assert_eq!(register_mismatch.register_values, None);
        assert_eq!(
            register_mismatch.warning.as_deref(),
            Some("register_write_byte_count_mismatch")
        );

        let coil_mismatch = decode_request(&[15, 0, 10, 0, 9, 1, 0xff]);
        assert_eq!(coil_mismatch.coil_values, None);
        assert_eq!(
            coil_mismatch.warning.as_deref(),
            Some("coil_write_byte_count_mismatch")
        );
    }

    #[test]
    fn extracts_vendor_identity_objects() {
        let mut pdu = vec![43, 14, 1, 1, 0, 0, 3];
        pdu.extend_from_slice(&[0, 7]);
        pdu.extend_from_slice(b"Siemens");
        pdu.extend_from_slice(&[1, 7]);
        pdu.extend_from_slice(b"S7-1500");
        pdu.extend_from_slice(&[4, 11]);
        pdu.extend_from_slice(b"SIMATIC PLC");
        let (identity, warning) = parse_identity_response(&pdu);
        assert!(warning.is_none());
        assert_eq!(identity.vendor_name.as_deref(), Some("Siemens"));
        assert_eq!(identity.product_code.as_deref(), Some("S7-1500"));
        assert_eq!(identity.product_name.as_deref(), Some("SIMATIC PLC"));
    }

    #[test]
    fn batch_schema_has_version_metadata_and_requested_write_values() {
        let conversation = ConversationKey {
            client_ip: "10.0.0.1".to_string(),
            client_port: 40000,
            server_ip: "10.0.0.2".to_string(),
            server_port: 502,
        };
        let raw = RawAdu {
            transaction_id: 1,
            unit_id: 1,
            pdu: vec![6, 0x04, 0x01, 0, 10],
            warning: None,
        };
        let observation =
            Observation::from_request(conversation, &raw, decode_request(&raw.pdu), 1, 2);
        let batch = observations_to_batch(&[observation]).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(
            batch
                .schema()
                .metadata()
                .get("deeptempo.schema")
                .map(String::as_str),
            Some(SCHEMA_VERSION)
        );
        assert_eq!(
            batch
                .schema()
                .field_with_name("register_values")
                .unwrap()
                .data_type(),
            &DataType::List(Arc::new(Field::new("item", DataType::Int32, false)))
        );
        assert!(batch.schema().field_with_name("raw_pdu").is_err());
    }

    #[test]
    fn executable_schema_matches_declared_json_contract() {
        let spec: Value = serde_json::from_str(SCHEMA_JSON).unwrap();
        let declared = spec["fields"].as_array().unwrap();
        let arrow = modbus_schema();
        assert_eq!(declared.len(), arrow.fields().len());
        for (json_field, arrow_field) in declared.iter().zip(arrow.fields()) {
            assert_eq!(
                json_field["name"].as_str(),
                Some(arrow_field.name().as_str())
            );
            assert_eq!(
                json_field["nullable"].as_bool(),
                Some(arrow_field.is_nullable())
            );
            let expected_type = match json_field["type"].as_str().unwrap() {
                "utf8" => DataType::Utf8,
                "int32" => DataType::Int32,
                "int64" => DataType::Int64,
                "boolean" => DataType::Boolean,
                "list<boolean>" => {
                    DataType::List(Arc::new(Field::new("item", DataType::Boolean, false)))
                }
                "list<int32>" => {
                    DataType::List(Arc::new(Field::new("item", DataType::Int32, false)))
                }
                other => panic!("unexpected declared type: {other}"),
            };
            assert_eq!(arrow_field.data_type(), &expected_type);
        }
    }

    #[test]
    fn configured_nonstandard_port_sets_roles_without_guessing() {
        let payload = adu(1, 4, &[3, 0, 0, 0, 1]);
        let mut decoder = Decoder::new(1502);
        decoder.ingest(TcpPayloadPacket {
            timestamp: 10,
            packet_number: 1,
            src_ip: "10.0.0.1".to_string(),
            dest_ip: "10.0.0.2".to_string(),
            src_port: 40000,
            dest_port: 1502,
            sequence_number: 100,
            syn: false,
            fin: false,
            rst: false,
            payload,
        });
        let (observations, summary) = decoder.finish();
        assert_eq!(summary.request_only, 1);
        assert_eq!(observations[0].conversation.client_port, 40000);
        assert_eq!(observations[0].conversation.server_port, 1502);
        assert_eq!(observations[0].unit_id, 4);
    }

    #[test]
    fn truncated_byte_count_is_visible_but_still_decoded() {
        let request = decode_request(&[16, 0, 10, 0, 2, 4, 0, 1]);
        assert_eq!(request.address, Some(10));
        assert_eq!(
            request.warning.as_deref(),
            Some("truncated_function_payload")
        );
        assert_eq!(
            validate_response_pdu(&[3, 4, 0, 1]).as_deref(),
            Some("truncated_function_payload")
        );
    }
}
