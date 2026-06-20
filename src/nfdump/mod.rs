//! Purpose-built reader for nfdump/nfcapd binary flow files.
//!
//! nfcapd files are nfdump's native on-disk format: a typed binary container of
//! already-aggregated flow records (NetFlow v5/v9, IPFIX, sFlow collected by
//! `nfcapd`), not packets. This reader walks the container — file header,
//! data blocks, per-block decompression, and the two flow-record layouts in the
//! wild (the V1 "common" record from nfdump 1.6.x and the V2 "v3" extension
//! record from 1.7.x) — and yields only the fields flowprep canonicalizes.
//! Non-flow records (extension maps, exporters, samplers, stat/ident blocks)
//! and unrecognized V3 extensions are skipped by their declared size.
//!
//! It is deliberately not a general nfdump library: the byte layouts are
//! derived from nfdump's format (phaag/nfdump) and the `nfdump` crate
//! (markzz/rust-nfdump, ISC), but only the flow-bearing fields are decoded, so
//! the surface stays small and auditable.
//!
//! Robustness contract (this is binary ingestion, so it matters):
//!   * `next_flow()` returns `Ok(None)` only on a clean, complete read.
//!   * Any truncation, malformed size, or unsupported feature is an `Err` —
//!     a corrupt file can never masquerade as an empty or partial success.
//!   * Every length is validated before it is used to allocate or slice, so a
//!     bogus size field cannot trigger a giant allocation, underflow, or panic.
//!
//! Limitation: the pre-1.6 "common v0" record type (0x0001) is not decoded; a
//! file containing only those yields zero flows, which the caller reports as an
//! error rather than a silent empty file.

mod decompress;
pub mod error;

use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use byteorder::{LittleEndian, ReadBytesExt};

use self::decompress::{
    COMPRESSION_BZ2, COMPRESSION_LZ4, COMPRESSION_LZO, COMPRESSION_PLAIN, decompress,
};
pub use self::error::NfdumpError;

type Result<T> = std::result::Result<T, NfdumpError>;

const MAGIC: u16 = 0xa50c;
const VERSION_V1: u16 = 0x0001;
const VERSION_V2: u16 = 0x0002;

// Bytes remaining after the 4-byte magic+version preamble.
const V1_HEADER_REMAINING: usize = 140 - 4;
const V2_HEADER_REMAINING: usize = 40 - 4;
const V1_STAT_RECORD: i64 = 136;
const BLOCK_HEADER_LEN: usize = 12;

/// Refuse a single compressed block larger than this before allocating for it.
const MAX_BLOCK_COMPRESSED: usize = 256 * 1024 * 1024;

// Record types (the 16-bit `rtype` of each in-block record).
const TYPE_COMMON_RECORD: u16 = 0x000a; // V1 flow record
const TYPE_RECORD_V3: u16 = 0x000b; // V2/V3 flow record

// V3 extension ids flowprep consumes; all others are skipped by size.
const EXT_GENERIC_FLOW: u16 = 0x1;
const EXT_IPV4_FLOW: u16 = 0x2;
const EXT_IPV6_FLOW: u16 = 0x3;
const EXT_CNT_FLOW: u16 = 0x5;

// V1 record flag bits.
const V1_FLAG_IPV6: u16 = 0x01;
const V1_FLAG_64BIT_COUNTERS: u16 = 0x02;

/// One flow reduced to the fields flowprep canonicalizes. Times are epoch
/// milliseconds (nfdump's convention); unit conversion to the canonical schema
/// happens in the `nfcapd` canonicalization layer, not here.
#[derive(Debug, Clone)]
pub struct NfdumpFlow {
    pub first_ms: u64,
    pub last_ms: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub fwd_bytes: u64,
    pub fwd_pkts: u64,
    /// Reverse-direction counters, present only for biflow exporters (V3
    /// `cnt_flow`). `None` means a single-counter record (bwd zero-fills).
    pub bwd_bytes: Option<u64>,
    pub bwd_pkts: Option<u64>,
}

/// Streaming reader over an nfdump/nfcapd file. One decompressed block is held
/// in memory at a time; flows are produced one at a time via `next_flow`.
pub struct NfdumpFlowReader<R> {
    reader: R,
    version: u16,
    codec: u8,
    /// V2 uncompressed-size hint (`block_size`); `None` for V1.
    block_size_hint: Option<usize>,
    /// Data blocks still to read (from the file header's block count).
    remaining_blocks: u32,
    /// V2 appendix offset (ident/stat live there, not flows); `u64::MAX` for V1.
    off_appendix: u64,
    /// Current decompressed block and read cursor within it.
    block: Vec<u8>,
    block_pos: usize,
    records_left: u32,
}

impl<R: Read + Seek> NfdumpFlowReader<R> {
    /// Parse the file header and position at the first data block.
    pub fn new(mut reader: R) -> Result<Self> {
        let magic = reader.read_u16::<LittleEndian>()?;
        if magic != MAGIC {
            return Err(NfdumpError::InvalidMagic(magic));
        }
        let version = reader.read_u16::<LittleEndian>()?;
        match version {
            VERSION_V1 => Self::open_v1(reader),
            VERSION_V2 => Self::open_v2(reader),
            v => Err(NfdumpError::UnsupportedVersion(v)),
        }
    }

    fn open_v1(mut reader: R) -> Result<Self> {
        let mut buf = [0u8; V1_HEADER_REMAINING];
        reader.read_exact(&mut buf)?;
        let flags = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let num_blocks = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        // ident[128] (buf[8..136]) is not needed for flows.
        // The stat record sits between the header and the first data block.
        reader.seek(SeekFrom::Current(V1_STAT_RECORD))?;
        // V1 records the codec in low bits of the header flags.
        let codec = match flags & 0x19 {
            0x01 => COMPRESSION_LZO,
            0x08 => COMPRESSION_BZ2,
            0x10 => COMPRESSION_LZ4,
            _ => COMPRESSION_PLAIN,
        };
        Ok(Self::with(
            reader,
            VERSION_V1,
            codec,
            None,
            num_blocks,
            u64::MAX,
        ))
    }

    fn open_v2(mut reader: R) -> Result<Self> {
        let mut buf = [0u8; V2_HEADER_REMAINING];
        reader.read_exact(&mut buf)?;
        // Layout after magic+version: nf_version u32, created u64, compression
        // u8, encryption u8, appendix_blocks u16, unused u32, off_appendix u64,
        // block_size u32, num_blocks u32.
        let compression = buf[12];
        let off_appendix = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let block_size = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        let num_blocks = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        // Data blocks begin immediately after the 40-byte header (current
        // position); the appendix at off_appendix is skipped entirely.
        Ok(Self::with(
            reader,
            VERSION_V2,
            compression,
            Some(block_size as usize),
            num_blocks,
            off_appendix,
        ))
    }

    fn with(
        reader: R,
        version: u16,
        codec: u8,
        block_size_hint: Option<usize>,
        remaining_blocks: u32,
        off_appendix: u64,
    ) -> Self {
        Self {
            reader,
            version,
            codec,
            block_size_hint,
            remaining_blocks,
            off_appendix,
            block: Vec::new(),
            block_pos: 0,
            records_left: 0,
        }
    }

    /// Yield the next flow record, or `Ok(None)` at a clean end of file.
    pub fn next_flow(&mut self) -> Result<Option<NfdumpFlow>> {
        loop {
            while self.records_left == 0 {
                if !self.load_next_block()? {
                    return Ok(None);
                }
            }
            let (rtype, body) = self.read_block_record()?;
            self.records_left -= 1;
            match rtype {
                TYPE_COMMON_RECORD => return Ok(Some(parse_v1_record(&body)?)),
                TYPE_RECORD_V3 => return Ok(Some(parse_v3_record(&body)?)),
                // Non-flow record (extension map, exporter, sampler, ...): skip.
                _ => continue,
            }
        }
    }

    /// Load and decompress the next data block. Returns `Ok(false)` when the
    /// data-block region is cleanly exhausted.
    fn load_next_block(&mut self) -> Result<bool> {
        if self.remaining_blocks == 0 {
            return Ok(false);
        }
        if self.version == VERSION_V2 {
            let pos = self.reader.stream_position()?;
            if pos >= self.off_appendix {
                return Ok(false);
            }
        }

        let mut hdr = [0u8; BLOCK_HEADER_LEN];
        self.reader.read_exact(&mut hdr)?;
        let num_records = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        // hdr[8..10] = id, hdr[10..12] = flags — unused for flow extraction.

        if size > MAX_BLOCK_COMPRESSED {
            return Err(NfdumpError::Corrupt(format!(
                "data block claims {size} compressed bytes (> {MAX_BLOCK_COMPRESSED} cap)"
            )));
        }
        let mut compressed = vec![0u8; size];
        self.reader.read_exact(&mut compressed)?;

        self.block = decompress(self.codec, compressed, self.block_size_hint)?;
        self.block_pos = 0;
        self.records_left = num_records;
        self.remaining_blocks -= 1;
        Ok(true)
    }

    /// Read one record (4-byte header + body) from the current block. The block
    /// header's record count drives iteration; every length is validated
    /// against the bytes actually present so a bad size cannot slice or
    /// allocate out of bounds.
    fn read_block_record(&mut self) -> Result<(u16, Vec<u8>)> {
        let avail = self.block.len().saturating_sub(self.block_pos);
        if avail < 4 {
            return Err(NfdumpError::Corrupt(format!(
                "record header needs 4 bytes but {avail} remain in block"
            )));
        }
        let base = self.block_pos;
        let rtype = u16::from_le_bytes([self.block[base], self.block[base + 1]]);
        let size = u16::from_le_bytes([self.block[base + 2], self.block[base + 3]]) as usize;
        if size < 4 {
            return Err(NfdumpError::Corrupt(format!(
                "record size {size} is smaller than its 4-byte header"
            )));
        }
        if size > avail {
            return Err(NfdumpError::Corrupt(format!(
                "record of {size} bytes overruns {avail} bytes left in block"
            )));
        }
        let body = self.block[base + 4..base + size].to_vec();
        self.block_pos += size;
        Ok((rtype, body))
    }
}

/// Parse a V1 "common" record body. Fields up to the byte counter are at fixed
/// offsets determined by the flag bits; any trailing extension fields
/// (interfaces, AS numbers) are intentionally ignored.
fn parse_v1_record(body: &[u8]) -> Result<NfdumpFlow> {
    let mut c = std::io::Cursor::new(body);
    let flags = c.read_u16::<LittleEndian>()?;
    let _ext_map = c.read_u16::<LittleEndian>()?;
    let msec_first = c.read_u16::<LittleEndian>()? as u64;
    let msec_last = c.read_u16::<LittleEndian>()? as u64;
    let first = c.read_u32::<LittleEndian>()? as u64;
    let last = c.read_u32::<LittleEndian>()? as u64;
    let _fwd_status = c.read_u8()?;
    let _tcp_flags = c.read_u8()?;
    let protocol = c.read_u8()?;
    let _tos = c.read_u8()?;
    let src_port = c.read_u16::<LittleEndian>()?;
    let dst_port = c.read_u16::<LittleEndian>()?;
    let _exporter_sysid = c.read_u16::<LittleEndian>()?;
    let _bi_flow_dir = c.read_u8()?;
    let _flow_end_reason = c.read_u8()?;
    let (src_ip, dst_ip) = if flags & V1_FLAG_IPV6 == 0 {
        (read_ipv4(&mut c)?, read_ipv4(&mut c)?)
    } else {
        (read_ipv6(&mut c)?, read_ipv6(&mut c)?)
    };
    let (fwd_pkts, fwd_bytes) = if flags & V1_FLAG_64BIT_COUNTERS == 0 {
        (
            c.read_u32::<LittleEndian>()? as u64,
            c.read_u32::<LittleEndian>()? as u64,
        )
    } else {
        (c.read_u64::<LittleEndian>()?, c.read_u64::<LittleEndian>()?)
    };
    Ok(NfdumpFlow {
        first_ms: first * 1000 + msec_first,
        last_ms: last * 1000 + msec_last,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        fwd_bytes,
        fwd_pkts,
        // V1 records are single-counter.
        bwd_bytes: None,
        bwd_pkts: None,
    })
}

/// Parse a V3 record body: a small header followed by `num_elements`
/// self-describing extensions. Only generic-flow, IPv4/IPv6, and the reverse
/// counter are decoded; every other extension is stepped over by its size.
fn parse_v3_record(body: &[u8]) -> Result<NfdumpFlow> {
    let mut c = std::io::Cursor::new(body);
    let num_elements = c.read_u16::<LittleEndian>()?;
    let _engine_type = c.read_u8()?;
    let _engine_id = c.read_u8()?;
    let _exporter_id = c.read_u16::<LittleEndian>()?;
    let _flags = c.read_u8()?;
    let _nf_version = c.read_u8()?;

    let mut generic: Option<GenericFlow> = None;
    let mut ipv4: Option<(IpAddr, IpAddr)> = None;
    let mut ipv6: Option<(IpAddr, IpAddr)> = None;
    let mut cnt: Option<(u64, u64)> = None; // (out_pkts, out_bytes)

    for _ in 0..num_elements {
        let ext = c.read_u16::<LittleEndian>()?;
        let size = c.read_u16::<LittleEndian>()? as usize;
        if size < 4 {
            return Err(NfdumpError::Corrupt(format!(
                "v3 extension {ext} size {size} is smaller than its 4-byte header"
            )));
        }
        let inner_len = size - 4;
        let start = c.position() as usize;
        let end = start
            .checked_add(inner_len)
            .filter(|e| *e <= body.len())
            .ok_or_else(|| {
                NfdumpError::Corrupt(format!(
                    "v3 extension {ext} of {inner_len} bytes overruns record"
                ))
            })?;
        let inner = &body[start..end];

        match ext {
            EXT_GENERIC_FLOW => generic = Some(parse_generic_flow(inner)?),
            EXT_IPV4_FLOW => {
                let mut e = std::io::Cursor::new(inner);
                ipv4 = Some((read_ipv4(&mut e)?, read_ipv4(&mut e)?));
            }
            EXT_IPV6_FLOW => {
                let mut e = std::io::Cursor::new(inner);
                ipv6 = Some((read_ipv6(&mut e)?, read_ipv6(&mut e)?));
            }
            EXT_CNT_FLOW => {
                let mut e = std::io::Cursor::new(inner);
                let _flows = e.read_u64::<LittleEndian>()?;
                let out_pkts = e.read_u64::<LittleEndian>()?;
                let out_bytes = e.read_u64::<LittleEndian>()?;
                cnt = Some((out_pkts, out_bytes));
            }
            _ => {} // Unrecognized extension: skip by stepping the cursor below.
        }
        // Advance past this extension by its declared size whether or not we
        // decoded it, keeping the element walk aligned.
        c.set_position(end as u64);
    }

    let g = generic.ok_or_else(|| {
        NfdumpError::Corrupt("v3 flow record has no generic-flow extension".into())
    })?;
    let (src_ip, dst_ip) = ipv4.or(ipv6).ok_or_else(|| {
        NfdumpError::Corrupt("v3 flow record has no IPv4/IPv6 endpoint extension".into())
    })?;
    Ok(NfdumpFlow {
        first_ms: g.msec_first,
        last_ms: g.msec_last,
        src_ip,
        dst_ip,
        src_port: g.src_port,
        dst_port: g.dst_port,
        protocol: g.proto,
        fwd_bytes: g.in_bytes,
        fwd_pkts: g.in_packets,
        bwd_bytes: cnt.map(|(_, b)| b),
        bwd_pkts: cnt.map(|(p, _)| p),
    })
}

struct GenericFlow {
    msec_first: u64,
    msec_last: u64,
    in_packets: u64,
    in_bytes: u64,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

fn parse_generic_flow(inner: &[u8]) -> Result<GenericFlow> {
    let mut e = std::io::Cursor::new(inner);
    let msec_first = e.read_u64::<LittleEndian>()?;
    let msec_last = e.read_u64::<LittleEndian>()?;
    let _msec_received = e.read_u64::<LittleEndian>()?;
    let in_packets = e.read_u64::<LittleEndian>()?;
    let in_bytes = e.read_u64::<LittleEndian>()?;
    let src_port = e.read_u16::<LittleEndian>()?;
    let dst_port = e.read_u16::<LittleEndian>()?;
    let proto = e.read_u8()?;
    Ok(GenericFlow {
        msec_first,
        msec_last,
        in_packets,
        in_bytes,
        src_port,
        dst_port,
        proto,
    })
}

fn read_ipv4(c: &mut std::io::Cursor<&[u8]>) -> Result<IpAddr> {
    Ok(IpAddr::V4(Ipv4Addr::from(c.read_u32::<LittleEndian>()?)))
}

fn read_ipv6(c: &mut std::io::Cursor<&[u8]>) -> Result<IpAddr> {
    Ok(IpAddr::V6(Ipv6Addr::from(c.read_u128::<LittleEndian>()?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SAMPLE_PLAIN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/sample.nfcapd"
    ));
    const SAMPLE_LZ4: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample_lz4.nfcapd"
    ));
    const SAMPLE_LZO: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample_lzo.nfcapd"
    ));
    const SAMPLE_BZ2: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample_bz2.nfcapd"
    ));

    fn read_all(bytes: &[u8]) -> Result<Vec<NfdumpFlow>> {
        let mut reader = NfdumpFlowReader::new(Cursor::new(bytes))?;
        let mut flows = Vec::new();
        while let Some(f) = reader.next_flow()? {
            flows.push(f);
        }
        Ok(flows)
    }

    /// The bundled fixtures hold the same five NetFlow v5 flows; every codec
    /// (plain/lz4/lzo/bz2) must decode to identical flows — this exercises the
    /// pure-Rust LZO path in particular.
    #[test]
    fn decodes_every_codec_to_the_same_flows() {
        let plain = read_all(SAMPLE_PLAIN).unwrap();
        assert_eq!(plain.len(), 5);
        for (label, bytes) in [
            ("lz4", SAMPLE_LZ4),
            ("lzo", SAMPLE_LZO),
            ("bz2", SAMPLE_BZ2),
        ] {
            let got = read_all(bytes).unwrap_or_else(|e| panic!("{label} decode failed: {e}"));
            let pairs = |v: &[NfdumpFlow]| {
                v.iter()
                    .map(|f| {
                        (
                            f.first_ms,
                            f.last_ms,
                            f.src_ip,
                            f.dst_ip,
                            f.src_port,
                            f.dst_port,
                            f.protocol,
                            f.fwd_bytes,
                            f.fwd_pkts,
                        )
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(pairs(&got), pairs(&plain), "{label} differs from plain");
        }
    }

    #[test]
    fn first_flow_fields_match_nfdump() {
        let flows = read_all(SAMPLE_PLAIN).unwrap();
        let f = &flows[0];
        assert_eq!(f.src_ip.to_string(), "10.0.0.1");
        assert_eq!(f.dst_ip.to_string(), "10.0.0.2");
        assert_eq!((f.src_port, f.dst_port), (44321, 443));
        assert_eq!(f.protocol, 6);
        assert_eq!((f.fwd_bytes, f.fwd_pkts), (1200, 8));
        // 5 V5 records are single-counter -> no reverse direction.
        assert_eq!((f.bwd_bytes, f.bwd_pkts), (None, None));
        // 2.5s flow: msec_last - msec_first == 2500.
        assert_eq!(f.last_ms - f.first_ms, 2500);
    }

    #[test]
    fn rejects_bad_magic() {
        let r = NfdumpFlowReader::new(Cursor::new(&b"\x00\x01not-nfdump"[..]));
        assert!(matches!(r, Err(NfdumpError::InvalidMagic(_))));
    }

    #[test]
    fn rejects_unsupported_version() {
        // Correct magic (0xa50c LE), version 0x0009.
        let buf = [0x0c, 0xa5, 0x09, 0x00];
        let r = NfdumpFlowReader::new(Cursor::new(&buf[..]));
        assert!(matches!(r, Err(NfdumpError::UnsupportedVersion(9))));
    }

    /// A file truncated mid-stream must surface an error, never a clean EOF
    /// that looks like a complete (but short) read.
    #[test]
    fn truncated_file_errors_not_eof() {
        // Cut the fixture inside its data block (header parsed, body short).
        let truncated = &SAMPLE_PLAIN[..SAMPLE_PLAIN.len() - 200];
        let mut reader = NfdumpFlowReader::new(Cursor::new(truncated)).unwrap();
        let mut hit_err = false;
        loop {
            match reader.next_flow() {
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => {
                    hit_err = true;
                    break;
                }
            }
        }
        assert!(
            hit_err,
            "truncated capture should error, not reach clean EOF"
        );
    }

    #[test]
    fn header_only_truncation_errors() {
        // Magic + version only, then nothing: header read must fail loudly.
        let buf = [0x0c, 0xa5, 0x02, 0x00];
        assert!(NfdumpFlowReader::new(Cursor::new(&buf[..])).is_err());
    }
}
