//! nfdump data-block decompression.
//!
//! nfdump compresses each data block independently with one of a small set of
//! codecs. Every codec here is pure-Rust or a vendored-C crate already linked
//! by flowprep — there is no system `liblzo2` dependency: LZO1X uses the
//! MIT-licensed `lzokay-native` (a clean-room lzokay port), so the binary stays
//! fully static.
//!
//! All paths are bounded: the caller caps the *compressed* block size before
//! calling, and each decoder caps the *decompressed* size, so a corrupt length
//! or a decompression bomb produces an error rather than an unbounded
//! allocation.

use std::io::Read;

use super::error::NfdumpError;

pub const COMPRESSION_PLAIN: u8 = 0;
pub const COMPRESSION_LZO: u8 = 1;
pub const COMPRESSION_BZ2: u8 = 2;
pub const COMPRESSION_LZ4: u8 = 3;
pub const COMPRESSION_ZSTD: u8 = 4;

/// Upper bound on a single decompressed block. nfdump's own write buffer is a
/// few MiB; this is generous headroom while still refusing pathological output.
const MAX_DECOMPRESSED: usize = 256 * 1024 * 1024;
/// LZ4 block decode needs a destination buffer; nfdump V1 files carry no
/// uncompressed-size hint, so this is the fallback when none is known.
const DEFAULT_LZ4_BUF: usize = 16 * 1024 * 1024;
const MIN_LZ4_BUF: usize = 64 * 1024;

/// Decompress one block. `hint` is the uncompressed size when the file header
/// records it (V2 `block_size`); it is only an allocation hint, never trusted
/// as an exact length.
pub fn decompress(codec: u8, data: Vec<u8>, hint: Option<usize>) -> Result<Vec<u8>, NfdumpError> {
    match codec {
        COMPRESSION_PLAIN => Ok(data),
        COMPRESSION_LZO => {
            let out = lzokay_native::decompress_all(&data, hint)
                .map_err(|e| NfdumpError::Decompress(format!("LZO: {e:?}")))?;
            cap(out)
        }
        COMPRESSION_BZ2 => read_capped(bzip2::read::BzDecoder::new(&data[..]), "bzip2"),
        COMPRESSION_ZSTD => {
            let dec = zstd::stream::read::Decoder::new(&data[..])
                .map_err(|e| NfdumpError::Decompress(format!("zstd init: {e}")))?;
            read_capped(dec, "zstd")
        }
        COMPRESSION_LZ4 => {
            let buf_size = hint
                .unwrap_or(DEFAULT_LZ4_BUF)
                .clamp(MIN_LZ4_BUF, MAX_DECOMPRESSED);
            let mut out = vec![0u8; buf_size];
            let n = lz4_flex::block::decompress_into(&data, &mut out).map_err(|e| {
                NfdumpError::Decompress(format!("lz4 (dest buffer {buf_size}): {e}"))
            })?;
            out.truncate(n);
            Ok(out)
        }
        other => Err(NfdumpError::UnsupportedCompression(other)),
    }
}

/// Read a streaming decoder to end, refusing output larger than the cap.
fn read_capped<R: Read>(reader: R, what: &str) -> Result<Vec<u8>, NfdumpError> {
    let mut out = Vec::new();
    // take(cap+1): if the decoder yields more than the cap we error instead of
    // growing `out` without bound (decompression-bomb guard).
    reader
        .take(MAX_DECOMPRESSED as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| NfdumpError::Decompress(format!("{what}: {e}")))?;
    cap(out)
}

fn cap(out: Vec<u8>) -> Result<Vec<u8>, NfdumpError> {
    if out.len() > MAX_DECOMPRESSED {
        return Err(NfdumpError::Decompress(format!(
            "decompressed block exceeds {MAX_DECOMPRESSED} bytes"
        )));
    }
    Ok(out)
}
