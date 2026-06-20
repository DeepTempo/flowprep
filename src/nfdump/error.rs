//! Errors for the nfdump/nfcapd reader.
//!
//! Clean end-of-file is *not* an error — `NfdumpFlowReader::next_flow` returns
//! `Ok(None)` for that. Every variant here means the input was unreadable,
//! unsupported, or corrupt, so a truncated or malformed capture can never be
//! mistaken for a clean, complete read.

use std::fmt;

#[derive(Debug)]
pub enum NfdumpError {
    /// Underlying read failed (including a short read on a truncated file).
    Io(std::io::Error),
    /// File magic was not nfdump's `0xa50c`.
    InvalidMagic(u16),
    /// File layout version is not one this reader understands (1 or 2).
    UnsupportedVersion(u16),
    /// Block compression codec is not supported.
    UnsupportedCompression(u8),
    /// A size/offset invariant in the container was violated.
    Corrupt(String),
    /// Block decompression failed or produced an implausibly large output.
    Decompress(String),
}

impl fmt::Display for NfdumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NfdumpError::Io(e) => write!(f, "io error: {e}"),
            NfdumpError::InvalidMagic(m) => {
                write!(f, "not an nfdump file (magic {m:#06x}, expected 0xa50c)")
            }
            NfdumpError::UnsupportedVersion(v) => write!(f, "unsupported nfdump file version {v}"),
            NfdumpError::UnsupportedCompression(c) => {
                write!(f, "unsupported nfdump block compression {c}")
            }
            NfdumpError::Corrupt(msg) => write!(f, "corrupt nfdump file: {msg}"),
            NfdumpError::Decompress(msg) => write!(f, "nfdump block decompression failed: {msg}"),
        }
    }
}

impl std::error::Error for NfdumpError {}

impl From<std::io::Error> for NfdumpError {
    fn from(e: std::io::Error) -> Self {
        NfdumpError::Io(e)
    }
}
