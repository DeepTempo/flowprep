use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum NfdumpError {
    EOF,
    IoError(io::Error),
    InvalidFile,
    UnexpectedSAInExporter,
    ParseError,
    UnsupportedVersion,
    UnsupportedCompression,
    UnexpectedExtension,
}

impl Display for NfdumpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NfdumpError::EOF => write!(f, "no more records to read (end of file)"),
            NfdumpError::IoError(e) => write!(f, "IO error: {}", e),
            NfdumpError::InvalidFile => write!(f, "invalid file"),
            NfdumpError::UnexpectedSAInExporter => {
                write!(f, "unexpected sa value in exporter record")
            }
            NfdumpError::ParseError => write!(f, "parser error"),
            NfdumpError::UnsupportedVersion => write!(f, "nfdump file version not supported (yet)"),
            NfdumpError::UnsupportedCompression => {
                write!(f, "nfdump file compression not supported")
            }
            NfdumpError::UnexpectedExtension => write!(f, "unexpected extension"),
        }
    }
}

impl Error for NfdumpError {}

impl From<io::Error> for NfdumpError {
    fn from(error: io::Error) -> Self {
        NfdumpError::IoError(error)
    }
}
