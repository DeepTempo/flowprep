use bzip2::read::BzDecoder;
use std::io::{self, BufReader, Cursor, Error, ErrorKind, Read};
use zstd::Decoder as ZstdDecoder;

pub(crate) const NFDUMP_COMPRESSION_TYPE_PLAIN: u8 = 0;
pub(crate) const NFDUMP_COMPRESSION_TYPE_LZO: u8 = 1;
pub(crate) const NFDUMP_COMPRESSION_TYPE_BZ2: u8 = 2;
pub(crate) const NFDUMP_COMPRESSION_TYPE_LZ4: u8 = 3;
pub(crate) const NFDUMP_COMPRESSION_TYPE_ZSTD: u8 = 4;

const BUFSIZE: usize = 5 * 1048576;

pub enum Decompressor {
    Lzo(LzoDecompressor),
    Lz4(Lz4Decompressor),
    Bz2(Bz2Decompressor),
    Zstd(ZstdDecompressor<'static>),
    Plain(PlainDecompressor),
}

impl Decompressor {
    pub(crate) fn new(dtype: u8, data: Vec<u8>) -> Result<Self, Error> {
        let decompressor = match dtype {
            NFDUMP_COMPRESSION_TYPE_LZO => Decompressor::Lzo(LzoDecompressor::new(data)?),
            NFDUMP_COMPRESSION_TYPE_LZ4 => Decompressor::Lz4(Lz4Decompressor::new(data)?),
            NFDUMP_COMPRESSION_TYPE_BZ2 => Decompressor::Bz2(Bz2Decompressor::new(data)?),
            NFDUMP_COMPRESSION_TYPE_ZSTD => Decompressor::Zstd(ZstdDecompressor::new(data)?),
            NFDUMP_COMPRESSION_TYPE_PLAIN => Decompressor::Plain(PlainDecompressor::new(data)?),
            _ => {
                return Err(Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported compression",
                ));
            }
        };

        Ok(decompressor)
    }
}

impl Read for Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            Decompressor::Lz4(d) => d.read(buf),
            Decompressor::Bz2(d) => d.read(buf),
            Decompressor::Plain(d) => d.read(buf),
            Decompressor::Lzo(d) => d.read(buf),
            Decompressor::Zstd(d) => d.read(buf),
        }
    }
}

pub struct ZstdDecompressor<'a> {
    pub(crate) d: Box<ZstdDecoder<'a, BufReader<Cursor<Vec<u8>>>>>,
}

impl ZstdDecompressor<'_> {
    fn new(data: Vec<u8>) -> Result<Self, Error> {
        let cursor = Cursor::new(data);
        let d = ZstdDecoder::new(cursor)?;
        Ok(ZstdDecompressor { d: Box::new(d) })
    }
}

impl Read for ZstdDecompressor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.d.read(buf)
    }
}

pub struct LzoDecompressor {
    pub(crate) d: Cursor<Vec<u8>>,
}

impl LzoDecompressor {
    fn new(data: Vec<u8>) -> Result<Self, Error> {
        // flowprep change: pure-Rust LZO1X (lzokay-native, MIT) replaces the
        // GPL `minilzo` FFI binding so the binary stays fully static. nfdump
        // blocks are uncapped on the decode side; BUFSIZE is the upstream
        // buffer hint, passed through as a starting capacity.
        let decompressed = lzokay_native::decompress_all(data.as_slice(), Some(BUFSIZE))
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("LZO decode failed: {e}")))?;
        let d = Cursor::new(decompressed);
        Ok(LzoDecompressor { d })
    }
}

impl Read for LzoDecompressor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.d.read(buf)
    }
}

pub struct Lz4Decompressor {
    pub(crate) d: Cursor<Vec<u8>>,
}

impl Lz4Decompressor {
    fn new(data: Vec<u8>) -> Result<Self, Error> {
        let mut out: [u8; BUFSIZE] = [0; BUFSIZE];
        let size = match lz4_flex::block::decompress_into(&data, &mut out) {
            Ok(s) => s,
            Err(_) => 0,
        };

        match size {
            1.. => {
                let trimmed_vec = out[..size].to_vec();
                let d = Cursor::new(trimmed_vec);
                Ok(Lz4Decompressor { d })
            }
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Lz4 decompression failed",
            )),
        }
    }
}

impl Read for Lz4Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.d.read(buf)
    }
}

pub struct Bz2Decompressor {
    pub(crate) d: BzDecoder<Cursor<Vec<u8>>>,
}

impl Bz2Decompressor {
    pub(crate) fn new(data: Vec<u8>) -> Result<Self, Error> {
        let cursor = Cursor::new(data);
        Ok(Bz2Decompressor {
            d: BzDecoder::new(cursor),
        })
    }
}

impl Read for Bz2Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.d.read(buf)
    }
}

pub struct PlainDecompressor {
    pub(crate) d: Cursor<Vec<u8>>,
}

impl PlainDecompressor {
    fn new(data: Vec<u8>) -> Result<Self, Error> {
        let cursor = Cursor::new(data);
        Ok(PlainDecompressor { d: cursor })
    }
}
impl Read for PlainDecompressor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.d.read(buf)
    }
}
