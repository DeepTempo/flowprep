//! nfdump/nfcapd binary file reader (vendored).
//!
//! Vendored from the `nfdump` crate (https://github.com/markzz/rust-nfdump,
//! ISC, © 2023 Mark King) so flowprep can read nfcapd files without inheriting
//! that crate's `minilzo` dependency, which dynamically links the GPL system
//! `liblzo2` and would break flowprep's single-static-binary guarantee. The
//! only functional change is in `compress.rs`: LZO1X block decompression now
//! uses the pure-Rust, MIT-licensed `lzokay-native` (a clean-room lzokay port)
//! instead of `minilzo`. `nfx_v3.rs` also stores MAC addresses as raw bytes to
//! drop the `eui48` dependency, which flowprep never reads.
//!
//! See ../nfcapd.rs for the canonicalization layer that maps these records onto
//! the canonical NetFlow schema. Lint and dead-code checks are relaxed for this
//! subtree because it intentionally models the full on-disk format (exporters,
//! stat records, V3 extensions) even though flowprep consumes only flow fields.
#![allow(dead_code, clippy::all)]

mod block;
mod compress;
pub mod error;
mod exporter;
mod nffilev1;
mod nffilev2;
mod nfx;
pub mod nfx_v3;
pub mod record;

use crate::nfdump::block::{DataBlock, DataBlockHeader};
use crate::nfdump::compress::{
    Decompressor, NFDUMP_COMPRESSION_TYPE_BZ2, NFDUMP_COMPRESSION_TYPE_LZ4,
    NFDUMP_COMPRESSION_TYPE_LZO, NFDUMP_COMPRESSION_TYPE_PLAIN, NFDUMP_COMPRESSION_TYPE_ZSTD,
};
use crate::nfdump::error::NfdumpError;
use crate::nfdump::exporter::ExporterInfo;
use crate::nfdump::nffilev1::{NfFileHeaderV1, StatRecordV1};
use crate::nfdump::nffilev2::{NfFileHeaderV2, StatRecordV2};
use crate::nfdump::record::RecordKind;
use byteorder::{LittleEndian, ReadBytesExt};
use std::default::Default;
use std::io::{Read, Seek, SeekFrom};

const NFFILE_V1_HEADER_SIZE: usize = 140;
const NFFILE_V2_HEADER_SIZE: usize = 40;
const NFFILE_V1_STAT_RECORD_SIZE: usize = 136;

pub enum NfFileHeader {
    V1(NfFileHeaderV1),
    V2(NfFileHeaderV2),
}

#[derive(Debug)]
pub enum StatRecord {
    V1(StatRecordV1),
    V2(StatRecordV2),
}

/// `NfFileReader` reads nfdump files and exposes their flow records.
pub struct NfFileReader<R> {
    reader: R,
    pub header: NfFileHeader,
    pub stat_record: StatRecord,
    data_block: Option<DataBlock>,
    remaining_blocks: u32,
    extensions: Vec<u16>,
    exporters: Vec<ExporterInfo>,
}

impl<R: Read + Seek> NfFileReader<R> {
    /// Create a new `NfFileReader` from a seekable reader, parsing the file
    /// header, stat record, and (for V2 files) the appendix.
    pub fn new(mut reader: R) -> Result<Self, NfdumpError> {
        let magic = reader.read_u16::<LittleEndian>()?;
        if magic != 0xa50c {
            return Err(NfdumpError::InvalidFile);
        }

        let version = reader.read_u16::<LittleEndian>()?;
        let header = match version {
            0x0001 => {
                let mut hbuf = vec![0; NFFILE_V1_HEADER_SIZE - 4];
                reader.read_exact(&mut hbuf)?;
                NfFileHeader::V1(NfFileHeaderV1::from(hbuf))
            }
            0x0002 => {
                let mut hbuf = vec![0; NFFILE_V2_HEADER_SIZE - 4];
                reader.read_exact(&mut hbuf)?;
                NfFileHeader::V2(NfFileHeaderV2::from(hbuf))
            }
            _ => return Err(NfdumpError::UnsupportedVersion),
        };

        let stat_record = match version {
            0x0001 => {
                let mut srbuf = vec![0; NFFILE_V1_STAT_RECORD_SIZE];
                match reader.read_exact(&mut srbuf) {
                    Ok(_) => StatRecord::V1(StatRecordV1::from(srbuf)),
                    Err(e) => return Err(NfdumpError::from(e)),
                }
            }
            0x0002 => {
                let x: StatRecordV2 = Default::default();
                StatRecord::V2(x)
            }
            _ => return Err(NfdumpError::UnsupportedVersion),
        };

        let remaining_blocks = match &header {
            NfFileHeader::V1(h) => h.num_blocks,
            NfFileHeader::V2(h) => h.num_blocks,
        };

        let mut ret = Self {
            reader,
            header,
            stat_record,
            data_block: None,
            remaining_blocks,
            extensions: Vec::new(),
            exporters: Vec::new(),
        };

        _ = ret.read_appendix();

        Ok(ret)
    }

    /// Return the file's identification string.
    pub fn get_ident(&self) -> Vec<u8> {
        match &self.header {
            NfFileHeader::V1(h) => h.ident.to_vec(),
            NfFileHeader::V2(h) => h.ident.to_vec(),
        }
    }

    fn read_appendix(&mut self) -> Result<(), NfdumpError> {
        if let NfFileHeader::V2(header) = &self.header {
            self.reader.seek(SeekFrom::Start(header.off_appendix))?;
            for _ in 0..header.appendix_blocks {
                self.read_data_block()?;
                while let Some(r) = self
                    .data_block
                    .as_mut()
                    .unwrap()
                    .read_record(&self.extensions)
                {
                    match r {
                        RecordKind::Ident(i) => {
                            if let NfFileHeader::V2(header) = &mut self.header {
                                header.ident = i;
                            }
                        }
                        RecordKind::Stat(s) => {
                            self.stat_record = StatRecord::V2(s);
                        }
                        _ => {}
                    }
                }
            }
            self.reader
                .seek(SeekFrom::Start(NFFILE_V2_HEADER_SIZE as u64))?;
        }
        self.data_block = None;
        Ok(())
    }

    fn _read_record(&mut self) -> Result<RecordKind, NfdumpError> {
        if self.data_block.is_none() && self.remaining_blocks > 0 {
            if let NfFileHeader::V2(h) = &self.header {
                if self.reader.seek(SeekFrom::Current(0)).unwrap() >= h.off_appendix {
                    return Err(NfdumpError::EOF);
                }
            }
            self.read_data_block()?;
            self.remaining_blocks -= 1;
        } else if self.data_block.is_none() && self.remaining_blocks == 0 {
            return Err(NfdumpError::EOF);
        }

        let record = self
            .data_block
            .as_mut()
            .unwrap()
            .read_record(&self.extensions);
        if record.is_none() {
            self.data_block = None;
            return self._read_record();
        }
        record.ok_or(NfdumpError::EOF)
    }

    /// Read the next flow record, returning `RecordKind::Record` (V1 file) or
    /// `RecordKind::RecordV3` (V2 file). Internal records (extension maps,
    /// exporters, stat/ident blocks) are consumed transparently.
    pub fn read_record(&mut self) -> Result<RecordKind, NfdumpError> {
        while let Ok(r) = self._read_record() {
            match r {
                RecordKind::ExtensionMap(e) => self.extensions = e.ex_id.clone(),
                RecordKind::ExporterInfo(e) => self.exporters.push(e.clone()),
                RecordKind::Record(_) | RecordKind::RecordV3(_) => return Ok(r),
                RecordKind::None if self.remaining_blocks > 0 => {
                    self.read_data_block()?;
                    self.remaining_blocks -= 1;
                    continue;
                }
                RecordKind::None => return Err(NfdumpError::EOF),
                _ => continue,
            }
        }
        Err(NfdumpError::EOF)
    }

    fn read_data_block(&mut self) -> Result<(), NfdumpError> {
        let mut db_buf = vec![0; 12];
        self.reader.read_exact(&mut db_buf)?;

        let mut cursor = std::io::Cursor::new(db_buf);

        let num_records = cursor.read_u32::<LittleEndian>()?;
        let size = cursor.read_u32::<LittleEndian>()?;
        let id = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u16::<LittleEndian>()?;

        let mut data = vec![0; size as usize];
        self.reader.read_exact(&mut data)?;

        let decompressor = NfFileReader::<R>::select_decompressor(&self.header, data)?;

        let db_header = DataBlockHeader {
            num_records,
            size,
            id,
            flags,
        };

        self.data_block = Some(DataBlock::new(db_header, decompressor));

        Ok(())
    }

    fn select_decompressor(
        header: &NfFileHeader,
        data: Vec<u8>,
    ) -> Result<Box<Decompressor>, NfdumpError> {
        match header {
            NfFileHeader::V1(h) => {
                let decompressor: Box<Decompressor> = match h.flags & 0x19 {
                    0x01 => Box::new(Decompressor::new(NFDUMP_COMPRESSION_TYPE_LZO, data)?),
                    0x08 => Box::new(Decompressor::new(NFDUMP_COMPRESSION_TYPE_BZ2, data)?),
                    0x10 => Box::new(Decompressor::new(NFDUMP_COMPRESSION_TYPE_LZ4, data)?),
                    _ => Box::new(Decompressor::new(NFDUMP_COMPRESSION_TYPE_PLAIN, data)?),
                };

                Ok(decompressor)
            }
            NfFileHeader::V2(h) => match h.compression {
                0 => Ok(Box::new(Decompressor::new(
                    NFDUMP_COMPRESSION_TYPE_PLAIN,
                    data,
                )?)),
                1 => Ok(Box::new(Decompressor::new(
                    NFDUMP_COMPRESSION_TYPE_LZO,
                    data,
                )?)),
                2 => Ok(Box::new(Decompressor::new(
                    NFDUMP_COMPRESSION_TYPE_BZ2,
                    data,
                )?)),
                3 => Ok(Box::new(Decompressor::new(
                    NFDUMP_COMPRESSION_TYPE_LZ4,
                    data,
                )?)),
                4 => Ok(Box::new(Decompressor::new(
                    NFDUMP_COMPRESSION_TYPE_ZSTD,
                    data,
                )?)),
                _ => Err(NfdumpError::UnsupportedCompression),
            },
        }
    }
}
