use crate::nfdump::compress::Decompressor;
use crate::nfdump::exporter::{read_exporter_record, read_samplerv0_record};
use crate::nfdump::nffilev2::StatRecordV2;
use crate::nfdump::nfx::read_extension_map;
use crate::nfdump::nfx_v3::RecordV3;
use crate::nfdump::record::*;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

const TYPE_COMMON_RECORD_V0: u16 = 0x0001;
const TYPE_EXTENSION_MAP: u16 = 0x0002;
const TYPE_PORT_HISTOGRAM: u16 = 0x0003;
const TYPE_BPP_HISTOGRAM: u16 = 0x0004;
const TYPE_LEGACY_RECORD_1: u16 = 0x0005;
const TYPE_LEGACY_RECORD_2: u16 = 0x0006;
const TYPE_EXPORTER_INFO: u16 = 0x0007;
const TYPE_EXPORTER_STAT: u16 = 0x0008;
const TYPE_LEGACY_SAMPLER: u16 = 0x0009;
const TYPE_COMMON_RECORD: u16 = 0x000a;
const TYPE_RECORD_V3: u16 = 0x000b;
const TYPE_NBAR_RECORD: u16 = 0x000c;
const TYPE_IF_NAME_RECORD: u16 = 0x000d;
const TYPE_VRF_NAME_RECORD: u16 = 0x000e;
const TYPE_SAMPLER: u16 = 0x000f;
const TYPE_IDENT: u16 = 0x8001;
const TYPE_STAT: u16 = 0x8002;

#[allow(dead_code)]
pub(crate) struct DataBlockHeader {
    pub(crate) num_records: u32,
    pub(crate) size: u32,
    // id is type in v3/v4 block (v2 files only)
    pub(crate) id: u16,
    pub(crate) flags: u16,
}

pub(crate) struct DataBlock {
    pub(crate) decoder: Box<Decompressor>,
    pub(crate) _header: DataBlockHeader,
    // pub(crate) data: Vec<u8>,
}

impl DataBlock {
    pub(crate) fn new(header: DataBlockHeader, decoder: Box<Decompressor>) -> DataBlock {
        DataBlock {
            _header: header,
            decoder,
        }
    }

    fn _read_record_kind(&mut self, header: &NfFileRecordHeader, ext: &Vec<u16>) -> RecordKind {
        let mut record_data = vec![0; header.size as usize - 4];
        _ = self.decoder.read_exact(&mut record_data);

        match header.rtype {
            TYPE_COMMON_RECORD_V0 => RecordKind::Unimplemented,
            TYPE_EXTENSION_MAP => {
                RecordKind::ExtensionMap(read_extension_map(*header, record_data).unwrap())
            }
            TYPE_PORT_HISTOGRAM => RecordKind::Unimplemented,
            TYPE_BPP_HISTOGRAM => RecordKind::Unimplemented,
            TYPE_LEGACY_RECORD_1 => RecordKind::Unimplemented,
            TYPE_LEGACY_RECORD_2 => RecordKind::Unimplemented,
            TYPE_EXPORTER_INFO => {
                RecordKind::ExporterInfo(read_exporter_record(*header, record_data).unwrap())
            }
            TYPE_EXPORTER_STAT => RecordKind::Unimplemented,
            TYPE_LEGACY_SAMPLER => {
                RecordKind::SamplerV0(read_samplerv0_record(*header, record_data).unwrap())
            }
            TYPE_COMMON_RECORD => {
                RecordKind::Record(new_record(*header, record_data, ext).unwrap())
            }
            TYPE_RECORD_V3 => RecordKind::RecordV3(RecordV3::new(*header, record_data).unwrap()),
            TYPE_NBAR_RECORD => RecordKind::Unimplemented,
            TYPE_IF_NAME_RECORD => RecordKind::Unimplemented,
            TYPE_VRF_NAME_RECORD => RecordKind::Unimplemented,
            TYPE_SAMPLER => RecordKind::Unimplemented,
            TYPE_IDENT => RecordKind::Ident(record_data),
            TYPE_STAT => RecordKind::Stat(StatRecordV2::from(record_data)),
            _ => RecordKind::Unimplemented,
        }
    }

    pub(crate) fn read_record(&mut self, ext: &Vec<u16>) -> Option<RecordKind> {
        let mut header_data = [0; 4];
        let record_header = match self.decoder.read_exact(&mut header_data) {
            Ok(_) => {
                let mut cursor = Cursor::new(&header_data);
                NfFileRecordHeader {
                    rtype: cursor.read_u16::<LittleEndian>().unwrap(),
                    size: cursor.read_u16::<LittleEndian>().unwrap(),
                }
            }
            Err(_) => {
                return None;
            }
        };

        Some(self._read_record_kind(&record_header, ext))
    }
}
