use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Read;

pub struct NfFileHeaderV1 {
    pub magic: u16,
    pub version: u16,
    pub flags: u32,
    pub num_blocks: u32,
    pub ident: [u8; 128],
}

/// `StatRecordV1` represents a stat record.
#[derive(Default, Debug)]
pub struct StatRecordV1 {
    pub flows: u64,
    pub bytes: u64,
    pub packets: u64,

    pub flows_tcp: u64,
    pub flows_udp: u64,
    pub flows_icmp: u64,
    pub flows_other: u64,

    pub bytes_tcp: u64,
    pub bytes_udp: u64,
    pub bytes_icmp: u64,
    pub bytes_other: u64,

    pub packets_tcp: u64,
    pub packets_udp: u64,
    pub packets_icmp: u64,
    pub packets_other: u64,

    pub first_seen: u32,
    pub last_seen: u32,
    pub msec_first: u16,
    pub msec_last: u16,

    pub sequence_failure: u32,
}

impl From<Vec<u8>> for NfFileHeaderV1 {
    fn from(value: Vec<u8>) -> Self {
        let mut cursor = std::io::Cursor::new(&value);

        NfFileHeaderV1 {
            magic: 0xa50c,
            version: 0x0001,
            flags: cursor.read_u32::<LittleEndian>().unwrap(),
            num_blocks: cursor.read_u32::<LittleEndian>().unwrap(),
            ident: {
                let mut arr: [u8; 128] = [0; 128];
                _ = cursor.read_exact(&mut arr);
                arr
            },
        }
    }
}

impl From<Vec<u8>> for StatRecordV1 {
    fn from(value: Vec<u8>) -> StatRecordV1 {
        let mut cursor = std::io::Cursor::new(&value);

        StatRecordV1 {
            flows: cursor.read_u64::<LittleEndian>().unwrap(),
            bytes: cursor.read_u64::<LittleEndian>().unwrap(),
            packets: cursor.read_u64::<LittleEndian>().unwrap(),
            flows_tcp: cursor.read_u64::<LittleEndian>().unwrap(),
            flows_udp: cursor.read_u64::<LittleEndian>().unwrap(),
            flows_icmp: cursor.read_u64::<LittleEndian>().unwrap(),
            flows_other: cursor.read_u64::<LittleEndian>().unwrap(),
            bytes_tcp: cursor.read_u64::<LittleEndian>().unwrap(),
            bytes_udp: cursor.read_u64::<LittleEndian>().unwrap(),
            bytes_icmp: cursor.read_u64::<LittleEndian>().unwrap(),
            bytes_other: cursor.read_u64::<LittleEndian>().unwrap(),
            packets_tcp: cursor.read_u64::<LittleEndian>().unwrap(),
            packets_udp: cursor.read_u64::<LittleEndian>().unwrap(),
            packets_icmp: cursor.read_u64::<LittleEndian>().unwrap(),
            packets_other: cursor.read_u64::<LittleEndian>().unwrap(),
            first_seen: cursor.read_u32::<LittleEndian>().unwrap(),
            last_seen: cursor.read_u32::<LittleEndian>().unwrap(),
            msec_first: cursor.read_u16::<LittleEndian>().unwrap(),
            msec_last: cursor.read_u16::<LittleEndian>().unwrap(),
            sequence_failure: cursor.read_u32::<LittleEndian>().unwrap(),
        }
    }
}
