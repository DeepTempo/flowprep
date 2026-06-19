use byteorder::{LittleEndian, ReadBytesExt};

pub struct NfFileHeaderV2 {
    pub magic: u16,
    pub version: u16,
    pub nf_version: u32,
    pub created: u64,
    pub compression: u8,
    pub encryption: u8,
    pub appendix_blocks: u16,
    pub unused: u32,
    pub off_appendix: u64,
    pub block_size: u32,
    pub num_blocks: u32,
    pub ident: Vec<u8>,
}

#[derive(Default, Debug)]
pub struct StatRecordV2 {
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
    pub first_seen: u64,
    pub last_seen: u64,
    pub sequence_failure: u64,
}

impl From<Vec<u8>> for NfFileHeaderV2 {
    fn from(value: Vec<u8>) -> Self {
        let mut cursor = std::io::Cursor::new(&value);

        NfFileHeaderV2 {
            magic: 0xa50c,
            version: 0x0002,
            nf_version: cursor.read_u32::<LittleEndian>().unwrap(),
            created: cursor.read_u64::<LittleEndian>().unwrap(),
            compression: cursor.read_u8().unwrap(),
            encryption: cursor.read_u8().unwrap(),
            appendix_blocks: cursor.read_u16::<LittleEndian>().unwrap(),
            unused: cursor.read_u32::<LittleEndian>().unwrap(),
            off_appendix: cursor.read_u64::<LittleEndian>().unwrap(),
            block_size: cursor.read_u32::<LittleEndian>().unwrap(),
            num_blocks: cursor.read_u32::<LittleEndian>().unwrap(),
            ident: Vec::new(),
        }
    }
}

impl From<Vec<u8>> for StatRecordV2 {
    fn from(value: Vec<u8>) -> StatRecordV2 {
        let mut cursor = std::io::Cursor::new(&value);

        StatRecordV2 {
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
            first_seen: cursor.read_u64::<LittleEndian>().unwrap(),
            last_seen: cursor.read_u64::<LittleEndian>().unwrap(),
            sequence_failure: cursor.read_u64::<LittleEndian>().unwrap(),
        }
    }
}
