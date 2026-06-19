use crate::nfdump::error::NfdumpError;
use crate::nfdump::record::NfFileRecordHeader;
use byteorder::{LittleEndian, ReadBytesExt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
#[derive(Debug, Copy, Clone)]
pub struct ExporterInfo {
    pub header: NfFileRecordHeader,
    pub version: u32,
    pub address: IpAddr,
    pub sa_family: u16,
    pub sysid: u16,
    pub id: u32,
}

#[derive(Debug)]
pub struct SamplerV0Record {
    pub header: NfFileRecordHeader,
    pub id: i32,
    pub interval: u32,
    pub algorithm: u16,
    pub exporter_sysid: u16,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ExporterStatsRecord {
    pub header: NfFileRecordHeader,
    pub stat_count: u32,
    pub stat: Vec<ExporterStat>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ExporterStat {
    pub sysid: u32,
    pub sequence_failure: u32,
    pub packets: u64,
    pub flows: u64,
}

pub fn read_exporter_record(
    header: NfFileRecordHeader,
    record_data: Vec<u8>,
) -> Result<ExporterInfo, NfdumpError> {
    let mut cursor = std::io::Cursor::new(&record_data);

    let version = cursor.read_u32::<LittleEndian>()?;
    let addr = cursor.read_u128::<LittleEndian>()?;
    let sa_family = cursor.read_u16::<LittleEndian>()?;
    let sysid = cursor.read_u16::<LittleEndian>()?;
    let id = cursor.read_u32::<LittleEndian>()?;

    Ok(ExporterInfo {
        header,
        version,
        address: {
            if sa_family == AF_INET {
                IpAddr::from(Ipv4Addr::from((addr >> 64) as u32))
            } else if sa_family == AF_INET6 {
                IpAddr::from(Ipv6Addr::from(addr))
            } else {
                return Err(NfdumpError::UnexpectedSAInExporter);
            }
        },
        sa_family,
        sysid,
        id,
    })
}

pub fn read_samplerv0_record(
    header: NfFileRecordHeader,
    record_data: Vec<u8>,
) -> Result<SamplerV0Record, NfdumpError> {
    let mut cursor = std::io::Cursor::new(&record_data);

    Ok(SamplerV0Record {
        header,
        id: cursor.read_i32::<LittleEndian>()?,
        interval: cursor.read_u32::<LittleEndian>()?,
        algorithm: cursor.read_u16::<LittleEndian>()?,
        exporter_sysid: cursor.read_u16::<LittleEndian>()?,
    })
}

// dead temporarily until implemented again
#[allow(dead_code)]
pub fn read_exporter_stats_record(
    header: NfFileRecordHeader,
    record_data: Vec<u8>,
) -> Result<ExporterStatsRecord, NfdumpError> {
    let mut cursor = std::io::Cursor::new(&record_data);

    let stat_count = cursor.read_u32::<LittleEndian>()?;
    let mut stat: Vec<ExporterStat> = Vec::new();
    let mut cnt = 0;
    while cnt < stat_count {
        stat.push(ExporterStat {
            sysid: cursor.read_u32::<LittleEndian>()?,
            sequence_failure: cursor.read_u32::<LittleEndian>()?,
            packets: cursor.read_u64::<LittleEndian>()?,
            flows: cursor.read_u64::<LittleEndian>()?,
        });
        cnt += 1;
    }

    Ok(ExporterStatsRecord {
        header,
        stat_count,
        stat,
    })
}
