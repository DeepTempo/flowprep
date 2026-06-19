use crate::nfdump::error::NfdumpError;
use crate::nfdump::exporter::{ExporterInfo, SamplerV0Record};
use crate::nfdump::nffilev2::StatRecordV2;
use crate::nfdump::nfx::ExtensionMap;
use crate::nfdump::nfx_v3::RecordV3;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum RecordKind {
    ExtensionMap(ExtensionMap),
    ExporterInfo(ExporterInfo),
    SamplerV0(SamplerV0Record),
    Record(Record),
    RecordV3(RecordV3),
    Ident(Vec<u8>),
    Stat(StatRecordV2),
    Unimplemented,
    None,
}

#[derive(Debug, Copy, Clone)]
pub struct NfFileRecordHeader {
    pub rtype: u16,
    pub size: u16,
}

/// `Record` represents a flow record.
#[derive(Debug)]
pub struct Record {
    pub head: NfFileRecordHeader,
    pub flags: u16,
    pub ext_map: u16,
    pub msec_first: u16,
    pub msec_last: u16,
    pub first: u32,
    pub last: u32,
    pub fwd_status: u8,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub exporter_sysid: u16,
    pub bi_flow_dir: u8,
    pub flow_end_reason: u8,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub packets: u64,
    pub bytes: u64,
    pub input: Option<u32>,
    pub output: Option<u32>,
    pub src_as: Option<u32>,
    pub dst_as: Option<u32>,
}

pub fn new_record(
    header: NfFileRecordHeader,
    data: Vec<u8>,
    ext: &Vec<u16>,
) -> Result<Record, NfdumpError> {
    let mut cursor = Cursor::new(&data);
    let flags = cursor.read_u16::<LittleEndian>()?;

    Ok(Record {
        head: header,
        flags,
        ext_map: cursor.read_u16::<LittleEndian>()?,
        msec_first: cursor.read_u16::<LittleEndian>()?,
        msec_last: cursor.read_u16::<LittleEndian>()?,
        first: cursor.read_u32::<LittleEndian>()?,
        last: cursor.read_u32::<LittleEndian>()?,
        fwd_status: cursor.read_u8()?,
        tcp_flags: cursor.read_u8()?,
        prot: cursor.read_u8()?,
        tos: cursor.read_u8()?,
        src_port: cursor.read_u16::<LittleEndian>()?,
        dst_port: cursor.read_u16::<LittleEndian>()?,
        exporter_sysid: cursor.read_u16::<LittleEndian>()?,
        bi_flow_dir: cursor.read_u8()?,
        flow_end_reason: cursor.read_u8()?,
        src_addr: read_addr(&mut cursor, flags)?,
        dst_addr: read_addr(&mut cursor, flags)?,
        packets: read_pkt_or_byt(&mut cursor, flags)?,
        bytes: read_pkt_or_byt(&mut cursor, flags)?,
        input: read_ext(&mut cursor, ext, 4).ok(),
        output: read_ext(&mut cursor, ext, 4).ok(),
        src_as: read_ext(&mut cursor, ext, 6).ok(),
        dst_as: read_ext(&mut cursor, ext, 6).ok(),
        // TODO: Implement extensions
    })
}

fn read_addr(cur: &mut Cursor<&Vec<u8>>, flags: u16) -> Result<IpAddr, Error> {
    if flags & 0x01 == 0 {
        Ok(IpAddr::from(Ipv4Addr::from(
            cur.read_u32::<LittleEndian>()?,
        )))
    } else {
        Ok(IpAddr::from(Ipv6Addr::from(
            cur.read_u128::<LittleEndian>()?,
        )))
    }
}

fn read_pkt_or_byt(cur: &mut Cursor<&Vec<u8>>, flags: u16) -> Result<u64, Error> {
    if flags & 0x02 == 0 {
        Ok(cur.read_u32::<LittleEndian>()? as u64)
    } else {
        Ok(cur.read_u64::<LittleEndian>()?)
    }
}

fn read_ext(cur: &mut Cursor<&Vec<u8>>, emap: &Vec<u16>, ext: u16) -> Result<u32, Error> {
    if emap.contains(&ext) {
        Ok(cur.read_u16::<LittleEndian>()? as u32)
    } else if emap.contains(&(ext + 1)) {
        Ok(cur.read_u32::<LittleEndian>()?)
    } else {
        Err(Error::from(std::io::ErrorKind::Other))
    }
}
