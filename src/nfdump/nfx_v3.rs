// dead code is allowed in this file as it is verified to not have anything dead
// except some of the extensions which are not implemented yet
#![allow(dead_code)]

use crate::nfdump::error::NfdumpError;
use crate::nfdump::record::NfFileRecordHeader;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

// flowprep change: MAC addresses are stored as raw 6-byte arrays rather than
// eui48::MacAddress, dropping the eui48 dependency (flowprep never reads them).

const EXT_NULL: u16 = 0x0;
const EXT_GENERIC_FLOW: u16 = 0x1;
const EXT_IPV4_FLOW: u16 = 0x2;
const EXT_IPV6_FLOW: u16 = 0x3;
const EXT_FLOW_MISC: u16 = 0x4;
const EXT_CNT_FLOW: u16 = 0x5;
const EXT_VLAN_FLOW: u16 = 0x6;
const EXT_AS_ROUTING: u16 = 0x7;
const EXT_BGP_NEXT_HOP_V4: u16 = 0x8;
const EXT_BGP_NEXT_HOP_V6: u16 = 0x9;
const EXT_IP_NEXT_HOP_V4: u16 = 0xa;
const EXT_IP_NEXT_HOP_V6: u16 = 0xb;
const EXT_IP_RECEIVED_V4: u16 = 0xc;
const EXT_IP_RECEIVED_V6: u16 = 0xd;
const EXT_SAMPLER_INFO: u16 = 0x12;
const EXT_IN_PAYLOAD: u16 = 0x1d;
const EXT_NSEL_X_LATE_IPV4: u16 = 0x14;
const EXT_NSEL_X_LATE_IPV6: u16 = 0x15;
const EXT_NSEL_X_LATE_PORT: u16 = 0x16;

const EXT_MAC_ADDR: u16 = 0xf;
const EXT_LAYER2: u16 = 0x26;
const EXT_MPLS: u16 = 0xe;
const EXT_TUN_V4: u16 = 0x1f;
const EXT_TUN_V6: u16 = 0x20;

#[derive(Debug)]
pub struct RecordHeaderV3 {
    pub header: NfFileRecordHeader,
    pub num_elements: u16,
    pub engine_type: u8,
    pub engine_id: u8,
    pub exporter_id: u16,
    pub flags: u8,
    pub nf_version: u8,
}

#[derive(Debug)]
pub struct ExGenericFlow {
    pub msec_first: u64,
    pub msec_last: u64,
    pub msec_received: u64,
    pub in_packets: u64,
    pub in_bytes: u64,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub tcp_flags: u8,
    pub fwd_status: u8,
    pub src_tos: u8,
}

#[derive(Debug)]
pub struct ExIpv4Flow {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

#[derive(Debug)]
pub struct ExIpv6Flow {
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
}

#[derive(Debug)]
pub struct ExFlowMisc {
    pub input: u32,
    pub output: u32,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub dir: u8,
    pub dst_tos: u8,
    pub bi_flow_dir: u8,
    pub flow_end_reason: u8,
    pub rev_tcp_flags: u8,
    pub fill: u8,
}

#[derive(Debug)]
pub struct ExCntFlow {
    pub flows: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
}

#[derive(Debug)]
pub struct ExVlan {
    pub src_vlan: u32,
    pub dst_vlan: u32,
}

#[derive(Debug)]
pub struct ExAsRouting {
    pub src_as: u32,
    pub dst_as: u32,
}

#[derive(Debug)]
pub struct ExSamplerInfo {
    pub selector_id: u64,
    pub sysid: u16,
    pub align: u16,
}

#[derive(Debug)]
pub struct ExNselXLatePort {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug)]
pub struct ExBgpNextHopIpv4 {
    pub ip: Ipv4Addr,
}

#[derive(Debug)]
pub struct ExBgpNextHopIpv6 {
    pub ip: Ipv6Addr,
}

#[derive(Debug)]
pub struct ExIpNextHopIpv4 {
    pub ip: Ipv4Addr,
}

#[derive(Debug)]
pub struct ExIpNextHopIpv6 {
    pub ip: Ipv6Addr,
}

#[derive(Debug)]
pub struct ExIpReceivedIpv4 {
    pub ip: Ipv4Addr,
}

#[derive(Debug)]
pub struct ExIpReceivedIpv6 {
    pub ip: Ipv6Addr,
}

pub type ExInPayload = Vec<u8>;

pub type ExNselXLateIpv4 = [u32; 10];

pub type ExNselXLateIpv6 = [u128; 10];

#[derive(Debug)]
pub struct ExMacAddress {
    pub in_src_mac: [u8; 6],
    pub out_dst_mac: [u8; 6],
    pub in_dst_mac: [u8; 6],
    pub out_src_mac: [u8; 6],
}

#[derive(Debug)]
pub struct ExLayer2 {
    pub vlan_id: u16,
    pub customer_vlan_id: u16,
    pub post_vlan_id: u16,
    pub post_customer_vlan_id: u16,
    pub ingress: u32,
    pub egress: u32,
    pub vx_lan: u64,
    pub ether_type: u16,
    pub ip_version: u8,
    pub fill: u8,
}

#[derive(Debug)]
pub struct ExMPLS {
    pub mpls_label_1: u32,
    pub mpls_label_2: u32,
    pub mpls_label_3: u32,
    pub mpls_label_4: u32,
    pub mpls_label_5: u32,
    pub mpls_label_6: u32,
    pub mpls_label_7: u32,
    pub mpls_label_8: u32,
    pub mpls_label_9: u32,
    pub mpls_label_10: u32,
}

#[derive(Debug)]
pub struct ExTunIpv4 {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub proto: u8,
}

#[derive(Debug)]
pub struct ExTunIpv6 {
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    pub proto: u8,
}

/// `Record` represents a flow record.
#[derive(Debug)]
pub struct RecordV3 {
    pub head: RecordHeaderV3,
    pub generic_flow: Option<ExGenericFlow>,
    pub ipv4_flow: Option<ExIpv4Flow>,
    pub ipv6_flow: Option<ExIpv6Flow>,
    pub flow_misc: Option<ExFlowMisc>,
    pub cnt_flow: Option<ExCntFlow>,
    pub vlan: Option<ExVlan>,
    pub as_routing: Option<ExAsRouting>,
    pub sampler_info: Option<ExSamplerInfo>,
    pub nsel_xlate_port: Option<ExNselXLatePort>,
    pub bgp_next_hop_ipv4: Option<ExBgpNextHopIpv4>,
    pub bgp_next_hop_ipv6: Option<ExBgpNextHopIpv6>,
    pub ip_next_hop_ipv4: Option<ExIpNextHopIpv4>,
    pub ip_next_hop_ipv6: Option<ExIpNextHopIpv6>,
    pub ip_received_ipv4: Option<ExIpReceivedIpv4>,
    pub ip_received_ipv6: Option<ExIpReceivedIpv6>,
    pub in_payload: Option<ExInPayload>,
    pub mac_address: Option<ExMacAddress>,
    pub layer2: Option<ExLayer2>,
    pub mpls: Option<ExMPLS>,
    pub tun_ipv4: Option<ExTunIpv4>,
    pub tun_ipv6: Option<ExTunIpv6>,
}

impl RecordV3 {
    pub fn new(header: NfFileRecordHeader, data: Vec<u8>) -> Result<RecordV3, NfdumpError> {
        let mut cursor = Cursor::new(&data);

        let v3_header = RecordHeaderV3 {
            header,
            num_elements: cursor.read_u16::<LittleEndian>()?,
            engine_type: cursor.read_u8()?,
            engine_id: cursor.read_u8()?,
            exporter_id: cursor.read_u16::<LittleEndian>()?,
            flags: cursor.read_u8()?,
            nf_version: cursor.read_u8()?,
        };

        let mut record = RecordV3 {
            head: v3_header,
            generic_flow: None,
            ipv4_flow: None,
            ipv6_flow: None,
            flow_misc: None,
            cnt_flow: None,
            vlan: None,
            as_routing: None,
            sampler_info: None,
            nsel_xlate_port: None,
            bgp_next_hop_ipv4: None,
            bgp_next_hop_ipv6: None,
            ip_next_hop_ipv4: None,
            ip_next_hop_ipv6: None,
            ip_received_ipv4: None,
            ip_received_ipv6: None,
            in_payload: None,
            mac_address: None,
            layer2: None,
            mpls: None,
            tun_ipv4: None,
            tun_ipv6: None,
        };

        let mut cnt = 0;
        while cnt < record.head.num_elements {
            cnt += 1;

            // Element header
            let ext = cursor.read_u16::<LittleEndian>()?;
            let size = cursor.read_u16::<LittleEndian>()? as usize;

            // Read extension data into a separate buffer
            let mut ext_data = vec![0; size - 4];
            cursor.read_exact(&mut ext_data)?;
            let mut ext_cursor = Cursor::new(&ext_data);

            match ext {
                EXT_GENERIC_FLOW => {
                    record.generic_flow = Some(ExGenericFlow {
                        msec_first: ext_cursor.read_u64::<LittleEndian>()?,
                        msec_last: ext_cursor.read_u64::<LittleEndian>()?,
                        msec_received: ext_cursor.read_u64::<LittleEndian>()?,
                        in_packets: ext_cursor.read_u64::<LittleEndian>()?,
                        in_bytes: ext_cursor.read_u64::<LittleEndian>()?,
                        src_port: ext_cursor.read_u16::<LittleEndian>()?,
                        dst_port: ext_cursor.read_u16::<LittleEndian>()?,
                        proto: ext_cursor.read_u8()?,
                        tcp_flags: ext_cursor.read_u8()?,
                        fwd_status: ext_cursor.read_u8()?,
                        src_tos: ext_cursor.read_u8()?,
                    });
                }
                EXT_IPV4_FLOW => {
                    record.ipv4_flow = Some(ExIpv4Flow {
                        src_addr: Ipv4Addr::from(ext_cursor.read_u32::<LittleEndian>()?),
                        dst_addr: Ipv4Addr::from(ext_cursor.read_u32::<LittleEndian>()?),
                    });
                }
                EXT_IPV6_FLOW => {
                    record.ipv6_flow = Some(ExIpv6Flow {
                        src_addr: Ipv6Addr::from(ext_cursor.read_u128::<LittleEndian>()?),
                        dst_addr: Ipv6Addr::from(ext_cursor.read_u128::<LittleEndian>()?),
                    });
                }
                EXT_FLOW_MISC => {
                    record.flow_misc = Some(ExFlowMisc {
                        input: ext_cursor.read_u32::<LittleEndian>()?,
                        output: ext_cursor.read_u32::<LittleEndian>()?,
                        src_mask: ext_cursor.read_u8()?,
                        dst_mask: ext_cursor.read_u8()?,
                        dir: ext_cursor.read_u8()?,
                        dst_tos: ext_cursor.read_u8()?,
                        bi_flow_dir: ext_cursor.read_u8()?,
                        flow_end_reason: ext_cursor.read_u8()?,
                        rev_tcp_flags: ext_cursor.read_u8()?,
                        fill: ext_cursor.read_u8()?,
                    });
                }
                EXT_CNT_FLOW => {
                    record.cnt_flow = Some(ExCntFlow {
                        flows: ext_cursor.read_u64::<LittleEndian>()?,
                        out_packets: ext_cursor.read_u64::<LittleEndian>()?,
                        out_bytes: ext_cursor.read_u64::<LittleEndian>()?,
                    });
                }
                EXT_VLAN_FLOW => {
                    record.vlan = Some(ExVlan {
                        src_vlan: ext_cursor.read_u32::<LittleEndian>()?,
                        dst_vlan: ext_cursor.read_u32::<LittleEndian>()?,
                    });
                }
                EXT_AS_ROUTING => {
                    record.as_routing = Some(ExAsRouting {
                        src_as: ext_cursor.read_u32::<LittleEndian>()?,
                        dst_as: ext_cursor.read_u32::<LittleEndian>()?,
                    });
                }
                EXT_SAMPLER_INFO => {
                    record.sampler_info = Some(ExSamplerInfo {
                        selector_id: ext_cursor.read_u64::<LittleEndian>()?,
                        sysid: ext_cursor.read_u16::<LittleEndian>()?,
                        align: ext_cursor.read_u16::<LittleEndian>()?,
                    });
                }
                EXT_NSEL_X_LATE_PORT => {
                    record.nsel_xlate_port = Some(ExNselXLatePort {
                        src_port: ext_cursor.read_u16::<LittleEndian>()?,
                        dst_port: ext_cursor.read_u16::<LittleEndian>()?,
                    });
                }
                EXT_BGP_NEXT_HOP_V4 => {
                    record.bgp_next_hop_ipv4 = Some(ExBgpNextHopIpv4 {
                        ip: Ipv4Addr::from(ext_cursor.read_u32::<LittleEndian>()?),
                    });
                }
                EXT_BGP_NEXT_HOP_V6 => {
                    record.bgp_next_hop_ipv6 = Some(ExBgpNextHopIpv6 {
                        ip: Ipv6Addr::from(ext_cursor.read_u128::<LittleEndian>()?),
                    });
                }
                EXT_IP_NEXT_HOP_V4 => {
                    record.ip_next_hop_ipv4 = Some(ExIpNextHopIpv4 {
                        ip: Ipv4Addr::from(ext_cursor.read_u32::<LittleEndian>()?),
                    });
                }
                EXT_IP_NEXT_HOP_V6 => {
                    record.ip_next_hop_ipv6 = Some(ExIpNextHopIpv6 {
                        ip: Ipv6Addr::from(ext_cursor.read_u128::<LittleEndian>()?),
                    });
                }
                EXT_IP_RECEIVED_V4 => {
                    record.ip_received_ipv4 = Some(ExIpReceivedIpv4 {
                        ip: Ipv4Addr::from(ext_cursor.read_u32::<LittleEndian>()?),
                    });
                }
                EXT_IP_RECEIVED_V6 => {
                    record.ip_received_ipv6 = Some(ExIpReceivedIpv6 {
                        ip: Ipv6Addr::from(ext_cursor.read_u128::<LittleEndian>()?),
                    });
                }
                EXT_IN_PAYLOAD => {
                    let mut payload = vec![0; record.head.header.size as usize - 4];
                    ext_cursor.read_exact(&mut payload)?;
                    record.in_payload = Some(payload);
                }
                EXT_MAC_ADDR => {
                    record.mac_address = Some(ExMacAddress {
                        in_src_mac: _mac_from_u64(ext_cursor.read_u64::<LittleEndian>()?),
                        out_dst_mac: _mac_from_u64(ext_cursor.read_u64::<LittleEndian>()?),
                        in_dst_mac: _mac_from_u64(ext_cursor.read_u64::<LittleEndian>()?),
                        out_src_mac: _mac_from_u64(ext_cursor.read_u64::<LittleEndian>()?),
                    });
                }
                EXT_LAYER2 => {
                    record.layer2 = Some(ExLayer2 {
                        vlan_id: ext_cursor.read_u16::<LittleEndian>()?,
                        customer_vlan_id: ext_cursor.read_u16::<LittleEndian>()?,
                        post_vlan_id: ext_cursor.read_u16::<LittleEndian>()?,
                        post_customer_vlan_id: ext_cursor.read_u16::<LittleEndian>()?,
                        ingress: ext_cursor.read_u32::<LittleEndian>()?,
                        egress: ext_cursor.read_u32::<LittleEndian>()?,
                        vx_lan: ext_cursor.read_u64::<LittleEndian>()?,
                        ether_type: ext_cursor.read_u16::<LittleEndian>()?,
                        ip_version: ext_cursor.read_u8()?,
                        fill: ext_cursor.read_u8()?,
                    });
                }
                EXT_MPLS => {
                    record.mpls = Some(ExMPLS {
                        mpls_label_1: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_2: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_3: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_4: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_5: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_6: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_7: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_8: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_9: ext_cursor.read_u32::<LittleEndian>()?,
                        mpls_label_10: ext_cursor.read_u32::<LittleEndian>()?,
                    });
                }
                EXT_TUN_V4 => {
                    record.tun_ipv4 = Some(ExTunIpv4 {
                        src_addr: Ipv4Addr::from(ext_cursor.read_u32::<LittleEndian>()?),
                        dst_addr: Ipv4Addr::from(ext_cursor.read_u32::<LittleEndian>()?),
                        proto: ext_cursor.read_u8()?,
                    });
                }
                EXT_TUN_V6 => {
                    record.tun_ipv6 = Some(ExTunIpv6 {
                        src_addr: Ipv6Addr::from(ext_cursor.read_u128::<LittleEndian>()?),
                        dst_addr: Ipv6Addr::from(ext_cursor.read_u128::<LittleEndian>()?),
                        proto: ext_cursor.read_u8()?,
                    });
                }
                _ => {}
            }
        }

        return Ok(record);
    }
}

fn _mac_from_u64(value: u64) -> [u8; 6] {
    [
        (value >> 40 & 0xFF) as u8,
        (value >> 32 & 0xFF) as u8,
        (value >> 24 & 0xFF) as u8,
        (value >> 16 & 0xFF) as u8,
        (value >> 8 & 0xFF) as u8,
        (value & 0xFF) as u8,
    ]
}
