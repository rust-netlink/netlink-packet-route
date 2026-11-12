// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, parse_u32, parse_u8, DecodeError, DefaultNla, Emitable,
    EncodeError, Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};

const IFLA_BRIDGE_CFM_MEP_CREATE_INFO: u16 = 9;
const IFLA_BRIDGE_CFM_MEP_CONFIG_INFO: u16 = 10;
const IFLA_BRIDGE_CFM_CC_CONFIG_INFO: u16 = 11;
const IFLA_BRIDGE_CFM_CC_RDI_INFO: u16 = 12;
const IFLA_BRIDGE_CFM_CC_CCM_TX_INFO: u16 = 13;
const IFLA_BRIDGE_CFM_CC_PEER_MEP_INFO: u16 = 14;
const IFLA_BRIDGE_CFM_MEP_STATUS_INFO: u16 = 15;
const IFLA_BRIDGE_CFM_CC_PEER_STATUS_INFO: u16 = 16;

use super::bridge::{append_nla_bytes, append_nla_u32, append_nla_u8};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmMepCreate {
    pub instance: u32,
    pub domain: u32,
    pub direction: u32,
    pub ifindex: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmMepConfig {
    pub instance: u32,
    pub unicast_mac: [u8; 6],
    pub mdlevel: u32,
    pub mepid: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmCcConfig {
    pub instance: u32,
    pub enable: u32,
    pub exp_interval: u32,
    pub exp_maid: [u8; 48],
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmCcRdi {
    pub instance: u32,
    pub rdi: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmCcCcmTx {
    pub instance: u32,
    pub dmac: [u8; 6],
    pub seq_no_update: u32,
    pub period: u32,
    pub if_tlv: u32,
    pub if_tlv_value: u8,
    pub port_tlv: u32,
    pub port_tlv_value: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmCcPeerMep {
    pub instance: u32,
    pub mepid: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmMepStatus {
    pub instance: u32,
    pub opcode_unexp_seen: u32,
    pub version_unexp_seen: u32,
    pub rx_level_low_seen: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeCfmCcPeerStatus {
    pub instance: u32,
    pub peer_mepid: u32,
    pub ccm_defect: u32,
    pub rdi: u32,
    pub port_tlv_value: u8,
    pub if_tlv_value: u8,
    pub seen: u32,
    pub tlv_seen: u32,
    pub seq_unexp_seen: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum BridgeCfm {
    MepCreate(BridgeCfmMepCreate),
    MepConfig(BridgeCfmMepConfig),
    CcConfig(BridgeCfmCcConfig),
    CcRdi(BridgeCfmCcRdi),
    CcCcmTx(BridgeCfmCcCcmTx),
    CcPeerMep(BridgeCfmCcPeerMep),
    MepStatus(BridgeCfmMepStatus),
    CcPeerStatus(BridgeCfmCcPeerStatus),
    Other(DefaultNla),
}

impl Nla for BridgeCfm {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::MepCreate(v) => v.emit(out),
            Self::MepConfig(v) => v.emit(out),
            Self::CcConfig(v) => v.emit(out),
            Self::CcRdi(v) => v.emit(out),
            Self::CcCcmTx(v) => v.emit(out),
            Self::CcPeerMep(v) => v.emit(out),
            Self::MepStatus(v) => v.emit(out),
            Self::CcPeerStatus(v) => v.emit(out),
            Self::Other(nla) => {
                append_bytes(out, nla.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::MepCreate(_) => {
                IFLA_BRIDGE_CFM_MEP_CREATE_INFO | NLA_F_NESTED
            }
            Self::MepConfig(_) => {
                IFLA_BRIDGE_CFM_MEP_CONFIG_INFO | NLA_F_NESTED
            }
            Self::CcConfig(_) => IFLA_BRIDGE_CFM_CC_CONFIG_INFO | NLA_F_NESTED,
            Self::CcRdi(_) => IFLA_BRIDGE_CFM_CC_RDI_INFO | NLA_F_NESTED,
            Self::CcCcmTx(_) => IFLA_BRIDGE_CFM_CC_CCM_TX_INFO | NLA_F_NESTED,
            Self::CcPeerMep(_) => {
                IFLA_BRIDGE_CFM_CC_PEER_MEP_INFO | NLA_F_NESTED
            }
            Self::MepStatus(_) => {
                IFLA_BRIDGE_CFM_MEP_STATUS_INFO | NLA_F_NESTED
            }
            Self::CcPeerStatus(_) => {
                IFLA_BRIDGE_CFM_CC_PEER_STATUS_INFO | NLA_F_NESTED
            }
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for BridgeCfm {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            IFLA_BRIDGE_CFM_MEP_CREATE_INFO => {
                Self::MepCreate(BridgeCfmMepCreate::parse(buf)?)
            }
            IFLA_BRIDGE_CFM_MEP_CONFIG_INFO => {
                Self::MepConfig(BridgeCfmMepConfig::parse(buf)?)
            }
            IFLA_BRIDGE_CFM_CC_CONFIG_INFO => {
                Self::CcConfig(BridgeCfmCcConfig::parse(buf)?)
            }
            IFLA_BRIDGE_CFM_CC_RDI_INFO => {
                Self::CcRdi(BridgeCfmCcRdi::parse(buf)?)
            }
            IFLA_BRIDGE_CFM_CC_CCM_TX_INFO => {
                Self::CcCcmTx(BridgeCfmCcCcmTx::parse(buf)?)
            }
            IFLA_BRIDGE_CFM_CC_PEER_MEP_INFO => {
                Self::CcPeerMep(BridgeCfmCcPeerMep::parse(buf)?)
            }
            IFLA_BRIDGE_CFM_MEP_STATUS_INFO => {
                Self::MepStatus(BridgeCfmMepStatus::parse(buf)?)
            }
            IFLA_BRIDGE_CFM_CC_PEER_STATUS_INFO => {
                Self::CcPeerStatus(BridgeCfmCcPeerStatus::parse(buf)?)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

impl BridgeCfmMepCreate {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let (mut instance, mut domain, mut direction, mut ifindex) =
            (None, None, None, None);
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => domain = Some(parse_u32(nla.value())?),
                3 => direction = Some(parse_u32(nla.value())?),
                4 => ifindex = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            domain: domain
                .ok_or_else(|| DecodeError::from("missing domain"))?,
            direction: direction
                .ok_or_else(|| DecodeError::from("missing direction"))?,
            ifindex: ifindex
                .ok_or_else(|| DecodeError::from("missing ifindex"))?,
        })
    }
}

impl Emitable for BridgeCfmMepCreate {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_u32(out, 2, self.domain);
        append_nla_u32(out, 3, self.direction);
        append_nla_u32(out, 4, self.ifindex);
        Ok(())
    }
}

impl BridgeCfmMepConfig {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut instance = None;
        let mut unicast_mac = None;
        let mut mdlevel = None;
        let mut mepid = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => {
                    let value = nla.value();
                    if value.len() < 6 {
                        return Err(DecodeError::from("short unicast mac"));
                    }
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&value[..6]);
                    unicast_mac = Some(mac);
                }
                3 => mdlevel = Some(parse_u32(nla.value())?),
                4 => mepid = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            unicast_mac: unicast_mac
                .ok_or_else(|| DecodeError::from("missing unicast mac"))?,
            mdlevel: mdlevel
                .ok_or_else(|| DecodeError::from("missing mdlevel"))?,
            mepid: mepid.ok_or_else(|| DecodeError::from("missing mepid"))?,
        })
    }
}

impl Emitable for BridgeCfmMepConfig {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_bytes(out, 2, &self.unicast_mac);
        append_nla_u32(out, 3, self.mdlevel);
        append_nla_u32(out, 4, self.mepid);
        Ok(())
    }
}

impl BridgeCfmCcConfig {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut instance = None;
        let mut enable = None;
        let mut exp_interval = None;
        let mut exp_maid = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => enable = Some(parse_u32(nla.value())?),
                3 => exp_interval = Some(parse_u32(nla.value())?),
                4 => {
                    let value = nla.value();
                    if value.len() < 48 {
                        return Err(DecodeError::from("short exp maid"));
                    }
                    let mut maid = [0u8; 48];
                    maid.copy_from_slice(&value[..48]);
                    exp_maid = Some(maid);
                }
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            enable: enable
                .ok_or_else(|| DecodeError::from("missing enable"))?,
            exp_interval: exp_interval
                .ok_or_else(|| DecodeError::from("missing exp interval"))?,
            exp_maid: exp_maid
                .ok_or_else(|| DecodeError::from("missing exp maid"))?,
        })
    }
}

impl Emitable for BridgeCfmCcConfig {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_u32(out, 2, self.enable);
        append_nla_u32(out, 3, self.exp_interval);
        append_nla_bytes(out, 4, &self.exp_maid);
        Ok(())
    }
}

impl BridgeCfmCcRdi {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut instance = None;
        let mut rdi = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => rdi = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            rdi: rdi.ok_or_else(|| DecodeError::from("missing rdi"))?,
        })
    }
}

impl Emitable for BridgeCfmCcRdi {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_u32(out, 2, self.rdi);
        Ok(())
    }
}

impl BridgeCfmCcCcmTx {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut instance = None;
        let mut dmac = None;
        let mut seq_no_update = None;
        let mut period = None;
        let mut if_tlv = None;
        let mut if_tlv_value = None;
        let mut port_tlv = None;
        let mut port_tlv_value = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => {
                    let value = nla.value();
                    if value.len() < 6 {
                        return Err(DecodeError::from("short dmac"));
                    }
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&value[..6]);
                    dmac = Some(mac);
                }
                3 => seq_no_update = Some(parse_u32(nla.value())?),
                4 => period = Some(parse_u32(nla.value())?),
                5 => if_tlv = Some(parse_u32(nla.value())?),
                6 => if_tlv_value = Some(parse_u8(nla.value())?),
                7 => port_tlv = Some(parse_u32(nla.value())?),
                8 => port_tlv_value = Some(parse_u8(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            dmac: dmac.ok_or_else(|| DecodeError::from("missing dmac"))?,
            seq_no_update: seq_no_update
                .ok_or_else(|| DecodeError::from("missing seq no update"))?,
            period: period
                .ok_or_else(|| DecodeError::from("missing period"))?,
            if_tlv: if_tlv
                .ok_or_else(|| DecodeError::from("missing if tlv"))?,
            if_tlv_value: if_tlv_value
                .ok_or_else(|| DecodeError::from("missing if tlv value"))?,
            port_tlv: port_tlv
                .ok_or_else(|| DecodeError::from("missing port tlv"))?,
            port_tlv_value: port_tlv_value
                .ok_or_else(|| DecodeError::from("missing port tlv value"))?,
        })
    }
}

impl Emitable for BridgeCfmCcCcmTx {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_bytes(out, 2, &self.dmac);
        append_nla_u32(out, 3, self.seq_no_update);
        append_nla_u32(out, 4, self.period);
        append_nla_u32(out, 5, self.if_tlv);
        append_nla_u8(out, 6, self.if_tlv_value);
        append_nla_u32(out, 7, self.port_tlv);
        append_nla_u8(out, 8, self.port_tlv_value);
        Ok(())
    }
}

impl BridgeCfmCcPeerMep {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut instance = None;
        let mut mepid = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => mepid = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            mepid: mepid.ok_or_else(|| DecodeError::from("missing mepid"))?,
        })
    }
}

impl Emitable for BridgeCfmCcPeerMep {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_u32(out, 2, self.mepid);
        Ok(())
    }
}

impl BridgeCfmMepStatus {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let (mut instance, mut opcode, mut version, mut rx_level) =
            (None, None, None, None);
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => opcode = Some(parse_u32(nla.value())?),
                3 => version = Some(parse_u32(nla.value())?),
                4 => rx_level = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            opcode_unexp_seen: opcode
                .ok_or_else(|| DecodeError::from("missing opcode"))?,
            version_unexp_seen: version
                .ok_or_else(|| DecodeError::from("missing version"))?,
            rx_level_low_seen: rx_level
                .ok_or_else(|| DecodeError::from("missing rx level"))?,
        })
    }
}

impl Emitable for BridgeCfmMepStatus {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_u32(out, 2, self.opcode_unexp_seen);
        append_nla_u32(out, 3, self.version_unexp_seen);
        append_nla_u32(out, 4, self.rx_level_low_seen);
        Ok(())
    }
}

impl BridgeCfmCcPeerStatus {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut instance = None;
        let mut peer_mepid = None;
        let mut ccm_defect = None;
        let mut rdi = None;
        let mut port_tlv_value = None;
        let mut if_tlv_value = None;
        let mut seen = None;
        let mut tlv_seen = None;
        let mut seq_unexp_seen = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => instance = Some(parse_u32(nla.value())?),
                2 => peer_mepid = Some(parse_u32(nla.value())?),
                3 => ccm_defect = Some(parse_u32(nla.value())?),
                4 => rdi = Some(parse_u32(nla.value())?),
                5 => port_tlv_value = Some(parse_u8(nla.value())?),
                6 => if_tlv_value = Some(parse_u8(nla.value())?),
                7 => seen = Some(parse_u32(nla.value())?),
                8 => tlv_seen = Some(parse_u32(nla.value())?),
                9 => seq_unexp_seen = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            instance: instance
                .ok_or_else(|| DecodeError::from("missing instance"))?,
            peer_mepid: peer_mepid
                .ok_or_else(|| DecodeError::from("missing peer mepid"))?,
            ccm_defect: ccm_defect
                .ok_or_else(|| DecodeError::from("missing ccm defect"))?,
            rdi: rdi.ok_or_else(|| DecodeError::from("missing rdi"))?,
            port_tlv_value: port_tlv_value
                .ok_or_else(|| DecodeError::from("missing port tlv value"))?,
            if_tlv_value: if_tlv_value
                .ok_or_else(|| DecodeError::from("missing if tlv value"))?,
            seen: seen.ok_or_else(|| DecodeError::from("missing seen"))?,
            tlv_seen: tlv_seen
                .ok_or_else(|| DecodeError::from("missing tlv seen"))?,
            seq_unexp_seen: seq_unexp_seen
                .ok_or_else(|| DecodeError::from("missing seq unexp seen"))?,
        })
    }
}

impl Emitable for BridgeCfmCcPeerStatus {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.instance);
        append_nla_u32(out, 2, self.peer_mepid);
        append_nla_u32(out, 3, self.ccm_defect);
        append_nla_u32(out, 4, self.rdi);
        append_nla_u8(out, 5, self.port_tlv_value);
        append_nla_u8(out, 6, self.if_tlv_value);
        append_nla_u32(out, 7, self.seen);
        append_nla_u32(out, 8, self.tlv_seen);
        append_nla_u32(out, 9, self.seq_unexp_seen);
        Ok(())
    }
}
