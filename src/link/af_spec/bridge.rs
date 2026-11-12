// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u16, append_u32, append_u8, parse_u16, parse_u32,
    parse_u8, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::{bridge_cfm::BridgeCfm, bridge_mrp::BridgeMrp};
use crate::link::{bridge_vlan::BridgeVlanInfoFlags, BridgePortState};

const IFLA_BRIDGE_FLAGS: u16 = 0;
const IFLA_BRIDGE_MODE: u16 = 1;
const IFLA_BRIDGE_VLAN_INFO: u16 = 2;
const IFLA_BRIDGE_VLAN_TUNNEL_INFO: u16 = 3;
const IFLA_BRIDGE_MRP: u16 = 4;
const IFLA_BRIDGE_CFM: u16 = 5;
const IFLA_BRIDGE_MST: u16 = 6;
const IFLA_BRIDGE_MST_ENTRY: u16 = 1;
const IFLA_BRIDGE_MST_ENTRY_MSTI: u16 = 1;
const IFLA_BRIDGE_MST_ENTRY_STATE: u16 = 2;

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum AfSpecBridge {
    Flags(BridgeFlag),
    Mode(BridgeMode),
    VlanInfo(BridgeVlanInfo),
    VlanTunnelInfo(Vec<BridgeVlanTunnelInfo>),
    Mrp(Vec<BridgeMrp>),
    Cfm(Vec<BridgeCfm>),
    Mst(Vec<BridgeMstEntry>),
    Other(DefaultNla),
}

impl Nla for AfSpecBridge {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Flags(value) => append_u16(out, u16::from(*value)),
            Self::Mode(value) => append_u16(out, u16::from(*value)),
            Self::VlanInfo(info) => {
                append_bytes(out, <[u8; 4]>::from(info).as_slice())
            }
            Self::VlanTunnelInfo(s) => (s).emit(out)?,
            Self::Mrp(nlas) => (nlas).emit(out)?,
            Self::Cfm(nlas) => (nlas).emit(out)?,
            Self::Mst(entries) => (entries).emit(out)?,
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Flags(_) => IFLA_BRIDGE_FLAGS,
            Self::Mode(_) => IFLA_BRIDGE_MODE,
            Self::VlanInfo(_) => IFLA_BRIDGE_VLAN_INFO,
            Self::VlanTunnelInfo(_) => IFLA_BRIDGE_VLAN_TUNNEL_INFO,
            Self::Mrp(_) => IFLA_BRIDGE_MRP,
            Self::Cfm(_) => IFLA_BRIDGE_CFM | NLA_F_NESTED,
            Self::Mst(_) => IFLA_BRIDGE_MST | NLA_F_NESTED,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for AfSpecBridge {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BRIDGE_FLAGS => Self::Flags(
                parse_u16(payload)
                    .context("Invalid IFLA_BRIDGE_FLAGS value")?
                    .into(),
            ),
            IFLA_BRIDGE_MODE => Self::Mode(
                parse_u16(payload)
                    .context("Invalid IFLA_BRIDGE_MODE value")?
                    .into(),
            ),
            IFLA_BRIDGE_VLAN_INFO => Self::VlanInfo(
                BridgeVlanInfo::try_from(payload)
                    .context("Invalid IFLA_BRIDGE_VLAN_INFO value")?,
            ),
            IFLA_BRIDGE_VLAN_TUNNEL_INFO => {
                let mut nlas = Vec::new();
                for nla in buf.nlas().with_context(|| {
                    format!(
                        "Invalid IFLA_BRIDGE_VLAN_TUNNEL_INFO for {payload:?}"
                    )
                })? {
                    let parsed = BridgeVlanTunnelInfo::parse(&nla)?;
                    nlas.push(parsed);
                }
                Self::VlanTunnelInfo(nlas)
            }
            IFLA_BRIDGE_MRP => {
                let mut nlas = Vec::new();
                for nla in buf.nlas().with_context(|| {
                    format!("invalid IFLA_BRIDGE_MRP {payload:?}")
                })? {
                    nlas.push(BridgeMrp::parse(&nla)?);
                }
                Self::Mrp(nlas)
            }
            IFLA_BRIDGE_CFM => {
                let mut nlas = Vec::new();
                for nla in buf.nlas().with_context(|| {
                    format!("invalid IFLA_BRIDGE_CFM {payload:?}")
                })? {
                    nlas.push(BridgeCfm::parse(&nla)?);
                }
                Self::Cfm(nlas)
            }
            IFLA_BRIDGE_MST => {
                let mut entries = Vec::new();
                for nla in buf.nlas().with_context(|| {
                    format!("invalid IFLA_BRIDGE_MST {payload:?}")
                })? {
                    entries.push(BridgeMstEntry::parse(&nla)?);
                }
                Self::Mst(entries)
            }
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .with_context(|| format!("Unknown NLA type {kind}"))?,
            ),
        })
    }
}

/// A single MSTI entry (`IFLA_BRIDGE_MST_ENTRY`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct BridgeMstEntry {
    pub msti: u16,
    pub state: BridgePortState,
}

impl Nla for BridgeMstEntry {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u16(out, 6);
        append_u16(out, IFLA_BRIDGE_MST_ENTRY_MSTI);
        append_u16(out, self.msti);
        append_u16(out, 0);
        append_u16(out, 5);
        append_u16(out, IFLA_BRIDGE_MST_ENTRY_STATE);
        append_u8(out, self.state.into());
        out.extend_from_slice(&[0, 0, 0]);
        Ok(())
    }

    fn kind(&self) -> u16 {
        IFLA_BRIDGE_MST_ENTRY
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for BridgeMstEntry {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let mut msti = 0u16;
        let mut state = BridgePortState::Disabled;
        for nla in buf.nlas().with_context(|| {
            format!("invalid IFLA_BRIDGE_MST_ENTRY {payload:?}")
        })? {
            match nla.kind() {
                IFLA_BRIDGE_MST_ENTRY_MSTI => {
                    msti = parse_u16(nla.value()).with_context(|| {
                        "invalid IFLA_BRIDGE_MST_ENTRY_MSTI value"
                    })?;
                }
                IFLA_BRIDGE_MST_ENTRY_STATE => {
                    state = parse_u8(nla.value())
                        .with_context(|| {
                            "invalid IFLA_BRIDGE_MST_ENTRY_STATE value"
                        })?
                        .into();
                }
                _ => {}
            }
        }
        Ok(Self { msti, state })
    }
}

pub(super) fn append_nla_u16(out: &mut Vec<u8>, kind: u16, value: u16) {
    append_u16(out, 6);
    append_u16(out, kind);
    append_u16(out, value);
    out.extend_from_slice(&[0, 0]);
}

pub(super) fn append_nla_u32(out: &mut Vec<u8>, kind: u16, value: u32) {
    append_u16(out, 8);
    append_u16(out, kind);
    append_u32(out, value);
}

pub(super) fn append_nla_u8(out: &mut Vec<u8>, kind: u16, value: u8) {
    append_u16(out, 5);
    append_u16(out, kind);
    append_u8(out, value);
    out.extend_from_slice(&[0, 0, 0]);
}

pub(super) fn append_nla_bytes(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    append_u16(out, len as u16);
    append_u16(out, kind);
    out.extend_from_slice(value);
    out.extend_from_slice(&vec![0; (4 - len % 4) % 4]);
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct BridgeVlanInfo {
    pub flags: BridgeVlanInfoFlags,
    pub vid: u16,
}

impl BridgeVlanInfo {
    pub const LENGTH: usize = 4;

    pub const fn new(flags: BridgeVlanInfoFlags, vid: u16) -> Self {
        Self { flags, vid }
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct BridgeVlanInfoBuffer {
    flags: u16,
    vid: u16,
}

impl From<&BridgeVlanInfo> for [u8; 4] {
    fn from(d: &BridgeVlanInfo) -> Self {
        let mut ret = [0u8; 4];
        ret.copy_from_slice(
            BridgeVlanInfoBuffer {
                flags: d.flags.bits(),
                vid: d.vid,
            }
            .as_bytes(),
        );
        ret
    }
}

impl TryFrom<&[u8]> for BridgeVlanInfo {
    type Error = DecodeError;
    fn try_from(raw: &[u8]) -> Result<Self, DecodeError> {
        let buf = BridgeVlanInfoBuffer::ref_from_bytes(raw).map_err(|_| {
            DecodeError::from(format!(
                "Invalid IFLA_BRIDGE_VLAN_INFO value, expecting [u8;4], but \
                 got {raw:?}"
            ))
        })?;
        Ok(Self {
            flags: BridgeVlanInfoFlags::from_bits_retain(buf.flags),
            vid: buf.vid,
        })
    }
}

// kernel constant name is BRIDGE_FLAGS_MASTER
const BRIDGE_FLAGS_CONTROLLER: u16 = 1;
const BRIDGE_FLAGS_SELF: u16 = 2;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum BridgeFlag {
    /// Bridge command to/from controller
    Controller,
    /// Bridge command to/from lowerdev
    LowerDev,
    Other(u16),
}

impl From<u16> for BridgeFlag {
    fn from(d: u16) -> Self {
        match d {
            BRIDGE_FLAGS_CONTROLLER => Self::Controller,
            BRIDGE_FLAGS_SELF => Self::LowerDev,
            _ => Self::Other(d),
        }
    }
}

impl From<BridgeFlag> for u16 {
    fn from(v: BridgeFlag) -> u16 {
        match v {
            BridgeFlag::Controller => BRIDGE_FLAGS_CONTROLLER,
            BridgeFlag::LowerDev => BRIDGE_FLAGS_SELF,
            BridgeFlag::Other(d) => d,
        }
    }
}

impl std::fmt::Display for BridgeFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Controller => f.write_str("master"),
            Self::LowerDev => f.write_str("self"),
            Self::Other(d) => write!(f, "{d}"),
        }
    }
}

impl std::str::FromStr for BridgeFlag {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "master" => Ok(Self::Controller),
            "self" => Ok(Self::LowerDev),
            _ => s.parse::<u16>().map(Self::from).map_err(|_| {
                DecodeError::from(format!("unknown bridge flag: {s}"))
            }),
        }
    }
}

impl BridgeFlag {
    pub const LENGTH: usize = 2;
}

const BRIDGE_MODE_VEB: u16 = 0;
const BRIDGE_MODE_VEPA: u16 = 1;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum BridgeMode {
    /// Default loopback mode
    Veb,
    /// 802.1Qbg defined VEPA mode
    Vepa,
    Other(u16),
}

impl From<u16> for BridgeMode {
    fn from(d: u16) -> Self {
        match d {
            BRIDGE_MODE_VEB => Self::Veb,
            BRIDGE_MODE_VEPA => Self::Vepa,
            _ => Self::Other(d),
        }
    }
}

impl From<BridgeMode> for u16 {
    fn from(v: BridgeMode) -> u16 {
        match v {
            BridgeMode::Veb => BRIDGE_MODE_VEB,
            BridgeMode::Vepa => BRIDGE_MODE_VEPA,
            BridgeMode::Other(d) => d,
        }
    }
}

impl std::fmt::Display for BridgeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Veb => f.write_str("veb"),
            Self::Vepa => f.write_str("vepa"),
            Self::Other(d) => write!(f, "{d}"),
        }
    }
}

impl std::str::FromStr for BridgeMode {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "veb" => Ok(Self::Veb),
            "vepa" => Ok(Self::Vepa),
            _ => s.parse::<u16>().map(Self::from).map_err(|_| {
                DecodeError::from(format!("unknown bridge mode: {s}"))
            }),
        }
    }
}

impl BridgeMode {
    pub const LENGTH: usize = 2;
}

const IFLA_BRIDGE_VLAN_TUNNEL_ID: u16 = 1;
const IFLA_BRIDGE_VLAN_TUNNEL_VID: u16 = 2;
const IFLA_BRIDGE_VLAN_TUNNEL_FLAGS: u16 = 3;

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum BridgeVlanTunnelInfo {
    Id(u32),
    Vid(u16),
    Flags(BridgeVlanInfoFlags),
    Other(DefaultNla),
}

impl Nla for BridgeVlanTunnelInfo {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Id(v) => append_u32(out, *v),
            Self::Vid(v) => append_u16(out, *v),
            Self::Flags(value) => append_u16(out, value.bits()),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => IFLA_BRIDGE_VLAN_TUNNEL_ID,
            Self::Vid(_) => IFLA_BRIDGE_VLAN_TUNNEL_VID,
            Self::Flags(_) => IFLA_BRIDGE_VLAN_TUNNEL_FLAGS,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for BridgeVlanTunnelInfo {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BRIDGE_VLAN_TUNNEL_ID => {
                Self::Id(parse_u32(payload).with_context(|| {
                    format!("Invalid IFLA_BRIDGE_VLAN_TUNNEL_ID {payload:?}")
                })?)
            }
            IFLA_BRIDGE_VLAN_TUNNEL_VID => {
                Self::Vid(parse_u16(payload).with_context(|| {
                    format!("Invalid IFLA_BRIDGE_VLAN_TUNNEL_VID {payload:?}")
                })?)
            }
            IFLA_BRIDGE_VLAN_TUNNEL_FLAGS => {
                Self::Flags(BridgeVlanInfoFlags::from_bits_retain(
                    parse_u16(payload).with_context(|| {
                        format!(
                            "Invalid IFLA_BRIDGE_VLAN_TUNNEL_FLAGS {payload:?}"
                        )
                    })?,
                ))
            }
            _ => {
                Self::Other(DefaultNla::parse(buf).context("Unknown NLA type")?)
            }
        })
    }
}
