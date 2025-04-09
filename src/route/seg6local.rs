// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator, NLA_F_NESTED},
    parsers::{parse_u32, parse_u64, parse_u8},
    traits::{Emitable, Parseable},
    DecodeError,
};

use crate::ip::{parse_ipv4_addr, parse_ipv6_addr};
use crate::route::Ipv6SrHdr;

const SEG6_LOCAL_ACTION: u16 = 1;
const SEG6_LOCAL_SRH: u16 = 2;
const SEG6_LOCAL_TABLE: u16 = 3;
const SEG6_LOCAL_NH4: u16 = 4;
const SEG6_LOCAL_NH6: u16 = 5;
const SEG6_LOCAL_IIF: u16 = 6;
const SEG6_LOCAL_OIF: u16 = 7;
// const SEG6_LOCAL_BPF: u16 = 8;  TODO
const SEG6_LOCAL_VRFTABLE: u16 = 9;
const SEG6_LOCAL_COUNTERS: u16 = 10;
const SEG6_LOCAL_FLAVORS: u16 = 11;

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6LOCAL`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteSeg6LocalIpTunnel {
    Action(Seg6LocalAction),
    Srh(Ipv6SrHdr),
    Table(u32),
    Nh4(Ipv4Addr),
    Nh6(Ipv6Addr),
    Iif(u32),
    Oif(u32),
    VrfTable(u32),
    Counters(Vec<Seg6LocalCounters>),
    Flavors(Vec<Seg6LocalFlavors>),
    Other(DefaultNla),
}

impl Nla for RouteSeg6LocalIpTunnel {
    fn value_len(&self) -> usize {
        match self {
            Self::Srh(v) => v.buffer_len(),
            Self::Action(_) => 4,
            Self::Table(_) => 4,
            Self::Nh4(_) => 4,
            Self::Nh6(_) => 16,
            Self::Iif(_) => 4,
            Self::Oif(_) => 4,
            Self::VrfTable(_) => 4,
            Self::Counters(nlas) => nlas.as_slice().buffer_len(),
            Self::Flavors(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Srh(_) => SEG6_LOCAL_SRH,
            Self::Action(_) => SEG6_LOCAL_ACTION,
            Self::Table(_) => SEG6_LOCAL_TABLE,
            Self::Nh4(_) => SEG6_LOCAL_NH4,
            Self::Nh6(_) => SEG6_LOCAL_NH6,
            Self::Iif(_) => SEG6_LOCAL_IIF,
            Self::Oif(_) => SEG6_LOCAL_OIF,
            Self::VrfTable(_) => SEG6_LOCAL_VRFTABLE,
            Self::Counters(_) => SEG6_LOCAL_COUNTERS | NLA_F_NESTED,
            Self::Flavors(_) => SEG6_LOCAL_FLAVORS | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Srh(v) => v.emit(buffer),
            Self::Action(v) => {
                let action: u32 = (*v).into();
                buffer[..4].copy_from_slice(action.to_ne_bytes().as_slice())
            }
            Self::Table(v) => {
                buffer[..4].copy_from_slice(v.to_ne_bytes().as_slice())
            }
            Self::Nh4(v) => buffer[..4].copy_from_slice(&v.octets()),
            Self::Nh6(v) => buffer[..16].copy_from_slice(&v.octets()),
            Self::Iif(v) => {
                buffer[..4].copy_from_slice(v.to_ne_bytes().as_slice())
            }
            Self::Oif(v) => {
                buffer[..4].copy_from_slice(v.to_ne_bytes().as_slice())
            }
            Self::VrfTable(v) => {
                buffer[..4].copy_from_slice(v.to_ne_bytes().as_slice())
            }
            Self::Counters(nlas) => nlas.as_slice().emit(buffer),
            Self::Flavors(nlas) => nlas.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for RouteSeg6LocalIpTunnel
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_LOCAL_SRH => Self::Srh(Ipv6SrHdr::parse(payload).context(
                format!("invalid SEG6_LOCAL_SRH value {:?}", payload),
            )?),
            SEG6_LOCAL_ACTION => Self::Action(
                parse_u32(payload)
                    .context("invalid SEG6_LOCAL_ACTION value")?
                    .into(),
            ),
            SEG6_LOCAL_TABLE => Self::Table(
                parse_u32(payload).context("invalid SEG6_LOCAL_TABLE value")?,
            ),
            SEG6_LOCAL_NH4 => Self::Nh4(parse_ipv4_addr(payload).context(
                format!("invalid SEG6_LOCAL_NH4 value {:?}", payload),
            )?),
            SEG6_LOCAL_NH6 => Self::Nh6(parse_ipv6_addr(payload).context(
                format!("invalid SEG6_LOCAL_NH6 value {:?}", payload),
            )?),
            SEG6_LOCAL_IIF => Self::Iif(
                parse_u32(payload).context("invalid SEG6_LOCAL_IIF value")?,
            ),
            SEG6_LOCAL_OIF => Self::Oif(
                parse_u32(payload).context("invalid SEG6_LOCAL_OIF value")?,
            ),
            SEG6_LOCAL_VRFTABLE => Self::VrfTable(
                parse_u32(payload)
                    .context("invalid SEG6_LOCAL_VRFTABLE value")?,
            ),
            SEG6_LOCAL_COUNTERS => {
                let mut v = Vec::new();
                let err = "failed to parse SEG6_LOCAL_COUNTERS";
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err)?;
                    let parsed = Seg6LocalCounters::parse(nla).context(err)?;
                    v.push(parsed);
                }
                Self::Counters(v)
            }
            SEG6_LOCAL_FLAVORS => {
                let mut v = Vec::new();
                let err = "failed to parse SEG6_LOCAL_FLAVORS";
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err)?;
                    let parsed = Seg6LocalFlavors::parse(nla).context(err)?;
                    v.push(parsed);
                }
                Self::Flavors(v)
            }
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}

// Seg6 action.
const SEG6_LOCAL_ACTION_UNSPEC: u32 = 0;
const SEG6_LOCAL_ACTION_END: u32 = 1;
const SEG6_LOCAL_ACTION_END_X: u32 = 2;
const SEG6_LOCAL_ACTION_END_T: u32 = 3;
const SEG6_LOCAL_ACTION_END_DX2: u32 = 4;
const SEG6_LOCAL_ACTION_END_DX6: u32 = 5;
const SEG6_LOCAL_ACTION_END_DX4: u32 = 6;
const SEG6_LOCAL_ACTION_END_DT6: u32 = 7;
const SEG6_LOCAL_ACTION_END_DT4: u32 = 8;
const SEG6_LOCAL_ACTION_END_B6: u32 = 9;
const SEG6_LOCAL_ACTION_END_B6_ENCAP: u32 = 10;
const SEG6_LOCAL_ACTION_END_BM: u32 = 11;
const SEG6_LOCAL_ACTION_END_S: u32 = 12;
const SEG6_LOCAL_ACTION_END_AS: u32 = 13;
const SEG6_LOCAL_ACTION_END_AM: u32 = 14;
const SEG6_LOCAL_ACTION_END_BPF: u32 = 15;
const SEG6_LOCAL_ACTION_END_DT46: u32 = 16;

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
#[non_exhaustive]
pub enum Seg6LocalAction {
    #[default]
    Unspec,
    End,
    EndX,
    EndT,
    EndDx2,
    EndDx6,
    EndDx4,
    EndDt6,
    EndDt4,
    EndB6,
    EndB6Encap,
    EndBm,
    EndS,
    EndAs,
    EndAm,
    EndBpf,
    EndDt46,
    Other(u32),
}

impl From<u32> for Seg6LocalAction {
    fn from(d: u32) -> Self {
        match d {
            SEG6_LOCAL_ACTION_UNSPEC => Self::Unspec,
            SEG6_LOCAL_ACTION_END => Self::End,
            SEG6_LOCAL_ACTION_END_X => Self::EndX,
            SEG6_LOCAL_ACTION_END_T => Self::EndT,
            SEG6_LOCAL_ACTION_END_DX2 => Self::EndDx2,
            SEG6_LOCAL_ACTION_END_DX6 => Self::EndDx6,
            SEG6_LOCAL_ACTION_END_DX4 => Self::EndDx4,
            SEG6_LOCAL_ACTION_END_DT6 => Self::EndDt6,
            SEG6_LOCAL_ACTION_END_DT4 => Self::EndDt4,
            SEG6_LOCAL_ACTION_END_B6 => Self::EndB6,
            SEG6_LOCAL_ACTION_END_B6_ENCAP => Self::EndB6Encap,
            SEG6_LOCAL_ACTION_END_BM => Self::EndBm,
            SEG6_LOCAL_ACTION_END_S => Self::EndS,
            SEG6_LOCAL_ACTION_END_AS => Self::EndAs,
            SEG6_LOCAL_ACTION_END_AM => Self::EndAm,
            SEG6_LOCAL_ACTION_END_BPF => Self::EndBpf,
            SEG6_LOCAL_ACTION_END_DT46 => Self::EndDt46,
            _ => Self::Other(d),
        }
    }
}

impl From<Seg6LocalAction> for u32 {
    fn from(v: Seg6LocalAction) -> u32 {
        match v {
            Seg6LocalAction::Unspec => SEG6_LOCAL_ACTION_UNSPEC,
            Seg6LocalAction::End => SEG6_LOCAL_ACTION_END,
            Seg6LocalAction::EndX => SEG6_LOCAL_ACTION_END_X,
            Seg6LocalAction::EndT => SEG6_LOCAL_ACTION_END_T,
            Seg6LocalAction::EndDx2 => SEG6_LOCAL_ACTION_END_DX2,
            Seg6LocalAction::EndDx6 => SEG6_LOCAL_ACTION_END_DX6,
            Seg6LocalAction::EndDx4 => SEG6_LOCAL_ACTION_END_DX4,
            Seg6LocalAction::EndDt6 => SEG6_LOCAL_ACTION_END_DT6,
            Seg6LocalAction::EndDt4 => SEG6_LOCAL_ACTION_END_DT4,
            Seg6LocalAction::EndB6 => SEG6_LOCAL_ACTION_END_B6,
            Seg6LocalAction::EndB6Encap => SEG6_LOCAL_ACTION_END_B6_ENCAP,
            Seg6LocalAction::EndBm => SEG6_LOCAL_ACTION_END_BM,
            Seg6LocalAction::EndS => SEG6_LOCAL_ACTION_END_S,
            Seg6LocalAction::EndAs => SEG6_LOCAL_ACTION_END_AS,
            Seg6LocalAction::EndAm => SEG6_LOCAL_ACTION_END_AM,
            Seg6LocalAction::EndBpf => SEG6_LOCAL_ACTION_END_BPF,
            Seg6LocalAction::EndDt46 => SEG6_LOCAL_ACTION_END_DT46,
            Seg6LocalAction::Other(d) => d,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Seg6LocalCounters {
    Unspec,
    Padding(usize),
    Packets(u64),
    Bytes(u64),
    Errors(u64),
    Other(DefaultNla),
}

const SEG6_LOCAL_CNT_UNSPEC: u16 = 0;
const SEG6_LOCAL_CNT_PAD: u16 = 1;
const SEG6_LOCAL_CNT_PACKETS: u16 = 2;
const SEG6_LOCAL_CNT_BYTES: u16 = 3;
const SEG6_LOCAL_CNT_ERRORS: u16 = 4;

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Seg6LocalCounters
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_LOCAL_CNT_UNSPEC => Self::Unspec,
            SEG6_LOCAL_CNT_PAD => Self::Padding(payload.len()),
            SEG6_LOCAL_CNT_PACKETS => Self::Packets(
                parse_u64(payload)
                    .context("invalid SEG6_LOCAL_CNT_PACKETS value")?,
            ),
            SEG6_LOCAL_CNT_BYTES => Self::Bytes(
                parse_u64(payload)
                    .context("invalid SEG6_LOCAL_CNT_BYTES value")?,
            ),
            SEG6_LOCAL_CNT_ERRORS => Self::Errors(
                parse_u64(payload)
                    .context("invalid SEG6_LOCAL_CNT_ERRORS value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}

impl Nla for Seg6LocalCounters {
    fn value_len(&self) -> usize {
        use self::Seg6LocalCounters::*;
        match self {
            Unspec => 0,
            Padding(v) => *v,
            Packets(_) | Bytes(_) | Errors(_) => 8,
            Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use self::Seg6LocalCounters::*;
        match self {
            Unspec => SEG6_LOCAL_CNT_UNSPEC,
            Padding(_) => SEG6_LOCAL_CNT_PAD,
            Packets(_) => SEG6_LOCAL_CNT_PACKETS,
            Bytes(_) => SEG6_LOCAL_CNT_BYTES,
            Errors(_) => SEG6_LOCAL_CNT_ERRORS,
            Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Seg6LocalCounters::*;
        match self {
            Unspec | Padding(_) => {}
            Packets(v) | Bytes(v) | Errors(v) => {
                buffer[..8].copy_from_slice(v.to_ne_bytes().as_slice())
            }
            Other(nla) => nla.emit_value(buffer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Seg6LocalFlavors {
    Operation(Seg6LocalFlavorOps),
    Lblen(u8),
    Nflen(u8),
    Other(DefaultNla),
}

const SEG6_LOCAL_FLV_OPERATION: u16 = 1;
const SEG6_LOCAL_FLV_LCBLOCK_BITS: u16 = 2;
const SEG6_LOCAL_FLV_LCNODE_FN_BITS: u16 = 3;

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Seg6LocalFlavors
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_LOCAL_FLV_OPERATION => Self::Operation(
                parse_u32(payload)
                    .context("invalid SEG6_LOCAL_FLV_OPERATION value")?
                    .into(),
            ),
            SEG6_LOCAL_FLV_LCBLOCK_BITS => Self::Lblen(
                parse_u8(payload)
                    .context("invalid SEG6_LOCAL_FLV_LCBLOCK_BITS value")?,
            ),
            SEG6_LOCAL_FLV_LCNODE_FN_BITS => Self::Nflen(
                parse_u8(payload)
                    .context("invalid SEG6_LOCAL_FLV_LCNODE_FN_BITS value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}

impl Nla for Seg6LocalFlavors {
    fn value_len(&self) -> usize {
        use self::Seg6LocalFlavors::*;
        match self {
            Operation(_) => 4,
            Lblen(_) => 1,
            Nflen(_) => 1,
            Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        use self::Seg6LocalFlavors::*;
        match self {
            Operation(_) => SEG6_LOCAL_FLV_OPERATION,
            Lblen(_) => SEG6_LOCAL_FLV_LCBLOCK_BITS,
            Nflen(_) => SEG6_LOCAL_FLV_LCNODE_FN_BITS,
            Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Seg6LocalFlavors::*;
        match self {
            Operation(v) => {
                let operation: u32 = (*v).into();
                buffer[..4].copy_from_slice(operation.to_ne_bytes().as_slice())
            }
            Lblen(v) => buffer[0] = *v,
            Nflen(v) => buffer[0] = *v,
            Other(nla) => nla.emit_value(buffer),
        }
    }
}

const SEG6_LOCAL_FLV_OP_UNSPEC: u32 = 1 << 0;
const SEG6_LOCAL_FLV_OP_PSP: u32 = 1 << 1;
const SEG6_LOCAL_FLV_OP_USP: u32 = 1 << 2;
const SEG6_LOCAL_FLV_OP_USD: u32 = 1 << 3;
const SEG6_LOCAL_FLV_OP_NEXT_CSID: u32 = 1 << 4;

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
#[non_exhaustive]
pub enum Seg6LocalFlavorOps {
    #[default]
    Unspec,
    Psp,
    Usp,
    Usd,
    NextCsid,
    Other(u32),
}

impl From<u32> for Seg6LocalFlavorOps {
    fn from(d: u32) -> Self {
        match d {
            SEG6_LOCAL_FLV_OP_UNSPEC => Self::Unspec,
            SEG6_LOCAL_FLV_OP_PSP => Self::Psp,
            SEG6_LOCAL_FLV_OP_USP => Self::Usp,
            SEG6_LOCAL_FLV_OP_USD => Self::Usd,
            SEG6_LOCAL_FLV_OP_NEXT_CSID => Self::NextCsid,
            _ => Self::Other(d),
        }
    }
}

impl From<Seg6LocalFlavorOps> for u32 {
    fn from(v: Seg6LocalFlavorOps) -> u32 {
        match v {
            Seg6LocalFlavorOps::Unspec => SEG6_LOCAL_FLV_OP_UNSPEC,
            Seg6LocalFlavorOps::Psp => SEG6_LOCAL_FLV_OP_PSP,
            Seg6LocalFlavorOps::Usp => SEG6_LOCAL_FLV_OP_USP,
            Seg6LocalFlavorOps::Usd => SEG6_LOCAL_FLV_OP_USD,
            Seg6LocalFlavorOps::NextCsid => SEG6_LOCAL_FLV_OP_NEXT_CSID,
            Seg6LocalFlavorOps::Other(d) => d,
        }
    }
}
