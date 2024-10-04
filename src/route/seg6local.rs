// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u32, parse_u64},
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
const SEG6_LOCAL_BPF: u16 = 8;
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
    Counters(u64, u64, u64),
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
            Self::Counters(_, _, _) => 24,
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
            Self::Counters(_, _, _) => SEG6_LOCAL_COUNTERS,
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
            Self::Counters(v1, v2, v3) => {
                buffer[..8].copy_from_slice(v1.to_ne_bytes().as_slice());
                buffer[8..16].copy_from_slice(v2.to_ne_bytes().as_slice());
                buffer[16..24].copy_from_slice(v3.to_ne_bytes().as_slice());
            }
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
            SEG6_LOCAL_COUNTERS => Self::Counters(
                parse_u64(payload)
                    .context("invalid SEG6_LOCAL_COUNTERS value")?,
                parse_u64(&payload[8..16])
                    .context("invalid SEG6_LOCAL_COUNTERS value")?,
                parse_u64(&payload[16..24])
                    .context("invalid SEG6_LOCAL_COUNTERS value")?,
            ),
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
