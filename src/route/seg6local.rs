// SPDX-License-Identifier: MIT

// use std::net::Ipv6Addr;

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32,
    traits::{Emitable, Parseable},
    DecodeError,
};

//
const SEG6_LOCAL_UNSPEC: u16 = 0;
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
    Seg6LocalAction(Seg6LocalAction),
    Seg6LocalIpTunnel(Seg6LocalIpTunnelEncap),
    VrfTable(u32),
    Other(DefaultNla),
}

impl Nla for RouteSeg6LocalIpTunnel {
    fn value_len(&self) -> usize {
        match self {
            Self::Seg6LocalIpTunnel(v) => v.buffer_len(),
            Self::Seg6LocalAction(_) => 4,
            Self::VrfTable(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Seg6LocalIpTunnel(_) => SEG6_LOCAL_SRH,
            Self::Seg6LocalAction(_) => SEG6_LOCAL_ACTION,
            Self::VrfTable(_) => SEG6_LOCAL_VRFTABLE,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Seg6LocalIpTunnel(v) => v.emit(buffer),
            Self::Seg6LocalAction(v) => {
                let action: u32 = (*v).into();
                buffer[..4].copy_from_slice(action.to_ne_bytes().as_slice())
            }
            Self::VrfTable(v) => {
                buffer[..4].copy_from_slice(v.to_ne_bytes().as_slice())
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
            SEG6_LOCAL_SRH => Self::Seg6LocalIpTunnel(
                Seg6LocalIpTunnelEncap::parse(payload).context(format!(
                    "invalid SEG6_LOCAL_SRH value {:?}",
                    payload
                ))?,
            ),
            SEG6_LOCAL_ACTION => Self::Seg6LocalAction(
                parse_u32(payload)
                    .context("invalid SEG6_LOCAL_ACTION value")?
                    .into(),
            ),
            SEG6_LOCAL_VRFTABLE => Self::VrfTable(
                parse_u32(payload)
                    .context("invalid SEG6_LOCAL_ACTION value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// IPv6 segment routing encapsulation
pub struct Seg6LocalIpTunnelEncap {
    /// Mode
    pub mode: u32,
}

impl Emitable for Seg6LocalIpTunnelEncap {
    fn buffer_len(&self) -> usize {
        let len: usize = 4; // mode.
        len
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[..4].copy_from_slice(self.mode.to_ne_bytes().as_slice());
    }
}

impl Seg6LocalIpTunnelEncap {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        // if payload.len() < 4 {
        //     return Err(DecodeError::from(format!(
        //         "Invalid u8 array length {}, expecting \
        //         4 bytes for IPv6 segment routing mode, got {:?}",
        //         payload.len(),
        //         payload,
        //     )));
        // }
        // let mode = parse_u32(&payload[..4])
        //     .context("invalid IPv6 segment routing mode")?;
        // let (_, payload) = payload.split_at(4usize);
        // if payload.len() < 8 {
        //     return Err(DecodeError::from(format!(
        //         "Invalid u8 array length {}, expecting \
        //         8 bytes for IPv6 segment routing header, got {:?}",
        //         payload.len(),
        //         payload,
        //     )));
        // }
        // let mut ipv6_sr_hdr = Ipv6SrHdr {
        //     nexthdr: payload[0],
        //     hdrlen: payload[1],
        //     typ: payload[2],
        //     segments_left: payload[3],
        //     first_segment: payload[4],
        //     flags: payload[5],
        //     tag: 0u16,
        //     segments: vec![],
        // };
        // ipv6_sr_hdr.tag = parse_u16(&payload[6..8])
        //     .context("invalid IPv6 segment rougint header tag")?;
        // let (_, payload) = payload.split_at(8usize);
        // if (payload.len() % 16) != 0 {
        //     return Err(DecodeError::from(format!(
        //         "Invalid u8 array alignment {}, expecting \
        //         16 bytes for IPv6 segments, got {:?}",
        //         payload.len(),
        //         payload,
        //     )));
        // }
        // let mut segments = payload;
        // while !segments.is_empty() {
        //     let bytes: &[u8; 16] =
        //         segments[0..16].try_into().context("invalid IPv6 segment")?;
        //     let segment: Ipv6Addr = Ipv6Addr::from(*bytes);
        //     ipv6_sr_hdr.segments.push(segment);
        //     (_, segments) = segments.split_at(16usize);
        // }
        // Ok(Self {
        //     mode,
        //     ipv6_sr_hdr: VecIpv6SrHdr(vec![ipv6_sr_hdr]),
        // })
        Ok(Self { mode: 0 })
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
