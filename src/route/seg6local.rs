// SPDX-License-Identifier: MIT

use std::{
    fmt::Debug,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
};

use netlink_packet_core::{
    emit_u16_be, emit_u32, parse_u16_be, parse_u32, DecodeError, DefaultNla,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

use crate::ip::{parse_ipv4_addr, parse_ipv6_addr};

const SEG6_LOCAL_UNSPEC: u16 = 0;
const SEG6_LOCAL_ACTION: u16 = 1;
const SEG6_LOCAL_SRH: u16 = 2;
const SEG6_LOCAL_TABLE: u16 = 3;
const SEG6_LOCAL_NH4: u16 = 4;
const SEG6_LOCAL_NH6: u16 = 5;
const SEG6_LOCAL_IIF: u16 = 6;
const SEG6_LOCAL_OIF: u16 = 7;
const SEG6_LOCAL_VRFTABLE: u16 = 9;

const SEG6_LOCAL_SRH_FIXED_LEN: usize = 8;
const SEG6_LOCAL_SEGMENT_LEN: usize = 16;

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

/// Actions of `SEG6_LOCAL_ACTION` attribute, the string representation
/// follows `iproute2`.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
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
            d => Self::Other(d),
        }
    }
}

impl From<Seg6LocalAction> for u32 {
    fn from(v: Seg6LocalAction) -> Self {
        match v {
            Seg6LocalAction::Unspec => 0,
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

impl std::fmt::Display for Seg6LocalAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspec => write!(f, "unspec"),
            Self::End => write!(f, "End"),
            Self::EndX => write!(f, "End.X"),
            Self::EndT => write!(f, "End.T"),
            Self::EndDx2 => write!(f, "End.DX2"),
            Self::EndDx6 => write!(f, "End.DX6"),
            Self::EndDx4 => write!(f, "End.DX4"),
            Self::EndDt6 => write!(f, "End.DT6"),
            Self::EndDt4 => write!(f, "End.DT4"),
            Self::EndB6 => write!(f, "End.B6"),
            Self::EndB6Encap => write!(f, "End.B6.Encaps"),
            Self::EndBm => write!(f, "End.BM"),
            Self::EndS => write!(f, "End.S"),
            Self::EndAs => write!(f, "End.AS"),
            Self::EndAm => write!(f, "End.AM"),
            Self::EndBpf => write!(f, "End.BPF"),
            Self::EndDt46 => write!(f, "End.DT46"),
            Self::Other(d) => write!(f, "other({d})"),
        }
    }
}

/// The segment routing header of `SEG6_LOCAL_SRH` attribute.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct Seg6LocalSrh {
    pub next_header: u8,
    pub routing_type: u8,
    pub segments_left: u8,
    pub first_segment: u8,
    pub flags: u8,
    pub tag: u16,
    pub segments: Vec<Ipv6Addr>,
}

impl Seg6LocalSrh {
    fn hdr_len(&self) -> u8 {
        let srh_len = SEG6_LOCAL_SRH_FIXED_LEN
            + SEG6_LOCAL_SEGMENT_LEN * self.segments.len();
        ((srh_len >> 3) - 1) as u8
    }
}

impl Nla for Seg6LocalSrh {
    fn value_len(&self) -> usize {
        SEG6_LOCAL_SRH_FIXED_LEN + SEG6_LOCAL_SEGMENT_LEN * self.segments.len()
    }

    fn kind(&self) -> u16 {
        SEG6_LOCAL_SRH
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0] = self.next_header;
        buffer[1] = self.hdr_len();
        buffer[2] = self.routing_type;
        buffer[3] = self.segments_left;
        buffer[4] = self.first_segment;
        buffer[5] = self.flags;
        emit_u16_be(&mut buffer[6..8], self.tag).unwrap();
        for (i, segment) in self.segments.iter().enumerate() {
            let start = SEG6_LOCAL_SRH_FIXED_LEN + SEG6_LOCAL_SEGMENT_LEN * i;
            buffer[start..start + SEG6_LOCAL_SEGMENT_LEN]
                .copy_from_slice(&segment.octets());
        }
    }
}

impl<'a, T> Parseable<NlaBuffer<&'a T>> for Seg6LocalSrh
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        if payload.len() < SEG6_LOCAL_SRH_FIXED_LEN {
            return Err(DecodeError::from(format!(
                "Invalid SEG6_LOCAL_SRH value {payload:?}"
            )));
        }
        let hdr_len = payload[1] as usize;
        let srh_len = (hdr_len + 1) * 8;
        // Only uncompressed SRH without extension TLV is supported, other
        // cases are handled by `RouteSeg6LocalTunnel::Other`.
        if srh_len != payload.len()
            || (srh_len - SEG6_LOCAL_SRH_FIXED_LEN) % SEG6_LOCAL_SEGMENT_LEN
                != 0
        {
            return Err(DecodeError::from(format!(
                "Unsupported SEG6_LOCAL_SRH value {payload:?}"
            )));
        }
        let mut segments = Vec::new();
        let mut offset = SEG6_LOCAL_SRH_FIXED_LEN;
        while offset + SEG6_LOCAL_SEGMENT_LEN <= payload.len() {
            segments.push(parse_ipv6_addr(
                &payload[offset..offset + SEG6_LOCAL_SEGMENT_LEN],
            )?);
            offset += SEG6_LOCAL_SEGMENT_LEN;
        }
        Ok(Self {
            next_header: payload[0],
            routing_type: payload[2],
            segments_left: payload[3],
            first_segment: payload[4],
            flags: payload[5],
            tag: parse_u16_be(&payload[6..8])
                .context("Invalid SEG6_LOCAL_SRH tag")?,
            segments,
        })
    }
}

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6_LOCAL`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub enum RouteSeg6LocalTunnel {
    #[default]
    Unspecified,
    Action(Seg6LocalAction),
    Srh(Seg6LocalSrh),
    Table(u32),
    Nh4(Ipv4Addr),
    Nh6(Ipv6Addr),
    Iif(u32),
    Oif(u32),
    VrfTable(u32),
    Other(DefaultNla),
}

impl std::fmt::Display for RouteSeg6LocalTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::Action(action) => write!(f, "action {action}"),
            Self::Srh(srh) => write!(
                f,
                "srh segs {} [ {} ]",
                srh.first_segment + 1,
                srh.segments
                    .iter()
                    .rev()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
                    .join(" ")
            ),
            Self::Table(table) => write!(f, "table {table}"),
            Self::Nh4(addr) => write!(f, "nh4 {addr}"),
            Self::Nh6(addr) => write!(f, "nh6 {addr}"),
            Self::Iif(iif) => write!(f, "iif {iif}"),
            Self::Oif(oif) => write!(f, "oif {oif}"),
            Self::VrfTable(table) => write!(f, "vrftable {table}"),
            Self::Other(other) => other.fmt(f),
        }
    }
}

impl Nla for RouteSeg6LocalTunnel {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Action(_)
            | Self::Table(_)
            | Self::Iif(_)
            | Self::Oif(_)
            | Self::VrfTable(_) => size_of::<u32>(),
            Self::Srh(srh) => srh.value_len(),
            Self::Nh4(_) => size_of::<Ipv4Addr>(),
            Self::Nh6(_) => size_of::<Ipv6Addr>(),
            Self::Other(other) => other.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => SEG6_LOCAL_UNSPEC,
            Self::Action(_) => SEG6_LOCAL_ACTION,
            Self::Srh(_) => SEG6_LOCAL_SRH,
            Self::Table(_) => SEG6_LOCAL_TABLE,
            Self::Nh4(_) => SEG6_LOCAL_NH4,
            Self::Nh6(_) => SEG6_LOCAL_NH6,
            Self::Iif(_) => SEG6_LOCAL_IIF,
            Self::Oif(_) => SEG6_LOCAL_OIF,
            Self::VrfTable(_) => SEG6_LOCAL_VRFTABLE,
            Self::Other(other) => other.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Action(action) => {
                emit_u32(buffer, u32::from(*action)).unwrap()
            }
            Self::Srh(srh) => srh.emit_value(buffer),
            Self::Table(value)
            | Self::Iif(value)
            | Self::Oif(value)
            | Self::VrfTable(value) => emit_u32(buffer, *value).unwrap(),
            Self::Nh4(addr) => buffer.copy_from_slice(&addr.octets()),
            Self::Nh6(addr) => buffer.copy_from_slice(&addr.octets()),
            Self::Other(other) => other.emit_value(buffer),
        }
    }
}

impl<'a, T> Parseable<NlaBuffer<&'a T>> for RouteSeg6LocalTunnel
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_LOCAL_UNSPEC => Self::Unspecified,
            SEG6_LOCAL_ACTION => Self::Action(Seg6LocalAction::from(
                parse_u32(payload).context("invalid SEG6_LOCAL_ACTION")?,
            )),
            SEG6_LOCAL_SRH => match Seg6LocalSrh::parse(buf) {
                Ok(srh) => Self::Srh(srh),
                Err(_) => Self::Other(DefaultNla::parse(buf)?),
            },
            SEG6_LOCAL_TABLE => Self::Table(
                parse_u32(payload).context("invalid SEG6_LOCAL_TABLE")?,
            ),
            SEG6_LOCAL_NH4 => Self::Nh4(
                parse_ipv4_addr(payload).context("invalid SEG6_LOCAL_NH4")?,
            ),
            SEG6_LOCAL_NH6 => Self::Nh6(
                parse_ipv6_addr(payload).context("invalid SEG6_LOCAL_NH6")?,
            ),
            SEG6_LOCAL_IIF => {
                Self::Iif(parse_u32(payload).context("invalid SEG6_LOCAL_IIF")?)
            }
            SEG6_LOCAL_OIF => {
                Self::Oif(parse_u32(payload).context("invalid SEG6_LOCAL_OIF")?)
            }
            SEG6_LOCAL_VRFTABLE => Self::VrfTable(
                parse_u32(payload).context("invalid SEG6_LOCAL_VRFTABLE")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
