// SPDX-License-Identifier: MIT

// Some sources for understanding the format of Seg6local in Netlink
//
// torvalds/linux:
//      include/uapi/linux/seg6_local.h
//
// iproute2/iproute2
//      ip/iproute_lwtunnel.c parse_encap_seg6local()

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer,
    Parseable,
};

use crate::ip::{emit_ip_addr, parse_ipv4_addr, parse_ipv6_addr};

// Netlink Encap sub-types
const SEG6_LOCAL_UNSPEC: u16 = 0;
const SEG6_LOCAL_ACTION: u16 = 1;
const SEG6_LOCAL_SRH: u16 = 2;
const SEG6_LOCAL_TABLE: u16 = 3;
const SEG6_LOCAL_NH4: u16 = 4;
const SEG6_LOCAL_NH6: u16 = 5;
const SEG6_LOCAL_IIF: u16 = 6;
const SEG6_LOCAL_OIF: u16 = 7;
// const SEG6_LOCAL_BPF: u16 = 8;
const SEG6_LOCAL_VRFTABLE: u16 = 9;
// const SEG6_LOCAL_COUNTERS: u16 = 10;
// const SEG6_LOCAL_FLAVORS: u16 = 11;

// Seg6local action types
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Seg6LocalAction {
    Unspec,
    End,
    EndX,
    EndT,
    EndDX2,
    EndDX6,
    EndDX4,
    EndDT6,
    EndDT4,
    EndB6,
    EndB6Encap,
    EndBM,
    EndS,
    EndAS,
    EndAM,
    EndBPF,
    EndDT46,
    Other(u32),
}

impl From<Seg6LocalAction> for u32 {
    fn from(value: Seg6LocalAction) -> Self {
        match value {
            Seg6LocalAction::Unspec => SEG6_LOCAL_ACTION_UNSPEC,
            Seg6LocalAction::End => SEG6_LOCAL_ACTION_END,
            Seg6LocalAction::EndX => SEG6_LOCAL_ACTION_END_X,
            Seg6LocalAction::EndT => SEG6_LOCAL_ACTION_END_T,
            Seg6LocalAction::EndDX2 => SEG6_LOCAL_ACTION_END_DX2,
            Seg6LocalAction::EndDX6 => SEG6_LOCAL_ACTION_END_DX6,
            Seg6LocalAction::EndDX4 => SEG6_LOCAL_ACTION_END_DX4,
            Seg6LocalAction::EndDT6 => SEG6_LOCAL_ACTION_END_DT6,
            Seg6LocalAction::EndDT4 => SEG6_LOCAL_ACTION_END_DT4,
            Seg6LocalAction::EndB6 => SEG6_LOCAL_ACTION_END_B6,
            Seg6LocalAction::EndB6Encap => SEG6_LOCAL_ACTION_END_B6_ENCAP,
            Seg6LocalAction::EndBM => SEG6_LOCAL_ACTION_END_BM,
            Seg6LocalAction::EndS => SEG6_LOCAL_ACTION_END_S,
            Seg6LocalAction::EndAS => SEG6_LOCAL_ACTION_END_AS,
            Seg6LocalAction::EndAM => SEG6_LOCAL_ACTION_END_AM,
            Seg6LocalAction::EndBPF => SEG6_LOCAL_ACTION_END_BPF,
            Seg6LocalAction::EndDT46 => SEG6_LOCAL_ACTION_END_DT46,
            Seg6LocalAction::Other(i) => i,
        }
    }
}

impl From<u32> for Seg6LocalAction {
    fn from(value: u32) -> Self {
        match value {
            SEG6_LOCAL_ACTION_UNSPEC => Seg6LocalAction::Unspec,
            SEG6_LOCAL_ACTION_END => Seg6LocalAction::End,
            SEG6_LOCAL_ACTION_END_X => Seg6LocalAction::EndX,
            SEG6_LOCAL_ACTION_END_T => Seg6LocalAction::EndT,
            SEG6_LOCAL_ACTION_END_DX2 => Seg6LocalAction::EndDX2,
            SEG6_LOCAL_ACTION_END_DX6 => Seg6LocalAction::EndDX6,
            SEG6_LOCAL_ACTION_END_DX4 => Seg6LocalAction::EndDX4,
            SEG6_LOCAL_ACTION_END_DT6 => Seg6LocalAction::EndDT6,
            SEG6_LOCAL_ACTION_END_DT4 => Seg6LocalAction::EndDT4,
            SEG6_LOCAL_ACTION_END_B6 => Seg6LocalAction::EndB6,
            SEG6_LOCAL_ACTION_END_B6_ENCAP => Seg6LocalAction::EndB6Encap,
            SEG6_LOCAL_ACTION_END_BM => Seg6LocalAction::EndBM,
            SEG6_LOCAL_ACTION_END_S => Seg6LocalAction::EndS,
            SEG6_LOCAL_ACTION_END_AS => Seg6LocalAction::EndAS,
            SEG6_LOCAL_ACTION_END_AM => Seg6LocalAction::EndAM,
            SEG6_LOCAL_ACTION_END_BPF => Seg6LocalAction::EndBPF,
            SEG6_LOCAL_ACTION_END_DT46 => Seg6LocalAction::EndDT46,
            v => Seg6LocalAction::Other(v),
        }
    }
}

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6_LOCAL`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteSeg6LocalIpTunnel {
    Unspec,
    Action(Seg6LocalAction),
    SRH(SRH),
    Table(u32),
    Nh4(Ipv4Addr),
    Nh6(Ipv6Addr),
    Iif(u32),
    Oif(u32),
    // BPF(...),
    VrfTable(u32),
    // Counters(...),
    // Flavors(...)
    Other(DefaultNla),
}

impl Nla for RouteSeg6LocalIpTunnel {
    fn value_len(&self) -> usize {
        match self {
            RouteSeg6LocalIpTunnel::Unspec => 0,
            RouteSeg6LocalIpTunnel::Action(_) => 4,
            RouteSeg6LocalIpTunnel::SRH(v) => v.value_len(),
            RouteSeg6LocalIpTunnel::Table(_) => 4,
            RouteSeg6LocalIpTunnel::Nh4(_) => 4,
            RouteSeg6LocalIpTunnel::Nh6(_) => 16,
            RouteSeg6LocalIpTunnel::Iif(_) => 4,
            RouteSeg6LocalIpTunnel::Oif(_) => 4,
            // BPF(...) => ...,
            RouteSeg6LocalIpTunnel::VrfTable(_) => 4,
            // Counters(...) => ...,
            // Flavors(...) => ...,
            RouteSeg6LocalIpTunnel::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            RouteSeg6LocalIpTunnel::Unspec => SEG6_LOCAL_UNSPEC,
            RouteSeg6LocalIpTunnel::Action(_) => SEG6_LOCAL_ACTION,
            RouteSeg6LocalIpTunnel::SRH(v) => v.kind(),
            RouteSeg6LocalIpTunnel::Table(_) => SEG6_LOCAL_TABLE,
            RouteSeg6LocalIpTunnel::Nh4(_) => SEG6_LOCAL_NH4,
            RouteSeg6LocalIpTunnel::Nh6(_) => SEG6_LOCAL_NH6,
            RouteSeg6LocalIpTunnel::Iif(_) => SEG6_LOCAL_IIF,
            RouteSeg6LocalIpTunnel::Oif(_) => SEG6_LOCAL_OIF,
            // BPF(...) => SEG6_LOCAL_BPF,
            RouteSeg6LocalIpTunnel::VrfTable(_) => SEG6_LOCAL_VRFTABLE,
            // Counters(...) => SEG6_LOCAL_COUNTERS,
            // Flavors(...) => SEG6_LOCAL_FLAVORS,
            RouteSeg6LocalIpTunnel::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            RouteSeg6LocalIpTunnel::Unspec => (),
            RouteSeg6LocalIpTunnel::Action(v) => {
                emit_u32(buffer, (*v).into()).unwrap()
            }
            RouteSeg6LocalIpTunnel::SRH(v) => v.emit_value(buffer),
            RouteSeg6LocalIpTunnel::Table(v) => emit_u32(buffer, *v).unwrap(),
            RouteSeg6LocalIpTunnel::Nh4(v) => {
                emit_ip_addr(&IpAddr::V4(*v), buffer)
            }
            RouteSeg6LocalIpTunnel::Nh6(v) => {
                emit_ip_addr(&IpAddr::V6(*v), buffer)
            }
            RouteSeg6LocalIpTunnel::Iif(v) => emit_u32(buffer, *v).unwrap(),
            RouteSeg6LocalIpTunnel::Oif(v) => emit_u32(buffer, *v).unwrap(),
            // BPF(...) => ...,
            RouteSeg6LocalIpTunnel::VrfTable(v) => {
                emit_u32(buffer, *v).unwrap()
            }
            // Counters(...) => ...,
            // Flavors(...) => ...,
            RouteSeg6LocalIpTunnel::Other(v) => v.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for RouteSeg6LocalIpTunnel
{
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> Result<Self, netlink_packet_core::DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_LOCAL_UNSPEC => Self::Unspec,
            SEG6_LOCAL_ACTION => Self::Action(parse_u32(payload)?.into()),
            SEG6_LOCAL_SRH => Self::SRH(SRH::parse(buf)?),
            SEG6_LOCAL_TABLE => Self::Table(parse_u32(payload)?),
            SEG6_LOCAL_NH4 => Self::Nh4(parse_ipv4_addr(payload)?),
            SEG6_LOCAL_NH6 => Self::Nh6(parse_ipv6_addr(payload)?),
            SEG6_LOCAL_IIF => Self::Iif(parse_u32(payload)?),
            SEG6_LOCAL_OIF => Self::Oif(parse_u32(payload)?),
            // SEG6_LOCAL_BPF => Self::BPF(...),
            SEG6_LOCAL_VRFTABLE => Self::VrfTable(parse_u32(payload)?),
            // SEG6_LOCAL_COUNTERS => Self::Counters(...),
            // SEG6_LOCAL_FLAVORS => Self::Flavors(...),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}

const SEG6_HEADER_LEN: usize = 8;

buffer!(Seg6MessageBuffer(SEG6_HEADER_LEN) {
    nexthdr: (u8, 0),
    hdrlen: (u8, 1),
    seg_type: (u8, 2),
    segments_left: (u8, 3),
    first_segment: (u8, 4),
    flags: (u8, 5),
    tag: (u16, 6..8),
    segments: (slice, SEG6_HEADER_LEN..),
});

const SEG6_SEGMENT_LEN: usize = 16;

buffer!(Seg6SegmentBuffer(SEG6_SEGMENT_LEN) {
    segment: (slice, 0..SEG6_SEGMENT_LEN),
    rest: (slice, SEG6_SEGMENT_LEN..)
});

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct SRH {
    // List of segments
    pub segments: Vec<Ipv6Addr>,
}

impl SRH {
    fn push_segments(buf: &mut [u8], mut segments: Vec<Ipv6Addr>) {
        if let Some(segment) = segments.pop() {
            let mut segment_buffer = Seg6SegmentBuffer::new(buf);
            emit_ip_addr(&IpAddr::V6(segment), segment_buffer.segment_mut());
            Self::push_segments(segment_buffer.rest_mut(), segments);
        }
    }

    fn get_segments(
        buf: &[u8],
        segments: &mut Vec<Ipv6Addr>,
    ) -> Result<(), DecodeError> {
        // are there any remaining segments ?
        if buf.len() >= SEG6_SEGMENT_LEN {
            let segment_buffer = Seg6SegmentBuffer::new(buf);
            let segment = parse_ipv6_addr(segment_buffer.segment())?;
            segments.push(segment);
            Self::get_segments(segment_buffer.rest(), segments)?;
        }
        Ok(())
    }
}

impl Nla for SRH {
    fn value_len(&self) -> usize {
        8 + 16 * self.segments.len()
    }

    fn kind(&self) -> u16 {
        SEG6_LOCAL_SRH
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut seg6_header = Seg6MessageBuffer::new(buffer);

        let number_segments = self.segments.len();
        let srhlen = 8 + 16 * number_segments;

        seg6_header.set_nexthdr(0);
        seg6_header.set_hdrlen(((srhlen >> 3) - 1) as u8);
        seg6_header.set_seg_type(4);
        seg6_header.set_segments_left((number_segments - 1) as u8);
        seg6_header.set_first_segment((number_segments - 1) as u8);
        seg6_header.set_flags(0);
        seg6_header.set_tag(0);

        let segments = self.segments.clone();

        SRH::push_segments(seg6_header.segments_mut(), segments);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for SRH {
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> Result<Self, netlink_packet_core::DecodeError> {
        let payload = buf.value();
        let seg6_header = Seg6MessageBuffer::new(payload);

        let mut segments: Vec<Ipv6Addr> = vec![];
        SRH::get_segments(seg6_header.segments(), &mut segments)?;

        let segments: Vec<Ipv6Addr> = segments.into_iter().rev().collect();

        Ok(SRH { segments })
    }
}
