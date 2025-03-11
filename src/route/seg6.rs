// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    Parseable,
};
use std::net::Ipv6Addr;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Seg6Mode {
    // Inline mode for Seg6
    Inline,
    // Encapsulation mode for Seg6
    Encap,
    // L2ENCAP = 2,
    // ENCAP_RED = 3,
    // L2ENCAP_RED = 4
    Other(u32),
}

impl From<Seg6Mode> for u32 {
    fn from(value: Seg6Mode) -> Self {
        match value {
            Seg6Mode::Inline => 0,
            Seg6Mode::Encap => 1,
            Seg6Mode::Other(i) => i,
        }
    }
}

impl From<u32> for Seg6Mode {
    fn from(value: u32) -> Self {
        match value {
            0 => Seg6Mode::Inline,
            1 => Seg6Mode::Encap,
            v => Seg6Mode::Other(v),
        }
    }
}

const SEG6_IPTUNNEL_SRH: u16 = 1;

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteSeg6IpTunnel {
    // Use an IPv6 segment routing header
    Seg6(Seg6Header),
    Other(DefaultNla),
}

impl Nla for RouteSeg6IpTunnel {
    fn value_len(&self) -> usize {
        match self {
            RouteSeg6IpTunnel::Seg6(v) => v.value_len(),
            RouteSeg6IpTunnel::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            RouteSeg6IpTunnel::Seg6(v) => v.kind(),
            RouteSeg6IpTunnel::Other(v) => v.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            RouteSeg6IpTunnel::Seg6(v) => v.emit_value(buffer),
            RouteSeg6IpTunnel::Other(v) => v.emit_value(buffer),
        }
    }
}

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Seg6Header {
    // Operation mode
    pub mode: Seg6Mode,
    // List of segments
    pub segments: Vec<Ipv6Addr>,
}

impl Nla for Seg6Header {
    fn value_len(&self) -> usize {
        let segments = match self.mode {
            Seg6Mode::Inline => self.segments.len() + 1,
            Seg6Mode::Encap => self.segments.len(),
            Seg6Mode::Other(_) => self.segments.len(),
        };
        12 + 16 * segments
    }

    fn kind(&self) -> u16 {
        SEG6_IPTUNNEL_SRH
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        // Some sources for understanding the format of Seg6 in Netlink
        // https://github.com/torvalds/linux/blob/master/include/uapi/linux/seg6.h
        // https://github.com/iproute2/iproute2/blob/main/include/uapi/linux/seg6_iptunnel.h#L27
        // https://github.com/iproute2/iproute2/blob/e3f9681d4a777fb2595a322b421abf0036ab1aae/ip/iproute_lwtunnel.c#L952

        let mut number_segments = self.segments.len();
        if matches!(self.mode, Seg6Mode::Inline) {
            number_segments += 1 // last segment (::) added
        }

        let srhlen = 8 + 16 * number_segments;

        // mode : 4 bytes
        NativeEndian::write_u32(&mut buffer[..4], self.mode.into());
        // nexthdr : 1 bytes
        buffer[4] = 0;
        // hdrlen : 1 bytes
        buffer[5] = ((srhlen >> 3) - 1) as u8;
        // type : 1 byte
        buffer[6] = 4;
        // segments_left : 1 byte
        buffer[7] = (number_segments - 1) as u8;
        // first_segment : 1 byte
        buffer[8] = (number_segments - 1) as u8;
        // flags : 1 byte
        buffer[9] = 0;
        // tag : 2 bytes
        NativeEndian::write_u16(&mut buffer[10..12], 0);

        let mut offset = 12;

        // Add the last segment (::) if working in inline mode
        if matches!(self.mode, Seg6Mode::Inline) {
            let addr: Ipv6Addr = "::".parse().expect("Impossible error");
            buffer[offset..offset + 16].copy_from_slice(&addr.octets());
            offset += 16;
        }

        // Add all segments in reverse order
        for addr in self.segments.iter().rev() {
            buffer[offset..offset + 16].copy_from_slice(&addr.octets());
            offset += 16;
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for RouteSeg6IpTunnel
{
    fn parse(
        buf: &NlaBuffer<&'a T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_IPTUNNEL_SRH => {
                let mode = NativeEndian::read_u32(payload).into();

                let number_segments = payload[7];

                let mut offset = 12;
                let mut segments: Vec<Ipv6Addr> = vec![];
                for _ in 0..number_segments + 1 {
                    let slice: [u8; 16] = payload[offset..offset + 16]
                        .try_into()
                        .expect("Impossible to fail");
                    let ip_addr = Ipv6Addr::from(slice);
                    segments.push(ip_addr);
                    offset += 16;
                }

                let mut segments: Vec<Ipv6Addr> =
                    segments.into_iter().rev().collect();

                if matches!(mode, Seg6Mode::Inline) {
                    segments.pop(); // remove last inline segment
                }

                RouteSeg6IpTunnel::Seg6(Seg6Header { mode, segments })
            }
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}
