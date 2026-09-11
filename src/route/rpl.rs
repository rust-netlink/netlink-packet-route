// SPDX-License-Identifier: MIT

use std::{fmt::Debug, net::Ipv6Addr};

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer,
    Parseable,
};

use crate::ip::parse_ipv6_addr;

const RPL_IPTUNNEL_UNSPEC: u16 = 0;
const RPL_IPTUNNEL_SRH: u16 = 1;

const RPL_SRH_FIXED_LEN: usize = 8;
const RPL_SEGMENT_LEN: usize = 16;

/// The RPL segment routing header of `RPL_IPTUNNEL_SRH` attribute.
///
/// The `cmpri` and `cmpre` fields describe compressed segments which is not
/// supported by this crate, therefore parsing fails when they are not zero.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct RplSrh {
    pub next_header: u8,
    pub routing_type: u8,
    pub segments_left: u8,
    pub cmpri: u8,
    pub cmpre: u8,
    pub pad: u8,
    /// Segment addresses in wire order.
    pub segments: Vec<Ipv6Addr>,
}

impl RplSrh {
    fn hdr_len(&self) -> u8 {
        let srh_len = RPL_SRH_FIXED_LEN + RPL_SEGMENT_LEN * self.segments.len();
        ((srh_len >> 3) - 1) as u8
    }

    fn cmpr_fields(&self) -> u32 {
        u32::from(self.cmpri & 0x0f)
            | (u32::from(self.cmpre & 0x0f) << 4)
            | (u32::from(self.pad & 0x0f) << 8)
    }
}

impl Nla for RplSrh {
    fn value_len(&self) -> usize {
        RPL_SRH_FIXED_LEN + RPL_SEGMENT_LEN * self.segments.len()
    }

    fn kind(&self) -> u16 {
        RPL_IPTUNNEL_SRH
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0] = self.next_header;
        buffer[1] = self.hdr_len();
        buffer[2] = self.routing_type;
        buffer[3] = self.segments_left;
        emit_u32(&mut buffer[4..8], self.cmpr_fields()).unwrap();
        for (i, segment) in self.segments.iter().enumerate() {
            let start = RPL_SRH_FIXED_LEN + RPL_SEGMENT_LEN * i;
            buffer[start..start + RPL_SEGMENT_LEN]
                .copy_from_slice(&segment.octets());
        }
    }
}

impl<'a, T> Parseable<NlaBuffer<&'a T>> for RplSrh
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        if payload.len() < RPL_SRH_FIXED_LEN {
            return Err(DecodeError::from(format!(
                "Invalid RPL_IPTUNNEL_SRH value {payload:?}"
            )));
        }
        let hdr_len = payload[1] as usize;
        let srh_len = (hdr_len + 1) * 8;
        if srh_len != payload.len()
            || (srh_len - RPL_SRH_FIXED_LEN) % RPL_SEGMENT_LEN != 0
        {
            return Err(DecodeError::from(format!(
                "Unsupported RPL_IPTUNNEL_SRH value {payload:?}"
            )));
        }
        let cmpr_fields =
            parse_u32(&payload[4..8]).context("Invalid RPL_IPTUNNEL_SRH")?;
        let cmpri = (cmpr_fields & 0x0f) as u8;
        let cmpre = ((cmpr_fields >> 4) & 0x0f) as u8;
        let pad = ((cmpr_fields >> 8) & 0x0f) as u8;
        if cmpri != 0 || cmpre != 0 {
            return Err(DecodeError::from(format!(
                "Compressed RPL segment is not supported: {payload:?}"
            )));
        }
        let mut segments = Vec::new();
        let mut offset = RPL_SRH_FIXED_LEN;
        while offset + RPL_SEGMENT_LEN <= payload.len() {
            segments.push(parse_ipv6_addr(
                &payload[offset..offset + RPL_SEGMENT_LEN],
            )?);
            offset += RPL_SEGMENT_LEN;
        }
        Ok(Self {
            next_header: payload[0],
            routing_type: payload[2],
            segments_left: payload[3],
            cmpri,
            cmpre,
            pad,
            segments,
        })
    }
}

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_RPL`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub enum RouteRplIpTunnel {
    #[default]
    Unspecified,
    Srh(RplSrh),
    Other(DefaultNla),
}

impl std::fmt::Display for RouteRplIpTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::Srh(srh) => write!(
                f,
                "srh segs {} [ {} ]",
                srh.segments_left,
                srh.segments
                    .iter()
                    .rev()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
                    .join(" ")
            ),
            Self::Other(other) => other.fmt(f),
        }
    }
}

impl Nla for RouteRplIpTunnel {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Srh(srh) => srh.value_len(),
            Self::Other(other) => other.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => RPL_IPTUNNEL_UNSPEC,
            Self::Srh(srh) => srh.kind(),
            Self::Other(other) => other.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Srh(srh) => srh.emit_value(buffer),
            Self::Other(other) => other.emit_value(buffer),
        }
    }
}

impl<'a, T> Parseable<NlaBuffer<&'a T>> for RouteRplIpTunnel
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            RPL_IPTUNNEL_UNSPEC => Self::Unspecified,
            RPL_IPTUNNEL_SRH => match RplSrh::parse(buf) {
                Ok(srh) => Self::Srh(srh),
                Err(_) => Self::Other(DefaultNla::parse(buf)?),
            },
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
