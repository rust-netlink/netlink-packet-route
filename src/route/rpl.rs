// SPDX-License-Identifier: MIT

use std::{fmt::Debug, net::Ipv6Addr};

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
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
        // `struct ipv6_rpl_sr_hdr` uses endian-dependent bitfields:
        //
        // little endian: cmpre:4, cmpri:4, reserved:4, pad:4
        // big endian:    cmpri:4, cmpre:4, pad:4, reserved:20
        if cfg!(target_endian = "little") {
            u32::from(self.cmpre & 0x0f)
                | (u32::from(self.cmpri & 0x0f) << 4)
                | (u32::from(self.pad & 0x0f) << 12)
        } else {
            (u32::from(self.cmpri & 0x0f) << 28)
                | (u32::from(self.cmpre & 0x0f) << 24)
                | (u32::from(self.pad & 0x0f) << 20)
        }
    }
}

impl Nla for RplSrh {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.push(self.next_header);
        out.push(self.hdr_len());
        out.push(self.routing_type);
        out.push(self.segments_left);
        append_u32(out, self.cmpr_fields());
        for segment in &self.segments {
            append_bytes(out, &segment.octets());
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        RPL_IPTUNNEL_SRH
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for RplSrh {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
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
        let (cmpri, cmpre, pad) = if cfg!(target_endian = "little") {
            (
                ((cmpr_fields >> 4) & 0x0f) as u8,
                (cmpr_fields & 0x0f) as u8,
                ((cmpr_fields >> 12) & 0x0f) as u8,
            )
        } else {
            (
                ((cmpr_fields >> 28) & 0x0f) as u8,
                ((cmpr_fields >> 24) & 0x0f) as u8,
                ((cmpr_fields >> 20) & 0x0f) as u8,
            )
        };
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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Srh(srh) => srh.emit_value(out)?,
            Self::Other(other) => append_bytes(out, other.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => RPL_IPTUNNEL_UNSPEC,
            Self::Srh(srh) => srh.kind(),
            Self::Other(other) => other.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for RouteRplIpTunnel {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
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
