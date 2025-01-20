// SPDX-License-Identifier: MIT

use std::net::Ipv6Addr;

use anyhow::Context;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16, parse_u32, parse_u32_be},
    traits::{Emitable, Parseable},
    DecodeError,
};

const SEG6_IPTUNNEL_SRH: u16 = 1;

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_SEG6`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteSeg6IpTunnel {
    Seg6IpTunnel(Seg6IpTunnelEncap),
    Other(DefaultNla),
}

impl Nla for RouteSeg6IpTunnel {
    fn value_len(&self) -> usize {
        match self {
            Self::Seg6IpTunnel(v) => v.buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Seg6IpTunnel(_) => SEG6_IPTUNNEL_SRH,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Seg6IpTunnel(v) => v.emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for RouteSeg6IpTunnel
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            SEG6_IPTUNNEL_SRH => {
                Self::Seg6IpTunnel(Seg6IpTunnelEncap::parse(payload).context(
                    format!("invalid SEG6_IPTUNNEL_SRH value {:?}", payload),
                )?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NLA value (unknown type) value")?,
            ),
        })
    }
}

const SR6_FLAG1_PROTECTED: u8 = 0x40;
const SR6_FLAG1_OAM: u8 = 0x20;
const SR6_FLAG1_ALERT: u8 = 0x10;
const SR6_FLAG1_HMAC: u8 = 0x08;

// const SR6_TLV_INGRESS: u8 = 1;
// const SR6_TLV_EGRESS: u8 = 2;
// const SR6_TLV_OPAQUE: u8 = 3;
// const SR6_TLV_PADDING: u8 = 4;
const SR6_TLV_HMAC: u8 = 5;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct SrhFlags: u8 {
        const Protected = SR6_FLAG1_PROTECTED;
        const Oam = SR6_FLAG1_OAM;
        const Alert = SR6_FLAG1_ALERT;
        const Hmac = SR6_FLAG1_HMAC;
        const _ = !0;
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
/// IPv6 segment routing header
pub struct Ipv6SrHdr {
    /// Next header
    pub nexthdr: u8,
    /// Header length
    pub hdrlen: u8,
    /// Type
    pub typ: u8,
    /// Segments left
    pub segments_left: u8,
    /// First segment
    pub first_segment: u8,
    /// Flags
    pub flags: u8,
    /// Tag
    pub tag: u16,
    /// IPv6 segments
    pub segments: Vec<Ipv6Addr>,
    /// HMAC
    pub tlvs: Vec<Ipv6SrHdrTlv>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Ipv6SrHdrTlv {
    Hmac(HmacTlv),
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct HmacTlv {
    /// D bit
    pub d_bit: bool,

    /// HMAC Key Id
    pub hmac_key_id: u32,

    /// HMAC
    pub hmac: Vec<u8>,
}

impl Emitable for Ipv6SrHdr {
    fn buffer_len(&self) -> usize {
        let len: usize = 8 + (self.segments.len() * 16);
        len
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.nexthdr;
        buffer[1] = self.hdrlen;
        buffer[2] = self.typ;
        buffer[3] = self.segments_left;
        buffer[4] = self.first_segment;
        buffer[5] = self.flags;
        buffer[6..8].copy_from_slice(self.tag.to_ne_bytes().as_slice());
        let mut index = 8;
        for segment in self.segments.iter() {
            buffer[index..index + 16].copy_from_slice(&segment.octets());
            index += 16;
        }
    }
}

impl Ipv6SrHdr {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 8 {
            return Err(DecodeError::from(format!(
                "Invalid u8 array length {}, expecting \
                8 bytes for IPv6 segment routing header, got {:?}",
                payload.len(),
                payload,
            )));
        }
        let mut ipv6_sr_hdr = Ipv6SrHdr {
            nexthdr: payload[0],
            hdrlen: payload[1],
            typ: payload[2],
            segments_left: payload[3],
            first_segment: payload[4],
            flags: payload[5],
            ..Default::default() // tag: 0u16,
                                 // segments: vec![],
                                 // hmac_key_id,
        };
        ipv6_sr_hdr.tag = parse_u16(&payload[6..8])
            .context("invalid IPv6 segment routing header tag")?;
        let (_, payload) = payload.split_at(8usize);

        let seglen: usize = ((ipv6_sr_hdr.segments_left + 1) * 16) as usize;
        if payload.len() < seglen {
            return Err(DecodeError::from(format!(
                "Invalid u8 array alignment {}, expecting \
                16 bytes for IPv6 segments, got {:?}",
                payload.len(),
                payload,
            )));
        }
        let (mut segments, payload) = payload.split_at(seglen);
        while !segments.is_empty() {
            let bytes: &[u8; 16] =
                segments[0..16].try_into().context("invalid IPv6 segment")?;
            let segment: Ipv6Addr = Ipv6Addr::from(*bytes);
            ipv6_sr_hdr.segments.push(segment);
            (_, segments) = segments.split_at(16usize);
        }

        if !payload.is_empty() {
            // Type and length.
            if payload.len() < 4 {
                return Err(DecodeError::from(format!(
                    "Invalid TLV header length {}, expecting \
                     at least 4 bytes for TLV header, got {:?}",
                    payload.len(),
                    payload,
                )));
            }
            let typ = payload[0];
            let length = payload[1];

            // HMAC
            if typ == SR6_TLV_HMAC {
                if length != 38 {
                    return Err(DecodeError::from(format!(
                        "Invalid HMAC header length {}, expecting \
                         38 bytes for TLV header, got {:?}",
                        payload.len(),
                        payload,
                    )));
                }
                let mut hmac = HmacTlv::default();
                let resv1 = payload[2];
                hmac.d_bit = (resv1 & 0x80) == 0x80;
                hmac.hmac_key_id = parse_u32_be(&payload[4..8]) // 32
                    .context("invalid IPv6 segment routing header tag")?;
                let (_, payload) = payload.split_at(8);
                let (hmac_data, _payload) = payload.split_at(32);
                hmac.hmac = Vec::from(hmac_data);
                ipv6_sr_hdr.tlvs.push(Ipv6SrHdrTlv::Hmac(hmac));
            }
        }

        Ok(ipv6_sr_hdr)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VecIpv6SrHdr(pub Vec<Ipv6SrHdr>);

const SEG6_IPTUN_MODE_INLINE: u32 = 0;
const SEG6_IPTUN_MODE_ENCAP: u32 = 1;
const SEG6_IPTUN_MODE_L2ENCAP: u32 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
#[non_exhaustive]
pub enum Seg6IpTunnelMode {
    #[default]
    Inline,
    Encap,
    L2Encap,
    Other(u32),
}

impl From<u32> for Seg6IpTunnelMode {
    fn from(d: u32) -> Self {
        match d {
            SEG6_IPTUN_MODE_INLINE => Self::Inline,
            SEG6_IPTUN_MODE_ENCAP => Self::Encap,
            SEG6_IPTUN_MODE_L2ENCAP => Self::L2Encap,
            _ => Self::Other(d),
        }
    }
}

impl From<Seg6IpTunnelMode> for u32 {
    fn from(v: Seg6IpTunnelMode) -> u32 {
        match v {
            Seg6IpTunnelMode::Inline => SEG6_IPTUN_MODE_INLINE,
            Seg6IpTunnelMode::Encap => SEG6_IPTUN_MODE_ENCAP,
            Seg6IpTunnelMode::L2Encap => SEG6_IPTUN_MODE_L2ENCAP,
            Seg6IpTunnelMode::Other(d) => d,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// IPv6 segment routing encapsulation
pub struct Seg6IpTunnelEncap {
    /// Mode
    pub mode: Seg6IpTunnelMode,
    /// IPv6 segment routing headers
    pub ipv6_sr_hdr: VecIpv6SrHdr,
}

impl Seg6IpTunnelEncap {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 4 {
            return Err(DecodeError::from(format!(
                "Invalid u8 array length {}, expecting \
                4 bytes for IPv6 segment routing mode, got {:?}",
                payload.len(),
                payload,
            )));
        }
        let mode = parse_u32(&payload[..4])
            .context("invalid IPv6 segment routing mode")?;
        let (_, payload) = payload.split_at(4usize);
        if payload.len() < 8 {
            return Err(DecodeError::from(format!(
                "Invalid u8 array length {}, expecting \
                8 bytes for IPv6 segment routing header, got {:?}",
                payload.len(),
                payload,
            )));
        }
        let mut ipv6_sr_hdr = Ipv6SrHdr {
            nexthdr: payload[0],
            hdrlen: payload[1],
            typ: payload[2],
            segments_left: payload[3],
            first_segment: payload[4],
            flags: payload[5],
            ..Default::default()
        };
        ipv6_sr_hdr.tag = parse_u16(&payload[6..8])
            .context("invalid IPv6 segment routing header tag")?;
        let (_, payload) = payload.split_at(8usize);
        if (payload.len() % 16) != 0 {
            return Err(DecodeError::from(format!(
                "Invalid u8 array alignment {}, expecting \
                16 bytes for IPv6 segments, got {:?}",
                payload.len(),
                payload,
            )));
        }
        let mut segments = payload;
        while !segments.is_empty() {
            let bytes: &[u8; 16] =
                segments[0..16].try_into().context("invalid IPv6 segment")?;
            let segment: Ipv6Addr = Ipv6Addr::from(*bytes);
            ipv6_sr_hdr.segments.push(segment);
            (_, segments) = segments.split_at(16usize);
        }
        Ok(Self {
            mode: mode.into(),
            ipv6_sr_hdr: VecIpv6SrHdr(vec![ipv6_sr_hdr]),
        })
    }
}

impl Emitable for Seg6IpTunnelEncap {
    fn buffer_len(&self) -> usize {
        let mut len: usize = 4; // mode.
        for hdr in self.ipv6_sr_hdr.0.iter() {
            len += hdr.buffer_len();
        }
        len
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mode: u32 = self.mode.into();
        buffer[..4].copy_from_slice(mode.to_ne_bytes().as_slice());
        let mut index = 4;
        for ipv6_sr_hdr in self.ipv6_sr_hdr.0.iter() {
            let len = ipv6_sr_hdr.buffer_len();
            ipv6_sr_hdr.emit(&mut buffer[index..index + len]);
            index += len;
        }
    }
}
