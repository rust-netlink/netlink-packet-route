// SPDX-License-Identifier: MIT

use std::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
};

use netlink_packet_core::{
    append_bytes, append_u16_be, append_u32_be, parse_u16_be, parse_u32_be,
    parse_u8, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::{TcActionGeneric, TcActionGenericBuffer, Tcf};
/// set tunnel key
///
/// The set_tunnel action allows to set tunnel encap applied
/// at the last stage of action processing
use crate::ip::{parse_ipv4_addr, parse_ipv6_addr};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcActionTunnelKey {}
impl TcActionTunnelKey {
    pub const KIND: &'static str = "tunnel_key";
}

const TCA_TUNNEL_KEY_TM: u16 = 1;
const TCA_TUNNEL_KEY_PARMS: u16 = 2;
const TCA_TUNNEL_KEY_ENC_IPV4_SRC: u16 = 3;
const TCA_TUNNEL_KEY_ENC_IPV4_DST: u16 = 4;
const TCA_TUNNEL_KEY_ENC_IPV6_SRC: u16 = 5;
const TCA_TUNNEL_KEY_ENC_IPV6_DST: u16 = 6;
const TCA_TUNNEL_KEY_ENC_KEY_ID: u16 = 7;
// const TCA_TUNNEL_KEY_PAD: u16 = 8;
const TCA_TUNNEL_KEY_ENC_DST_PORT: u16 = 9;
const TCA_TUNNEL_KEY_NO_CSUM: u16 = 10;
// const TCA_TUNNEL_KEY_ENC_OPTS: u16 = 11;
const TCA_TUNNEL_KEY_ENC_TOS: u16 = 12;
const TCA_TUNNEL_KEY_ENC_TTL: u16 = 13;
// const TCA_TUNNEL_KEY_NO_FRAG: u16 = 14;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcActionTunnelKeyOption {
    Tm(Tcf),
    Parms(TcTunnelKey),
    EncIpv4Src(Ipv4Addr),
    EncIpv4Dst(Ipv4Addr),
    EncIpv6Src(Ipv6Addr),
    EncIpv6Dst(Ipv6Addr),
    EncKeyId(u32),
    EncDstPort(u16),
    EncTos(u8),
    EncTtl(u8),
    NoCsum(bool),
    Other(DefaultNla),
}

impl Nla for TcActionTunnelKeyOption {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Tm(p) => p.emit(out)?,
            Self::Parms(p) => p.emit(out)?,
            Self::EncIpv4Src(ip) | Self::EncIpv4Dst(ip) => {
                append_bytes(out, &ip.octets())
            }
            Self::EncIpv6Src(ip) | Self::EncIpv6Dst(ip) => {
                append_bytes(out, &ip.octets())
            }
            Self::EncKeyId(i) => append_u32_be(out, *i),
            Self::EncDstPort(i) => append_u16_be(out, *i),
            Self::EncTos(i) | Self::EncTtl(i) => out.push(*i),
            Self::NoCsum(i) => out.push(*i as u8),
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Tm(_) => TCA_TUNNEL_KEY_TM,
            Self::Parms(_) => TCA_TUNNEL_KEY_PARMS,
            Self::EncIpv4Src(_) => TCA_TUNNEL_KEY_ENC_IPV4_SRC,
            Self::EncIpv4Dst(_) => TCA_TUNNEL_KEY_ENC_IPV4_DST,
            Self::EncIpv6Src(_) => TCA_TUNNEL_KEY_ENC_IPV6_SRC,
            Self::EncIpv6Dst(_) => TCA_TUNNEL_KEY_ENC_IPV6_DST,
            Self::EncKeyId(_) => TCA_TUNNEL_KEY_ENC_KEY_ID,
            Self::EncDstPort(_) => TCA_TUNNEL_KEY_ENC_DST_PORT,
            Self::EncTos(_) => TCA_TUNNEL_KEY_ENC_TOS,
            Self::EncTtl(_) => TCA_TUNNEL_KEY_ENC_TTL,
            Self::NoCsum(_) => TCA_TUNNEL_KEY_NO_CSUM,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcActionTunnelKeyOption {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_TUNNEL_KEY_TM => Self::Tm(Tcf::parse(payload)?),
            TCA_TUNNEL_KEY_PARMS => Self::Parms(TcTunnelKey::parse(payload)?),
            TCA_TUNNEL_KEY_ENC_IPV4_SRC => Self::EncIpv4Src(
                parse_ipv4_addr(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_IPV4_SRC")?,
            ),
            TCA_TUNNEL_KEY_ENC_IPV4_DST => Self::EncIpv4Dst(
                parse_ipv4_addr(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_IPV4_DST")?,
            ),
            TCA_TUNNEL_KEY_ENC_IPV6_SRC => Self::EncIpv6Src(
                parse_ipv6_addr(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_IPV6_SRC")?,
            ),
            TCA_TUNNEL_KEY_ENC_IPV6_DST => Self::EncIpv6Dst(
                parse_ipv6_addr(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_IPV6_DST")?,
            ),
            TCA_TUNNEL_KEY_ENC_KEY_ID => Self::EncKeyId(
                parse_u32_be(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_KEY_ID")?,
            ),
            TCA_TUNNEL_KEY_ENC_DST_PORT => Self::EncDstPort(
                parse_u16_be(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_DST_PORT")?,
            ),
            TCA_TUNNEL_KEY_ENC_TOS => Self::EncTos(
                parse_u8(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_TOS")?,
            ),
            TCA_TUNNEL_KEY_ENC_TTL => Self::EncTtl(
                parse_u8(payload)
                    .context("failed to parse TCA_TUNNEL_KEY_ENC_TTL")?,
            ),
            TCA_TUNNEL_KEY_NO_CSUM => Self::NoCsum(
                parse_u8(payload)
                    .context("invalid TCA_TUNNEL_KEY_NO_CSUM value")?
                    != 0,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcTunnelKey {
    pub generic: TcActionGeneric,
    pub t_action: i32,
}

// kernel struct `tc_tunnel_key`
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
pub struct TcTunnelKeyBuffer {
    generic: TcActionGenericBuffer,
    t_action: i32,
}

impl TcTunnelKey {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcTunnelKeyBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcTunnelKeyBuffer>(),
                )
            })?;
        Ok(Self {
            generic: TcActionGeneric::parse(
                &payload[..size_of::<TcActionGenericBuffer>()],
            )?,
            t_action: raw.t_action,
        })
    }
}

impl From<&TcTunnelKey> for TcTunnelKeyBuffer {
    fn from(key: &TcTunnelKey) -> Self {
        Self {
            generic: TcActionGenericBuffer::from(&key.generic),
            t_action: key.t_action,
        }
    }
}

impl Emitable for TcTunnelKey {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TcTunnelKeyBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
