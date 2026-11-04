// SPDX-License-Identifier: MIT

use std::{mem::size_of, net::Ipv6Addr};

use netlink_packet_core::{
    append_bytes, append_u16, append_u16_be, append_u32, append_u32_be,
    parse_u16, parse_u16_be, parse_u32, parse_u32_be, parse_u8, DecodeError,
    DefaultNla, EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};

use super::{
    gre_common::{
        IFLA_GRE_COLLECT_METADATA, IFLA_GRE_ENCAP_DPORT, IFLA_GRE_ENCAP_FLAGS,
        IFLA_GRE_ENCAP_LIMIT, IFLA_GRE_ENCAP_SPORT, IFLA_GRE_ENCAP_TYPE,
        IFLA_GRE_ERSPAN_DIR, IFLA_GRE_ERSPAN_HWID, IFLA_GRE_ERSPAN_INDEX,
        IFLA_GRE_ERSPAN_VER, IFLA_GRE_FLOWINFO, IFLA_GRE_FWMARK,
        IFLA_GRE_IFLAGS, IFLA_GRE_IKEY, IFLA_GRE_LINK, IFLA_GRE_LOCAL,
        IFLA_GRE_OFLAGS, IFLA_GRE_OKEY, IFLA_GRE_REMOTE, IFLA_GRE_TOS,
        IFLA_GRE_TTL,
    },
    ErSpanDir, GreEncapFlags, GreEncapType, GreIOFlags,
};
use crate::ip::parse_ipv6_addr;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoGre6 {
    Link(u32),
    IFlags(GreIOFlags),
    OFlags(GreIOFlags),
    IKey(u32),
    OKey(u32),
    Local(Ipv6Addr),
    Remote(Ipv6Addr),
    Ttl(u8),
    EncapLimit(u8),
    FlowLabel(u32),
    EncapType(GreEncapType),
    EncapFlags(GreEncapFlags),
    SourcePort(u16),
    DestinationPort(u16),
    CollectMetadata,
    FwMask(u32),
    Tos(u8),
    ErSpanIndex(u32),
    ErSpanVer(u8),
    ErSpanDir(ErSpanDir),
    ErSpanHwId(u16),
    Other(DefaultNla),
}

impl Nla for InfoGre6 {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Link(id) => {
                append_u32(out, *id);
                Ok(())
            }
            Self::IFlags(flags) | Self::OFlags(flags) => {
                append_u16_be(out, flags.bits());
                Ok(())
            }
            Self::IKey(key) | Self::OKey(key) => {
                append_u32_be(out, *key);
                Ok(())
            }
            Self::Local(ip) | Self::Remote(ip) => {
                append_bytes(out, &ip.octets());
                Ok(())
            }
            Self::Ttl(value) | Self::EncapLimit(value) => {
                out.push(*value);
                Ok(())
            }
            Self::EncapFlags(flags) => {
                append_u16(out, flags.bits());
                Ok(())
            }
            Self::FlowLabel(value) => {
                append_u32_be(out, *value);
                Ok(())
            }
            Self::EncapType(t) => {
                append_u16(out, t.into());
                Ok(())
            }
            Self::SourcePort(port) | Self::DestinationPort(port) => {
                append_u16_be(out, *port);
                Ok(())
            }
            Self::CollectMetadata => Ok(()),
            Self::FwMask(fw_mask) => {
                append_u32(out, *fw_mask);
                Ok(())
            }
            Self::Tos(value) => {
                out.push(*value);
                Ok(())
            }
            Self::ErSpanIndex(idx) => {
                append_u32(out, *idx);
                Ok(())
            }
            Self::ErSpanVer(v) => {
                out.push(*v);
                Ok(())
            }
            Self::ErSpanDir(v) => {
                out.push(v.into());
                Ok(())
            }
            Self::ErSpanHwId(id) => {
                append_u16(out, *id);
                Ok(())
            }
            Self::Other(nla) => {
                append_bytes(out, nla.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        <InfoGre6>::kind(self)
    }
}

impl InfoGre6 {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::Link(_) => IFLA_GRE_LINK,
            Self::IFlags(_) => IFLA_GRE_IFLAGS,
            Self::OFlags(_) => IFLA_GRE_OFLAGS,
            Self::IKey(_) => IFLA_GRE_IKEY,
            Self::OKey(_) => IFLA_GRE_OKEY,
            Self::Local(_) => IFLA_GRE_LOCAL,
            Self::Remote(_) => IFLA_GRE_REMOTE,
            Self::Ttl(_) => IFLA_GRE_TTL,
            Self::EncapLimit(_) => IFLA_GRE_ENCAP_LIMIT,
            Self::FlowLabel(_) => IFLA_GRE_FLOWINFO,
            Self::EncapType(_) => IFLA_GRE_ENCAP_TYPE,
            Self::EncapFlags(_) => IFLA_GRE_ENCAP_FLAGS,
            Self::SourcePort(_) => IFLA_GRE_ENCAP_SPORT,
            Self::DestinationPort(_) => IFLA_GRE_ENCAP_DPORT,
            Self::CollectMetadata => IFLA_GRE_COLLECT_METADATA,
            Self::FwMask(_) => IFLA_GRE_FWMARK,
            Self::Tos(_) => IFLA_GRE_TOS,
            Self::ErSpanIndex(_) => IFLA_GRE_ERSPAN_INDEX,
            Self::ErSpanVer(_) => IFLA_GRE_ERSPAN_VER,
            Self::ErSpanDir(_) => IFLA_GRE_ERSPAN_DIR,
            Self::ErSpanHwId(_) => IFLA_GRE_ERSPAN_HWID,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoGre6 {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_GRE_LINK => Self::Link(
                parse_u32(payload).context("invalid IFLA_GRE_LINK value")?,
            ),
            IFLA_GRE_IFLAGS => Self::IFlags(GreIOFlags::from_bits_retain(
                parse_u16_be(payload)
                    .context("invalid IFLA_GRE_IFLAGS value")?,
            )),
            IFLA_GRE_OFLAGS => Self::OFlags(GreIOFlags::from_bits_retain(
                parse_u16_be(payload)
                    .context("invalid IFLA_GRE_OFLAGS value")?,
            )),
            IFLA_GRE_IKEY => Self::IKey(
                parse_u32_be(payload).context("invalid IFLA_GRE_IKEY value")?,
            ),
            IFLA_GRE_OKEY => Self::OKey(
                parse_u32_be(payload).context("invalid IFLA_GRE_OKEY value")?,
            ),
            IFLA_GRE_LOCAL => Self::Local(
                parse_ipv6_addr(payload)
                    .context("invalid IFLA_GRE_LOCAL value")?,
            ),
            IFLA_GRE_REMOTE => Self::Remote(
                parse_ipv6_addr(payload)
                    .context("invalid IFLA_GRE_LOCAL value")?,
            ),
            IFLA_GRE_TTL => Self::Ttl(
                parse_u8(payload).context("invalid IFLA_GRE_TTL value")?,
            ),
            IFLA_GRE_ENCAP_LIMIT => Self::EncapLimit(
                parse_u8(payload)
                    .context("invalid IFLA_GRE_ENCAP_LIMIT value")?,
            ),
            IFLA_GRE_FLOWINFO => Self::FlowLabel(
                parse_u32_be(payload)
                    .context("invalid IFLA_GRE_FLOWINFO value")?,
            ),
            IFLA_GRE_ENCAP_TYPE => Self::EncapType(GreEncapType::from(
                parse_u16(payload)
                    .context("invalid IFLA_GRE_ENCAP_TYPE value")?,
            )),
            IFLA_GRE_ENCAP_FLAGS => {
                Self::EncapFlags(GreEncapFlags::from_bits_retain(
                    parse_u16(payload)
                        .context("invalid IFLA_GRE_ENCAP_FLAGS value")?,
                ))
            }
            IFLA_GRE_ENCAP_SPORT => Self::SourcePort(
                parse_u16_be(payload)
                    .context("invalid IFLA_GRE_ENCAP_SPORT value")?,
            ),
            IFLA_GRE_ENCAP_DPORT => Self::DestinationPort(
                parse_u16_be(payload)
                    .context("invalid IFLA_GRE_ENCAP_DPORT value")?,
            ),
            IFLA_GRE_COLLECT_METADATA => Self::CollectMetadata,
            IFLA_GRE_FWMARK => Self::FwMask(
                parse_u32(payload).context("invalid IFLA_GRE_FWMARK value")?,
            ),
            IFLA_GRE_TOS => Self::Tos(
                parse_u8(payload).context("invalid IFLA_GRE_TOS value")?,
            ),
            IFLA_GRE_ERSPAN_INDEX => Self::ErSpanIndex(
                parse_u32(payload)
                    .context("invalid IFLA_GRE_ERSPAN_INDEX value")?,
            ),
            IFLA_GRE_ERSPAN_VER => Self::ErSpanVer(
                parse_u8(payload)
                    .context("invalid IFLA_GRE_ERSPAN_VER value")?,
            ),
            IFLA_GRE_ERSPAN_DIR => Self::ErSpanDir(ErSpanDir::from(
                parse_u8(payload)
                    .context("invalid IFLA_GRE_ERSPAN_DIR value")?,
            )),
            IFLA_GRE_ERSPAN_HWID => Self::ErSpanHwId(
                parse_u16(payload)
                    .context("invalid IFLA_GRE_ERSPAN_HWID value")?,
            ),
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for ip6gre")
            })?),
        })
    }
}
