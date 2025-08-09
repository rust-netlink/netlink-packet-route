// SPDX-License-Identifier: MIT

use std::net::Ipv6Addr;

use crate::ip::parse_ipv6_addr;
use anyhow::Context;
use byteorder::{ByteOrder, NetworkEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16_be, parse_u32_be, parse_u8},
    DecodeError, Parseable,
};

use super::{
    GreEncapFlags, GreEncapType, GreIOFlags, IFLA_GRE_COLLECT_METADATA,
    IFLA_GRE_ENCAP_DPORT, IFLA_GRE_ENCAP_FLAGS, IFLA_GRE_ENCAP_LIMIT,
    IFLA_GRE_ENCAP_SPORT, IFLA_GRE_ENCAP_TYPE, IFLA_GRE_FLAGS,
    IFLA_GRE_FLOWINFO, IFLA_GRE_FWMARK, IFLA_GRE_IFLAGS, IFLA_GRE_IKEY,
    IFLA_GRE_LOCAL, IFLA_GRE_OFLAGS, IFLA_GRE_OKEY, IFLA_GRE_REMOTE,
    IFLA_GRE_TTL, IFLA_GRE_UNSPEC,
};

pub use InfoGreTun6 as InfoGreTap6;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoGreTun6 {
    Unspec,
    //Link,
    IFlags(GreIOFlags),
    OFlags(GreIOFlags),
    IKey(u32),
    OKey(u32),
    Local(Ipv6Addr),
    Remote(Ipv6Addr),
    Ttl(u8),
    EncapLimit(u8),
    FlowLabel(u32),
    Flags(u32), // TODO: expose IP6_TNL_F_* flags
    EncapType(GreEncapType),
    EncapFlags(GreEncapFlags),
    SourcePort(u16),
    DestinationPort(u16),
    CollectMetadata,
    FwMask(u32),
    Other(DefaultNla),
}

impl Nla for InfoGreTun6 {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspec => 0,
            Self::IFlags(_) | Self::OFlags(_) => const { size_of::<u16>() },
            Self::IKey(_) | Self::OKey(_) => const { size_of::<u32>() },
            Self::Local(_) | Self::Remote(_) => const { size_of::<Ipv6Addr>() },
            Self::Ttl(_) | Self::EncapLimit(_) => const { size_of::<u8>() },
            Self::FlowLabel(_) | Self::Flags(_) => const { size_of::<u32>() },
            Self::EncapType(_) => const { size_of::<u16>() },
            Self::EncapFlags(_) => const { size_of::<u16>() },
            Self::SourcePort(_) | Self::DestinationPort(_) => {
                const { size_of::<u16>() }
            }
            Self::CollectMetadata => 0,
            Self::FwMask(_) => const { size_of::<u32>() },
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspec => {}
            Self::IFlags(flags) | Self::OFlags(flags) => {
                NetworkEndian::write_u16(buffer, flags.bits())
            }
            Self::IKey(key) | Self::OKey(key) => {
                NetworkEndian::write_u32(buffer, *key)
            }
            Self::Local(ip) | Self::Remote(ip) => {
                buffer.copy_from_slice(&ip.octets());
            }
            Self::Ttl(value) | Self::EncapLimit(value) => buffer[0] = *value,
            Self::EncapFlags(flags) => {
                NetworkEndian::write_u16(buffer, flags.bits())
            }
            Self::FlowLabel(value) | Self::Flags(value) => {
                NetworkEndian::write_u32(buffer, *value)
            }
            Self::EncapType(t) => NetworkEndian::write_u16(buffer, t.into()),
            Self::SourcePort(port) | Self::DestinationPort(port) => {
                NetworkEndian::write_u16(buffer, *port)
            }
            Self::CollectMetadata => {}
            Self::FwMask(fw_mask) => NetworkEndian::write_u32(buffer, *fw_mask),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => IFLA_GRE_UNSPEC,
            Self::IFlags(_) => IFLA_GRE_IFLAGS,
            Self::OFlags(_) => IFLA_GRE_OFLAGS,
            Self::IKey(_) => IFLA_GRE_IKEY,
            Self::OKey(_) => IFLA_GRE_OKEY,
            Self::Local(_) => IFLA_GRE_LOCAL,
            Self::Remote(_) => IFLA_GRE_REMOTE,
            Self::Ttl(_) => IFLA_GRE_TTL,
            Self::EncapLimit(_) => IFLA_GRE_ENCAP_LIMIT,
            Self::FlowLabel(_) => IFLA_GRE_FLOWINFO,
            Self::Flags(_) => IFLA_GRE_FLAGS,
            Self::EncapType(_) => IFLA_GRE_ENCAP_TYPE,
            Self::EncapFlags(_) => IFLA_GRE_ENCAP_FLAGS,
            Self::SourcePort(_) => IFLA_GRE_ENCAP_SPORT,
            Self::DestinationPort(_) => IFLA_GRE_ENCAP_DPORT,
            Self::CollectMetadata => IFLA_GRE_COLLECT_METADATA,
            Self::FwMask(_) => IFLA_GRE_FWMARK,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoGreTun6 {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_GRE_UNSPEC => Self::Unspec,
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
            IFLA_GRE_FLAGS => Self::Flags(
                parse_u32_be(payload)
                    .context("invalid IFLA_GRE_FLAGS value")?,
            ),
            IFLA_GRE_ENCAP_TYPE => Self::EncapType(GreEncapType::from(
                parse_u16_be(payload)
                    .context("invalid IFLA_GRE_ENCAP_TYPE value")?,
            )),
            IFLA_GRE_ENCAP_FLAGS => {
                Self::EncapFlags(GreEncapFlags::from_bits_retain(
                    parse_u16_be(payload)
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
                parse_u32_be(payload)
                    .context("invalid IFLA_GRE_FWMARK value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind} for ip6gre"))?,
            ),
        })
    }
}
