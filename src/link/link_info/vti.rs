// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{
    append_bytes, append_u32, append_u32_be, parse_u32, parse_u32_be,
    DecodeError, DefaultNla, EncodeError, ErrorContext, Nla, NlaBuffer,
    Parseable,
};

use crate::ip::parse_ip_addr;

const IFLA_VTI_LINK: u16 = 1;
const IFLA_VTI_IKEY: u16 = 2;
const IFLA_VTI_OKEY: u16 = 3;
const IFLA_VTI_LOCAL: u16 = 4;
const IFLA_VTI_REMOTE: u16 = 5;
const IFLA_VTI_FWMARK: u16 = 6;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoVti {
    Link(u32),
    IKey(u32),
    OKey(u32),
    Local(IpAddr),
    Remote(IpAddr),
    FwMark(u32),
    Other(DefaultNla),
}

impl Nla for InfoVti {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Local(value) | Self::Remote(value) => match value {
                IpAddr::V4(ipv4) => append_bytes(out, &ipv4.octets()),
                IpAddr::V6(ipv6) => append_bytes(out, &ipv6.octets()),
            },
            Self::Link(value) | Self::FwMark(value) => append_u32(out, *value),
            Self::IKey(value) | Self::OKey(value) => append_u32_be(out, *value),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Link(_) => IFLA_VTI_LINK,
            Self::IKey(_) => IFLA_VTI_IKEY,
            Self::OKey(_) => IFLA_VTI_OKEY,
            Self::Local(_) => IFLA_VTI_LOCAL,
            Self::Remote(_) => IFLA_VTI_REMOTE,
            Self::FwMark(_) => IFLA_VTI_FWMARK,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoVti {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VTI_LINK => Self::Link(
                parse_u32(payload).context("invalid IFLA_VTI_LINK value")?,
            ),
            IFLA_VTI_IKEY => Self::IKey(
                parse_u32_be(payload).context("invalid IFLA_VTI_IKEY value")?,
            ),
            IFLA_VTI_OKEY => Self::OKey(
                parse_u32_be(payload).context("invalid IFLA_VTI_OKEY value")?,
            ),
            IFLA_VTI_LOCAL => {
                let ip =
                    parse_ip_addr(payload).context("invalid IFLA_VTI_LOCAL")?;
                Self::Local(ip)
            }
            IFLA_VTI_REMOTE => {
                let ip = parse_ip_addr(payload)
                    .context("invalid IFLA_VTI_REMOTE")?;
                Self::Remote(ip)
            }
            IFLA_VTI_FWMARK => Self::FwMark(
                parse_u32(payload).context("invalid IFLA_VTI_FWMARK value")?,
            ),
            kind => {
                Self::Other(DefaultNla::parse(buf).with_context(|| {
                    format!("unknown NLA type {kind} for vti")
                })?)
            }
        })
    }
}
