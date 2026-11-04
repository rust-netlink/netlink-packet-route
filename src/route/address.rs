// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};

use crate::{
    ip::{parse_ipv4_addr, parse_ipv6_addr},
    route::MplsLabel,
    AddressFamily,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteAddress {
    Inet(Ipv4Addr),
    Inet6(Ipv6Addr),
    Mpls(MplsLabel),
    Other(Vec<u8>),
}

impl From<IpAddr> for RouteAddress {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => Self::Inet(ipv4),
            IpAddr::V6(ipv6) => Self::Inet6(ipv6),
        }
    }
}

impl RouteAddress {
    pub(crate) fn parse(
        address_family: AddressFamily,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        Ok(match address_family {
            AddressFamily::Inet => Self::Inet(parse_ipv4_addr(payload)?),
            AddressFamily::Inet6 => Self::Inet6(parse_ipv6_addr(payload)?),
            #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
            AddressFamily::Mpls => Self::Mpls(MplsLabel::parse(payload)?),
            _ => Self::Other(payload.to_vec()),
        })
    }
}

impl Emitable for RouteAddress {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Inet(v) => append_bytes(out, &v.octets()),
            Self::Inet6(v) => append_bytes(out, &v.octets()),
            Self::Mpls(v) => v.emit(out)?,
            Self::Other(v) => append_bytes(out, v.as_slice()),
        }
        Ok(())
    }
}

impl From<Ipv4Addr> for RouteAddress {
    fn from(v: Ipv4Addr) -> Self {
        Self::Inet(v)
    }
}

impl From<Ipv6Addr> for RouteAddress {
    fn from(v: Ipv6Addr) -> Self {
        Self::Inet6(v)
    }
}

impl From<MplsLabel> for RouteAddress {
    fn from(v: MplsLabel) -> Self {
        Self::Mpls(v)
    }
}
