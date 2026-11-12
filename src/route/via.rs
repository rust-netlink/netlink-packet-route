// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    ip::{parse_ipv4_addr, parse_ipv6_addr},
    AddressFamily,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
// Kernel representative is `struct rtvia`
// In Linux kernel 6.18, MPLS route also use `AF_PACKET`
// and MPLS route. Even the MPLS is using AF_PACKET, so we cannot simply
// treat `RouteVia` as `IpAddr`.
pub enum RouteVia {
    Inet(Ipv4Addr),
    Inet6(Ipv6Addr),
    #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
    Packet(Vec<u8>),
    Other((AddressFamily, Vec<u8>)),
}

const RTVIA_LEN: usize = 2;

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
pub(crate) struct RouteViaBuffer {
    address_family: u16,
}

impl RouteVia {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, address) =
            RouteViaBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), RTVIA_LEN)
            })?;
        let address_family: AddressFamily = (raw.address_family as u8).into();
        Ok(match address_family {
            AddressFamily::Inet => Self::Inet(parse_ipv4_addr(address)?),
            AddressFamily::Inet6 => Self::Inet6(parse_ipv6_addr(address)?),
            #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
            AddressFamily::Packet => Self::Packet(address.to_vec()),
            _ => Self::Other((address_family, address.to_vec())),
        })
    }
}

impl Emitable for RouteVia {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let address_family = match self {
            Self::Inet(_) => AddressFamily::Inet,
            Self::Inet6(_) => AddressFamily::Inet6,
            #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
            Self::Packet(_) => AddressFamily::Packet,
            Self::Other((f, _)) => *f,
        };
        let raw = RouteViaBuffer {
            address_family: u16::from(u8::from(address_family)),
        };
        append_bytes(out, raw.as_bytes());
        match self {
            Self::Inet(ip) => append_bytes(out, &ip.octets()),
            Self::Inet6(ip) => append_bytes(out, &ip.octets()),
            #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
            Self::Packet(a) => append_bytes(out, a),
            Self::Other((_, a)) => append_bytes(out, a),
        }
        Ok(())
    }
}

impl From<Ipv4Addr> for RouteVia {
    fn from(v: Ipv4Addr) -> Self {
        Self::Inet(v)
    }
}

impl From<Ipv6Addr> for RouteVia {
    fn from(v: Ipv6Addr) -> Self {
        Self::Inet6(v)
    }
}

impl From<IpAddr> for RouteVia {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => Self::Inet(ipv4),
            IpAddr::V6(ipv6) => Self::Inet6(ipv6),
        }
    }
}
