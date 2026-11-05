// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};

use crate::{
    ip::{parse_ipv4_addr, parse_ipv6_addr},
    AddressFamily,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NeighbourAddress {
    Inet(Ipv4Addr),
    Inet6(Ipv6Addr),
    Other(Vec<u8>),
}

#[allow(dead_code)]
impl NeighbourAddress {
    pub(crate) fn parse_with_param(
        address_family: AddressFamily,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        Ok(match address_family {
            AddressFamily::Inet => Self::Inet(parse_ipv4_addr(payload)?),
            AddressFamily::Inet6 => Self::Inet6(parse_ipv6_addr(payload)?),
            _ => Self::Other(payload.to_vec()),
        })
    }
}

impl Emitable for NeighbourAddress {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Inet(v) => append_bytes(out, &v.octets()),
            Self::Inet6(v) => append_bytes(out, &v.octets()),
            Self::Other(v) => append_bytes(out, v.as_slice()),
        }
        Ok(())
    }
}

impl From<IpAddr> for NeighbourAddress {
    fn from(v: IpAddr) -> Self {
        match v {
            IpAddr::V4(a) => a.into(),
            IpAddr::V6(a) => a.into(),
        }
    }
}

impl From<Ipv4Addr> for NeighbourAddress {
    fn from(v: Ipv4Addr) -> Self {
        Self::Inet(v)
    }
}

impl From<Ipv6Addr> for NeighbourAddress {
    fn from(v: Ipv6Addr) -> Self {
        Self::Inet6(v)
    }
}
