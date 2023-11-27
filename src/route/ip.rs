// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_utils::DecodeError;

pub(crate) const IPV4_ADDR_LEN: usize = 4;
pub(crate) const IPV6_ADDR_LEN: usize = 16;

pub(crate) fn parse_ipv4_addr(raw: &[u8]) -> Result<Ipv4Addr, DecodeError> {
    if raw.len() == IPV4_ADDR_LEN {
        Ok(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    } else {
        Err(DecodeError::from(format!(
            "Invalid u8 array length {}, expecting \
            {IPV4_ADDR_LEN} for IPv4 address, got {:?}",
            raw.len(),
            raw,
        )))
    }
}

pub(crate) fn parse_ipv6_addr(raw: &[u8]) -> Result<Ipv6Addr, DecodeError> {
    if raw.len() == IPV6_ADDR_LEN {
        let mut data = [0u8; IPV6_ADDR_LEN];
        data.copy_from_slice(raw);
        Ok(Ipv6Addr::from(data))
    } else {
        Err(DecodeError::from(format!(
            "Invalid u8 array length {}, expecting {IPV6_ADDR_LEN} \
            for IPv6 address, got {:?}",
            raw.len(),
            raw,
        )))
    }
}

pub(crate) fn emit_ip_to_buffer(ip: &IpAddr, buffer: &mut [u8]) {
    match ip {
        IpAddr::V4(ip) => buffer.copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => buffer.copy_from_slice(&ip.octets()),
    }
}
