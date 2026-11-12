// SPDX-License-Identifier: MIT
use std::net::Ipv6Addr;

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    prefix::{
        attribute::PrefixAttribute, cache_info::CacheInfo, PrefixFlags,
        PrefixHeader, PrefixMessage,
    },
    AddressFamily,
};

// Kernel emitted RTM_NEWPREFIX captured by joining RTNLGRP_IPV6_PREFIX
// while running `test_env_mozim`, which starts dnsmasq with `--enable-ra`.
#[cfg(not(target_endian = "big"))]
#[test]
fn test_new_prefix() {
    #[rustfmt::skip]
    let data = vec![
        // prefixmsg
        // AF_INET6 + padding
        0x0a, 0x00, 0x00, 0x00,
        // ifindex
        0x60, 0x05, 0x00, 0x00,
        // type, prefix length, flags, padding
        0x03, 0x40, 0xc0, 0x00,
        // PREFIX_ADDRESS attribute
        0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0a, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // PREFIX_CACHEINFO attribute
        0x0c, 0x00, 0x02, 0x00,
        0x08, 0x07, 0x00, 0x00,
        0x08, 0x07, 0x00, 0x00,
    ];
    let actual = PrefixMessage::parse(&data).expect("Generated PrefixMessage");

    let expected = PrefixMessage {
        header: PrefixHeader {
            prefix_family: AddressFamily::Inet6,
            ifindex: 0x0560,
            prefix_type: 3,
            prefix_len: 64,
            flags: PrefixFlags::OnLink | PrefixFlags::Autonomous,
        },
        attributes: vec![
            PrefixAttribute::Address(
                "2001:db8:a::".parse::<Ipv6Addr>().expect("Ipv6Addr"),
            ),
            PrefixAttribute::CacheInfo(CacheInfo {
                preferred_time: 1800,
                valid_time: 1800,
            }),
        ],
    };

    assert_eq!(expected, actual);

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(data, buf);
}
