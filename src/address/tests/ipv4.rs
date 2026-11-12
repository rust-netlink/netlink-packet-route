// SPDX-License-Identifier: MIT
use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    address::{
        AddressAttribute, AddressFlags, AddressHeader, AddressHeaderFlags,
        AddressMessage, AddressScope, CacheInfo,
    },
    AddressFamily,
};

// nlmon capture (netlink header removed) of the kernel `RTM_NEWADDR`
// reply on Linux 7.2.14 after:
//
//      ip link add nltest0 type dummy
//      ip link set nltest0 up
//      ip addr add 192.0.2.10/24 broadcast 192.0.2.255 dev nltest0
//      ip addr show dev nltest0
//
// test data are using hard coded little endian byte order, not for big-endian
#[cfg(not(target_endian = "big"))]
#[test]
fn test_ipv4_get_broadcast_address() {
    let raw = vec![
        0x02, 0x18, 0x80, 0x00, 0x63, 0x05, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0xc0, 0x00, 0x02, 0x0a, 0x08, 0x00, 0x02, 0x00, 0xc0, 0x00, 0x02, 0x0a,
        0x08, 0x00, 0x04, 0x00, 0xc0, 0x00, 0x02, 0xff, 0x0c, 0x00, 0x03, 0x00,
        0x6e, 0x6c, 0x74, 0x65, 0x73, 0x74, 0x30, 0x00, 0x08, 0x00, 0x08, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x14, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x4e, 0xc3, 0x9b, 0x02, 0x4e, 0xc3, 0x9b, 0x02,
    ];

    let expected = AddressMessage {
        header: AddressHeader {
            family: AddressFamily::Inet,
            prefix_len: 24,
            flags: AddressHeaderFlags::Permanent,
            scope: AddressScope::Universe,
            index: 1379,
        },
        attributes: vec![
            AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            AddressAttribute::Broadcast(Ipv4Addr::new(192, 0, 2, 255)),
            AddressAttribute::Label("nltest0".to_string()),
            AddressAttribute::Flags(AddressFlags::Permanent),
            AddressAttribute::CacheInfo(CacheInfo {
                ifa_preferred: u32::MAX,
                ifa_valid: u32::MAX,
                cstamp: 43762510,
                tstamp: 43762510,
            }),
        ],
    };

    assert_eq!(expected, AddressMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();

    expected.emit(&mut buf).unwrap();

    assert_eq!(buf, raw);
}

#[test]
fn test_ipv4_get_loopback_address() {
    let raw = vec![
        0x02, 0x08, 0x80, 0xfe, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00, 0x7f, 0x00, 0x00, 0x01,
        0x07, 0x00, 0x03, 0x00, 0x6c, 0x6f, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x14, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x9c, 0x00, 0x00, 0x00, 0x9c, 0x00, 0x00, 0x00,
    ];

    let expected = AddressMessage {
        header: AddressHeader {
            family: AddressFamily::Inet,
            prefix_len: 8,
            flags: AddressHeaderFlags::Permanent,
            scope: AddressScope::Host,
            index: 1,
        },
        attributes: vec![
            AddressAttribute::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            AddressAttribute::Local(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            AddressAttribute::Label("lo".to_string()),
            AddressAttribute::Flags(AddressFlags::Permanent),
            AddressAttribute::CacheInfo(CacheInfo {
                ifa_preferred: u32::MAX,
                ifa_valid: u32::MAX,
                cstamp: 156,
                tstamp: 156,
            }),
        ],
    };

    assert_eq!(expected, AddressMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();

    expected.emit(&mut buf).unwrap();

    assert_eq!(buf, raw);
}
