// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    address::{
        freebsd::{FreeBsdAddressAttribute, IfaFlags},
        AddressAttribute, AddressFlags, AddressHeader, AddressHeaderFlags,
        AddressMessage, AddressMessageBuffer, AddressScope,
    },
    AddressFamily,
};

#[test]
fn test_freebsd_address_vhid() {
    let raw: [u8; _] = [
        2, 24, 0, 0, 2, 0, 0, 0, 8, 0, 1, 0, 192, 168, 56, 120, 8, 0, 2, 0,
        192, 168, 56, 120, 8, 0, 4, 0, 192, 168, 56, 255, 8, 0, 3, 0, 104, 110,
        48, 0, 8, 0, 8, 0, 0, 0, 0, 0, 12, 0, 11, 0, 8, 0, 1, 0, 10, 0, 0, 0,
    ];
    let expected = AddressMessage {
        header: AddressHeader {
            family: AddressFamily::Inet,
            prefix_len: 24,
            flags: AddressHeaderFlags::empty(),
            scope: AddressScope::Universe,
            index: 2,
        },
        attributes: vec![
            AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
                192, 168, 56, 120,
            ))),
            AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(
                192, 168, 56, 120,
            ))),
            AddressAttribute::Broadcast(Ipv4Addr::new(192, 168, 56, 255)),
            AddressAttribute::Label("hn0".to_string()),
            AddressAttribute::Flags(AddressFlags::empty()),
            AddressAttribute::FreeBSD(vec![FreeBsdAddressAttribute::Vhid(10)]),
        ],
    };

    assert_eq!(
        expected,
        AddressMessage::parse(&AddressMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

#[test]
fn test_freebsd_address_unspecific() {
    let raw: [u8; 44] = [
        2, 8, 0, 254, 1, 0, 0, 0, 8, 0, 1, 0, 127, 0, 0, 1, 8, 0, 2, 0, 127, 0,
        0, 1, 8, 0, 3, 0, 108, 111, 48, 0, 8, 0, 8, 0, 0, 0, 0, 0, 4, 0, 11, 0,
    ];
    let expected = AddressMessage {
        header: AddressHeader {
            family: AddressFamily::Inet,
            prefix_len: 8,
            flags: AddressHeaderFlags::empty(),
            scope: AddressScope::Host,
            index: 1,
        },
        attributes: vec![
            AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            AddressAttribute::Label("lo0".to_string()),
            AddressAttribute::Flags(AddressFlags::empty()),
            AddressAttribute::FreeBSD(vec![]),
        ],
    };

    assert_eq!(
        expected,
        AddressMessage::parse(&AddressMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
