// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, NlaBuffer, Parseable};

use crate::{
    rule::{RuleAction, RuleAttribute, RuleHeader, RuleMessage},
    AddressFamily,
};

#[test]
fn test_ipv4_tun_id() {
    let raw = vec![
        0x02, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];
    let expected = RuleMessage {
        header: RuleHeader {
            family: AddressFamily::Inet,
            table: 10,
            action: RuleAction::ToTable,
            ..Default::default()
        },
        attributes: vec![
            RuleAttribute::Priority(1000),
            RuleAttribute::TunId(0x1122334455667788),
        ],
    };

    assert_eq!(RuleMessage::parse(&raw).unwrap(), expected);

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

#[test]
fn test_ipv6_tun_id() {
    let raw = vec![
        0x0a, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x06, 0x00, 0xe9, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let expected = RuleMessage {
        header: RuleHeader {
            family: AddressFamily::Inet6,
            table: 10,
            action: RuleAction::ToTable,
            ..Default::default()
        },
        attributes: vec![
            RuleAttribute::Priority(1001),
            RuleAttribute::TunId(u64::MAX),
        ],
    };

    assert_eq!(RuleMessage::parse(&raw).unwrap(), expected);

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

#[test]
fn test_tun_id_invalid_length() {
    let raw = [0x08, 0x00, 0x0c, 0x00, 0x11, 0x22, 0x33, 0x44];
    let nla = NlaBuffer::new_checked(&raw[..]).unwrap();

    assert!(RuleAttribute::parse(&nla).is_err());
}
