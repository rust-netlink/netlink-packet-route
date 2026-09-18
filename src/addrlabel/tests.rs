// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    addrlabel::{AddrLabelAttribute, AddrLabelHeader, AddrLabelMessage},
    AddressFamily,
};

// iproute2 request, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel add prefix 2001:db8::/64 label 5
#[test]
fn test_addrlabel_add_request() {
    let raw = vec![
        0x0a, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 64,
            flags: 0,
            index: 0,
            sequence: 0,
        },
        attributes: vec![
            AddrLabelAttribute::Label(5),
            AddrLabelAttribute::Address(IpAddr::V6(
                "2001:db8::".parse().unwrap(),
            )),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// iproute2 request, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel add prefix 2001:db8:1::/64 dev lo label 7
#[test]
fn test_addrlabel_add_request_with_dev() {
    let raw = vec![
        0x0a, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 64,
            flags: 0,
            index: 1,
            sequence: 0,
        },
        attributes: vec![
            AddrLabelAttribute::Label(7),
            AddrLabelAttribute::Address(IpAddr::V6(
                "2001:db8:1::".parse().unwrap(),
            )),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// iproute2 request, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel del prefix 2001:db8::/64 label 5
#[test]
fn test_addrlabel_delete_request() {
    let raw = vec![
        0x0a, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 64,
            flags: 0,
            index: 0,
            sequence: 0,
        },
        attributes: vec![
            AddrLabelAttribute::Label(5),
            AddrLabelAttribute::Address(IpAddr::V6(
                "2001:db8::".parse().unwrap(),
            )),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// iproute2 request, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel list
#[test]
fn test_addrlabel_dump_request() {
    let raw = vec![
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 0,
            flags: 0,
            index: 0,
            sequence: 0,
        },
        attributes: vec![],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup
//      ip addrlabel add prefix 2001:db8::/64 label 5
//      ip addrlabel add prefix 2001:db8:1::/64 dev lo label 7
// linux kernel reply, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel list
#[test]
fn test_addrlabel_dump_reply_loopback() {
    let raw = vec![
        0x0a, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 128,
            flags: 0,
            index: 0,
            sequence: 12,
        },
        attributes: vec![
            AddrLabelAttribute::Address(IpAddr::V6("::1".parse().unwrap())),
            AddrLabelAttribute::Label(0),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// linux kernel reply, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel list
#[test]
fn test_addrlabel_dump_reply_ipv4_mapped() {
    let raw = vec![
        0x0a, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x04, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 96,
            flags: 0,
            index: 0,
            sequence: 12,
        },
        attributes: vec![
            AddrLabelAttribute::Address(IpAddr::V6(
                "::ffff:0.0.0.0".parse().unwrap(),
            )),
            AddrLabelAttribute::Label(4),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// linux kernel reply, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel list
#[test]
fn test_addrlabel_dump_reply_with_dev() {
    let raw = vec![
        0x0a, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x07, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 64,
            flags: 0,
            index: 1,
            sequence: 12,
        },
        attributes: vec![
            AddrLabelAttribute::Address(IpAddr::V6(
                "2001:db8:1::".parse().unwrap(),
            )),
            AddrLabelAttribute::Label(7),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// linux kernel reply, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel list
#[test]
fn test_addrlabel_dump_reply_added() {
    let raw = vec![
        0x0a, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x05, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 64,
            flags: 0,
            index: 0,
            sequence: 12,
        },
        attributes: vec![
            AddrLabelAttribute::Address(IpAddr::V6(
                "2001:db8::".parse().unwrap(),
            )),
            AddrLabelAttribute::Label(5),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// linux kernel reply, wireshark capture(netlink message header removed) of
// nlmon against command:
//      ip addrlabel list
#[test]
fn test_addrlabel_dump_reply_default() {
    let raw = vec![
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x00,
    ];

    let expected = AddrLabelMessage {
        header: AddrLabelHeader {
            family: AddressFamily::Inet6,
            prefix_len: 0,
            flags: 0,
            index: 0,
            sequence: 12,
        },
        attributes: vec![
            AddrLabelAttribute::Address(IpAddr::V6("::".parse().unwrap())),
            AddrLabelAttribute::Label(1),
        ],
    };

    assert_eq!(expected, AddrLabelMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
