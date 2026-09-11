// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        flags::RouteFlags, RouteAddress, RouteAttribute, RouteHeader,
        RouteMessage, RouteProtocol, RouteScope, RouteType,
    },
    AddressFamily,
};

// nlmon capture(netlink message header removed) against command:
//   ip route get 10.0.0.2 ipproto tcp sport 100 dport 200
#[test]
fn test_ipv4_route_get_ip_proto_ports() {
    let raw = vec![
        0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x02, 0x05, 0x00, 0x1b, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x1c, 0x00, 0x00, 0x64, 0x00, 0x00,
        0x06, 0x00, 0x1d, 0x00, 0x00, 0xc8, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: 32,
            source_prefix_length: 0,
            tos: 0,
            table: 0,
            protocol: RouteProtocol::Unspec,
            scope: RouteScope::Universe,
            kind: RouteType::Unspec,
            flags: RouteFlags::LookupTable,
        },
        attributes: vec![
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(
                10, 0, 0, 2,
            ))),
            RouteAttribute::IpProto(6),
            RouteAttribute::Sport(100),
            RouteAttribute::Dport(200),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// nlmon capture(netlink message header removed) against command:
//   ip -6 route get 2001:db8::2 ipproto tcp sport 100 dport 200 flowlabel 4660
#[test]
fn test_ipv6_route_get_ip_proto_ports_flowlabel() {
    let raw = vec![
        0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x00, 0x1b, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x1c, 0x00, 0x00, 0x64, 0x00, 0x00,
        0x06, 0x00, 0x1d, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x08, 0x00, 0x1f, 0x00,
        0x00, 0x00, 0x12, 0x34,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet6,
            destination_prefix_length: 128,
            source_prefix_length: 0,
            tos: 0,
            table: 0,
            protocol: RouteProtocol::Unspec,
            scope: RouteScope::Universe,
            kind: RouteType::Unspec,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Destination(RouteAddress::Inet6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0002,
            ))),
            RouteAttribute::IpProto(6),
            RouteAttribute::Sport(100),
            RouteAttribute::Dport(200),
            RouteAttribute::Flowlabel(0x1234),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
