// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        flags::RouteFlags, RouteAttribute, RouteHeader, RouteMessage,
        RouteProtocol, RouteScope, RouteType,
    },
    AddressFamily,
};

// nlmon capture(netlink message header removed) against command:
//   ip route add 10.6.0.0/16 nhid 42
#[test]
fn test_ipv4_route_nh_id() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x06, 0x00, 0x00, 0x08, 0x00, 0x1e, 0x00,
        0x2a, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: 16,
            source_prefix_length: 0,
            tos: 0,
            table: 254,
            protocol: RouteProtocol::Boot,
            scope: RouteScope::Universe,
            kind: RouteType::Unicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Destination(Ipv4Addr::new(10, 6, 0, 0).into()),
            RouteAttribute::NhId(42),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
