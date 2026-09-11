// SPDX-License-Identifier: MIT

use std::{net::Ipv4Addr, str::FromStr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        RouteAttribute, RouteFlags, RouteHeader, RouteIpTunnel,
        RouteIpTunnelFlags, RouteLwEnCapType, RouteLwTunnelEncap,
        RouteMessage, RouteProtocol, RouteScope, RouteType,
    },
    AddressFamily,
};

// Setup:
//      ip link add d0 type dummy
//      ip link set d0 up
//      ip route add 10.115.0.0/16 encap ip id 200 dst 10.0.0.3 \
//          src 10.0.0.1 ttl 64 tos 8 key csum dev d0
// nlmon capture(netlink message header removed) against command:
//      ip route show 10.115.0.0/16
#[test]
fn test_ip_tunnel() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x0a, 0x73, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00,
        0x38, 0x00, 0x16, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xc8, 0x08, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x03,
        0x08, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x05, 0x00, 0x05, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x06, 0x00, 0x00, 0x05, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00,
        0x02, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: 16,
            source_prefix_length: 0,
            tos: 0,
            table: 254,
            protocol: RouteProtocol::Boot,
            scope: RouteScope::Link,
            kind: RouteType::Unicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Table(254),
            RouteAttribute::Destination(
                Ipv4Addr::from_str("10.115.0.0").unwrap().into(),
            ),
            RouteAttribute::Oif(11),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(200)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Destination(
                    Ipv4Addr::from_str("10.0.0.3").unwrap(),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Source(
                    Ipv4Addr::from_str("10.0.0.1").unwrap(),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Tos(8)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Ttl(64)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Flags(
                    RouteIpTunnelFlags::Key | RouteIpTunnelFlags::Checksum,
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ip),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
