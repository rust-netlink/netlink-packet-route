// SPDX-License-Identifier: MIT

use std::{net::Ipv6Addr, str::FromStr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        RouteAttribute, RouteCacheInfo, RouteFlags, RouteHeader,
        RouteLwEnCapType, RouteLwTunnelEncap, RouteMessage, RoutePreference,
        RouteProtocol, RouteRplIpTunnel, RouteScope, RouteType, RplSrh,
    },
    AddressFamily,
};

// Setup:
//      ip link add d0 type dummy
//      ip link set d0 up
//      ip -6 route add 2001:db8:6::/64 \
//          encap rpl segs 2001:db8::2,2001:db8::3 dev d0
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show 2001:db8:6::/64
#[test]
fn test_rpl_tunnel() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x30, 0x00, 0x16, 0x00,
        0x2c, 0x00, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x15, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x24, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet6,
            destination_prefix_length: 64,
            source_prefix_length: 0,
            tos: 0,
            table: 254,
            protocol: RouteProtocol::Boot,
            scope: RouteScope::Universe,
            kind: RouteType::Unicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Table(254),
            RouteAttribute::Destination(
                Ipv6Addr::from_str("2001:db8:6::").unwrap().into(),
            ),
            RouteAttribute::Priority(1024),
            RouteAttribute::Oif(11),
            RouteAttribute::Encap(vec![RouteLwTunnelEncap::Rpl(
                RouteRplIpTunnel::Srh(RplSrh {
                    next_header: 0,
                    routing_type: 3,
                    segments_left: 2,
                    cmpri: 0,
                    cmpre: 0,
                    pad: 0,
                    segments: vec![
                        Ipv6Addr::from_str("2001:db8::3").unwrap(),
                        Ipv6Addr::from_str("2001:db8::2").unwrap(),
                    ],
                }),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Rpl),
            RouteAttribute::CacheInfo(RouteCacheInfo {
                clntref: 0,
                last_use: 0,
                expires: 0,
                error: 0,
                used: 0,
                id: 0,
                ts: 0,
                ts_age: 0,
            }),
            RouteAttribute::Preference(RoutePreference::Medium),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // The kernel does not set `NLA_F_NESTED` on `RTA_ENCAP` in dumps while
    // the emitted message carries the flag required by the kernel.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// nlmon capture(netlink message header removed) against command:
//   ip -6 route add 2001:db8:90::/64 \
//       encap rpl segs 2001:db8::2,2001:db8::3 dev d0
// The `NLA_F_NESTED` flag of `RTA_ENCAP` is only present in the request.
#[test]
fn test_rpl_tunnel_request() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x90, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x16, 0x80,
        0x2c, 0x00, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x15, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet6,
            destination_prefix_length: 64,
            source_prefix_length: 0,
            tos: 0,
            table: 254,
            protocol: RouteProtocol::Boot,
            scope: RouteScope::Universe,
            kind: RouteType::Unicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Destination(
                Ipv6Addr::from_str("2001:db8:90::").unwrap().into(),
            ),
            RouteAttribute::Encap(vec![RouteLwTunnelEncap::Rpl(
                RouteRplIpTunnel::Srh(RplSrh {
                    next_header: 0,
                    routing_type: 3,
                    segments_left: 2,
                    cmpri: 0,
                    cmpre: 0,
                    pad: 0,
                    segments: vec![
                        Ipv6Addr::from_str("2001:db8::3").unwrap(),
                        Ipv6Addr::from_str("2001:db8::2").unwrap(),
                    ],
                }),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Rpl),
            RouteAttribute::Oif(11),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
