// SPDX-License-Identifier: MIT

use std::{net::Ipv6Addr, str::FromStr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        seg6::{RouteSeg6IpTunnel, Seg6Mode},
        RouteAttribute, RouteCacheInfo, RouteFlags, RouteHeader,
        RouteLwEnCapType, RouteLwTunnelEncap, RouteMessage, RoutePreference,
        RouteProtocol, RouteScope, RouteType, Seg6Header,
    },
    AddressFamily,
};

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6 mode encap \
//          segs fe80::1,fe80::2 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_encap() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x16, 0x80,
        0x30, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x01,
        0x01, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfe, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x00, 0x15, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
        0x02, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet6,
            destination_prefix_length: 32,
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
                Ipv6Addr::from_str("fe80::").unwrap().into(),
            ),
            RouteAttribute::Encap(vec![RouteLwTunnelEncap::Seg6(
                RouteSeg6IpTunnel::Seg6(Seg6Header {
                    mode: Seg6Mode::Encap,
                    segments: vec![
                        Ipv6Addr::from_str("fe80::1").unwrap(),
                        Ipv6Addr::from_str("fe80::2").unwrap(),
                    ],
                    hmac: None,
                }),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add nprc0 type dummy
//      ip link set nprc0 up
//      ip -6 route add 2001:db8:92::/64 encap seg6 mode encap \
//          tunsrc 2001:db8::8 segs 2001:db8::2,2001:db8::3 lookup 100 \
//          dev nprc0
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show 2001:db8:92::/64
// The kernel drops `SEG6_IPTUNNEL_TABLE` of the `lookup` argument, the
// request capture of the `lookup` attribute is asserted by
// `test_encap_tunsrc_lookup_request()`.
#[test]
fn test_encap_tunsrc() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x76, 0x01, 0x00, 0x00, 0x48, 0x00, 0x16, 0x00,
        0x30, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x14, 0x00, 0x02, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x15, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x24, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:92::").unwrap().into(),
            ),
            RouteAttribute::Priority(1024),
            RouteAttribute::Oif(374),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Seg6(Seg6Header {
                    mode: Seg6Mode::Encap,
                    segments: vec![
                        Ipv6Addr::from_str("2001:db8::2").unwrap(),
                        Ipv6Addr::from_str("2001:db8::3").unwrap(),
                    ],
                    hmac: None,
                })),
                RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Src(
                    Ipv6Addr::from_str("2001:db8::8").unwrap(),
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6),
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

    // The kernel emits `RTA_ENCAP` without `NLA_F_NESTED` while the emitted
    // message carries the flag required by the kernel.
    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      ip link add nprc0 type dummy
//      ip link set nprc0 up
//      ip -6 route add 2001:db8:93::/64 encap seg6 mode encap hmac 1234 \
//          segs 2001:db8::2,2001:db8::3 dev nprc0
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show 2001:db8:93::/64
#[test]
fn test_encap_hmac() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x76, 0x01, 0x00, 0x00, 0x5c, 0x00, 0x16, 0x00,
        0x58, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x04, 0x01,
        0x01, 0x08, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x05, 0x26, 0x00, 0x00, 0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:93::").unwrap().into(),
            ),
            RouteAttribute::Priority(1024),
            RouteAttribute::Oif(374),
            RouteAttribute::Encap(vec![RouteLwTunnelEncap::Seg6(
                RouteSeg6IpTunnel::Seg6(Seg6Header {
                    mode: Seg6Mode::Encap,
                    segments: vec![
                        Ipv6Addr::from_str("2001:db8::2").unwrap(),
                        Ipv6Addr::from_str("2001:db8::3").unwrap(),
                    ],
                    hmac: Some(1234),
                }),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6),
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

    // The kernel emits `RTA_ENCAP` without `NLA_F_NESTED` while the emitted
    // message carries the flag required by the kernel.
    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      ip link add nprc0 type dummy
//      ip link set nprc0 up
// nlmon capture(netlink message header removed) of the request sent by:
//      ip -6 route add 2001:db8:94::/64 encap seg6 mode encap \
//          tunsrc 2001:db8::8 segs 2001:db8::2,2001:db8::3 lookup 100 \
//          dev nprc0
#[test]
fn test_encap_tunsrc_lookup_request() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x94, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x16, 0x80,
        0x30, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x14, 0x00, 0x02, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x03, 0x00,
        0x64, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x76, 0x01, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:94::").unwrap().into(),
            ),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Seg6(Seg6Header {
                    mode: Seg6Mode::Encap,
                    segments: vec![
                        Ipv6Addr::from_str("2001:db8::2").unwrap(),
                        Ipv6Addr::from_str("2001:db8::3").unwrap(),
                    ],
                    hmac: None,
                })),
                RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Src(
                    Ipv6Addr::from_str("2001:db8::8").unwrap(),
                )),
                RouteLwTunnelEncap::Seg6(RouteSeg6IpTunnel::Table(100)),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6),
            RouteAttribute::Oif(374),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6 mode inline \
//          segs fe80::1,fe80::2 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_inline() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x16, 0x80,
        0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x04, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x15, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet6,
            destination_prefix_length: 32,
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
                Ipv6Addr::from_str("fe80::").unwrap().into(),
            ),
            RouteAttribute::Encap(vec![RouteLwTunnelEncap::Seg6(
                RouteSeg6IpTunnel::Seg6(Seg6Header {
                    mode: Seg6Mode::Inline,
                    segments: vec![
                        Ipv6Addr::from_str("fe80::1").unwrap(),
                        Ipv6Addr::from_str("fe80::2").unwrap(),
                        Ipv6Addr::UNSPECIFIED,
                    ],
                    hmac: None,
                }),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
