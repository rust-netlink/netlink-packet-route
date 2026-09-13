// SPDX-License-Identifier: MIT

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        seg6local::{RouteSeg6LocalTunnel, Seg6LocalAction, Seg6LocalSrh},
        RouteAttribute, RouteCacheInfo, RouteFlags, RouteHeader,
        RouteLwEnCapType, RouteLwTunnelEncap, RouteMessage, RoutePreference,
        RouteProtocol, RouteScope, RouteType,
    },
    AddressFamily,
};

// Setup:
//      ip link add d0 type dummy
//      ip link set d0 up
//      ip -6 route add 2001:db8:8::/64 \
//          encap seg6local action End.DX4 nh4 10.0.0.2 dev d0
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show 2001:db8:8::/64
#[test]
fn test_seg6local_end_dx4() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x14, 0x00, 0x16, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
        0x0a, 0x00, 0x00, 0x02, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:8::").unwrap().into(),
            ),
            RouteAttribute::Priority(1024),
            RouteAttribute::Oif(11),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndDx4,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Nh4(
                    Ipv4Addr::from_str("10.0.0.2").unwrap(),
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
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

    assert_eq!(buf, raw);

    // The encapsulation type name is printed as iproute2 spells it.
    assert_eq!(RouteLwEnCapType::Seg6Local.to_string(), "seg6local");
}

// Setup:
//      ip -6 route add 2001:db8:9::/64 encap seg6local \
//          action End.B6.Encaps srh segs 2001:db8::2,2001:db8::3 dev d0
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show 2001:db8:9::/64
#[test]
fn test_seg6local_end_b6_encaps() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x38, 0x00, 0x16, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x02, 0x00,
        0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:9::").unwrap().into(),
            ),
            RouteAttribute::Priority(1024),
            RouteAttribute::Oif(11),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndB6Encap,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Srh(
                    Seg6LocalSrh {
                        next_header: 0,
                        routing_type: 4,
                        segments_left: 1,
                        first_segment: 1,
                        flags: 0,
                        tag: 0,
                        segments: vec![
                            Ipv6Addr::from_str("2001:db8::3").unwrap(),
                            Ipv6Addr::from_str("2001:db8::2").unwrap(),
                        ],
                    },
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
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

    assert_eq!(buf, raw);
}

// Setup:
//      ip -6 route add 2001:db8:11::/64 encap seg6local \
//          action End.DX6 nh6 2001:db8::5 dev d0
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show 2001:db8:11::/64
#[test]
fn test_seg6local_end_dx6() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x20, 0x00, 0x16, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x14, 0x00, 0x05, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:11::").unwrap().into(),
            ),
            RouteAttribute::Priority(1024),
            RouteAttribute::Oif(11),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndDx6,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Nh6(
                    Ipv6Addr::from_str("2001:db8::5").unwrap(),
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
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

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local action End dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![RouteLwTunnelEncap::Seg6Local(
                RouteSeg6LocalTunnel::Action(Seg6LocalAction::End),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // The capture carries `NLA_F_NESTED` on `RTA_ENCAP` while the kernel
    // does not require the flag for `seg6local` and omits it in dumps, so
    // the emitted message is checked by parsing instead of by bytes.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local \
//          action End.X nh6 fe80:1:2:: dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end_x() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x05, 0x00,
        0xfe, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndX,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Nh6(
                    Ipv6Addr::from_str("fe80:1:2::").unwrap(),
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // See `test_seg6local_end` for the `NLA_F_NESTED` flag difference.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local \
//          action End.T table 10 dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end_t() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndT,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Table(10)),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // See `test_seg6local_end` for the `NLA_F_NESTED` flag difference.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local \
//          action End.B6 srh segs fe80:1:2::,fe80:2:3:: dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end_b6() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0x00,
        0x00, 0x06, 0x04, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfe, 0x80, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndB6,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Srh(
                    Seg6LocalSrh {
                        next_header: 0,
                        routing_type: 4,
                        segments_left: 2,
                        first_segment: 2,
                        flags: 0,
                        tag: 0,
                        segments: vec![
                            // Without encapsulation, the segment list must
                            // have an additional zero segment.
                            Ipv6Addr::from_str("::").unwrap(),
                            Ipv6Addr::from_str("fe80:2:3::").unwrap(),
                            Ipv6Addr::from_str("fe80:1:2::").unwrap(),
                        ],
                    },
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // See `test_seg6local_end` for the `NLA_F_NESTED` flag difference.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local \
//          action End.DX2 oif dummy1 dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end_dx2() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndDx2,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Oif(2)),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // See `test_seg6local_end` for the `NLA_F_NESTED` flag difference.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local \
//          action End.DT6 table 10 dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end_dt6() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndDt6,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Table(10)),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // See `test_seg6local_end` for the `NLA_F_NESTED` flag difference.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      modprobe vrf
//      sysctl net.vrf.strict_mode=1
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local \
//          action End.DT4 vrftable 10 dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end_dt4() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndDt4,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::VrfTable(
                    10,
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // See `test_seg6local_end` for the `NLA_F_NESTED` flag difference.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// Setup:
//      modprobe vrf
//      sysctl net.vrf.strict_mode=1
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip -6 route add fe80::/32 encap seg6local \
//          action End.DT46 vrftable 10 dev dummy1
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show dev dummy1
#[test]
fn test_seg6local_end_dt46() {
    let raw = vec![
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::Action(
                    Seg6LocalAction::EndDt46,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalTunnel::VrfTable(
                    10,
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // See `test_seg6local_end` for the `NLA_F_NESTED` flag difference.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}
