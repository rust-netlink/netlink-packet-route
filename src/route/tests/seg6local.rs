// SPDX-License-Identifier: MIT

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        seg6local::{RouteSeg6LocalIpTunnel, Seg6LocalAction, SRH},
        RouteAttribute, RouteFlags, RouteHeader, RouteLwEnCapType,
        RouteLwTunnelEncap, RouteMessage, RouteMessageBuffer, RouteProtocol,
        RouteScope, RouteType,
    },
    AddressFamily,
};

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end() {
    let raw = [
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
                RouteSeg6LocalIpTunnel::Action(Seg6LocalAction::End),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.X nh6 fe80:1:2:: dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_x() {
    let raw = [
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndX,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Nh6(
                    Ipv6Addr::from_str("fe80:1:2::").unwrap().into(),
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.T table 10 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_t() {
    let raw = [
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndT,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Table(
                    10,
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:

//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.B6 srh segs fe80:1:2::,fe80:2:3:: dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_b6() {
    let raw = [
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndB6,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::SRH(
                    SRH {
                        segments: vec![
                            Ipv6Addr::from_str("fe80:1:2::").unwrap().into(),
                            Ipv6Addr::from_str("fe80:2:3::").unwrap().into(),
                            // without encap, we have **must have** an
                            // additional segment
                            Ipv6Addr::from_str("::").unwrap().into(),
                        ],
                    },
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:

//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.B6.Encaps srh segs fe80:1:2::,fe80:2:3:: dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_b6_encap() {
    let raw = [
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x02, 0x00,
        0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndB6Encap,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::SRH(
                    SRH {
                        segments: vec![
                            Ipv6Addr::from_str("fe80:1:2::").unwrap().into(),
                            Ipv6Addr::from_str("fe80:2:3::").unwrap().into(),
                        ],
                    },
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.DX2 oif dummy1 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_dx2() {
    let raw = [
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDX2,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Oif(2)),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.DX6 nh6 fe80:1:2:: dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_dx6() {
    let raw = [
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x14, 0x00, 0x05, 0x00,
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDX6,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Nh6(
                    Ipv6Addr::from_str("fe80:1:2::").unwrap().into(),
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.DX4 nh4 10.1.2.1 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_dx4() {
    let raw = [
        0x0a, 0x20, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
        0x0a, 0x01, 0x02, 0x01, 0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00,
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDX4,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Nh4(
                    Ipv4Addr::from_str("10.1.2.1").unwrap().into(),
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.DT6 table 10 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_dt6() {
    let raw = [
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDT6,
                )),
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Table(
                    10,
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      modprobe vrf
//      sysctl net.vrf.strict_mode=1
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.DT4 vrftable 10 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_dt4() {
    let raw = [
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDT4,
                )),
                RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalIpTunnel::VrfTable(10),
                ),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Setup:
//      modprobe vrf
//      sysctl net.vrf.strict_mode=1
//      ip link add vrf-dummy type vrf table 10
//      ip link set vrf-dummy up
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      ip route add fe80::/32 encap seg6local \
//          action End.DT46 vrftable 10 dev dummy1
// wireshark capture(netlink message header removed) of nlmon against command:
//      ip -6 route show dev dummy1
#[test]
fn test_end_dt46() {
    let raw = [
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
                RouteLwTunnelEncap::Seg6Local(RouteSeg6LocalIpTunnel::Action(
                    Seg6LocalAction::EndDT46,
                )),
                RouteLwTunnelEncap::Seg6Local(
                    RouteSeg6LocalIpTunnel::VrfTable(10),
                ),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Seg6Local),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(
        expected,
        RouteMessage::parse(&RouteMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
