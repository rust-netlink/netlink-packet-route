// SPDX-License-Identifier: MIT

use std::{net::Ipv4Addr, str::FromStr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        flags::RouteFlags, RouteAttribute, RouteErspanOpt, RouteGeneveOpt,
        RouteHeader, RouteIpTunnel, RouteIpTunnelFlags, RouteLwEnCapType,
        RouteLwTunnelEncap, RouteLwTunnelOpt, RouteMessage, RouteProtocol,
        RouteScope, RouteType,
    },
    AddressFamily,
};

// strace capture(netlink message header removed) against command:
//   ip route add 10.32.0.0/16 encap ip id 300 vxlan_opts 100 dev d0
#[test]
fn test_ip_tunnel_vxlan_opts_request() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x20, 0x00, 0x16, 0x80,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c,
        0x10, 0x00, 0x08, 0x80, 0x0c, 0x00, 0x02, 0x80, 0x08, 0x00, 0x01, 0x00,
        0x64, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
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
            RouteAttribute::Destination(Ipv4Addr::new(10, 32, 0, 0).into()),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(300)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Opts(vec![
                    RouteLwTunnelOpt::Vxlan(100),
                ])),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ip),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// strace capture(netlink message header removed) against command:
//   ip route add 10.33.0.0/16 encap ip id 300 erspan_opts 1:2:3:4 dev d0
#[test]
fn test_ip_tunnel_erspan_opts_request() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x21, 0x00, 0x00, 0x38, 0x00, 0x16, 0x80,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c,
        0x28, 0x00, 0x08, 0x80, 0x24, 0x00, 0x03, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x05, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
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
            RouteAttribute::Destination(Ipv4Addr::new(10, 33, 0, 0).into()),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(300)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Opts(vec![erspan_opt()])),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ip),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

fn erspan_opt() -> RouteLwTunnelOpt {
    let opt = RouteErspanOpt {
        ver: 1,
        index: Some(2),
        dir: Some(3),
        hwid: Some(4),
    };
    RouteLwTunnelOpt::Erspan(opt)
}

// strace capture(netlink message header removed) against command:
//   ip route add 10.40.0.0/16 encap ip id 300 \
//       geneve_opts 0x1234:0x42:11223344 dev d0
// The kernel oopses in `ip_tun_parse_opts_geneve()` on the tested kernel, so
// the request is captured with `strace` instead of `nlmon` and no route is
// created.
#[test]
fn test_ip_tunnel_geneve_opts_request() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x28, 0x00, 0x00, 0x30, 0x00, 0x16, 0x80,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c,
        0x20, 0x00, 0x08, 0x80, 0x1c, 0x00, 0x01, 0x80, 0x06, 0x00, 0x01, 0x00,
        0x12, 0x34, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x42, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x11, 0x22, 0x33, 0x44, 0x06, 0x00, 0x15, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];

    let geneve = RouteGeneveOpt {
        class: 0x1234,
        typ: 0x42,
        data: vec![0x11, 0x22, 0x33, 0x44],
    };

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
            RouteAttribute::Destination(Ipv4Addr::new(10, 40, 0, 0).into()),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(300)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Opts(vec![
                    RouteLwTunnelOpt::Geneve(vec![geneve]),
                ])),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ip),
            RouteAttribute::Oif(2),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// nlmon capture(netlink message header removed) against command:
//   ip route show 10.32.0.0/16
// The kernel does not set `NLA_F_NESTED` on `RTA_ENCAP` and its options in
// dumps while the emitted message carries the flags the kernel requires.
#[test]
fn test_ip_tunnel_vxlan_opts_dump() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x0a, 0x20, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x16, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x2c, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x06, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x08, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x15, 0x00, 0x02, 0x00, 0x00, 0x00,
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
            RouteAttribute::Destination(Ipv4Addr::new(10, 32, 0, 0).into()),
            RouteAttribute::Oif(2),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(300)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Destination(
                    Ipv4Addr::from_str("0.0.0.0").unwrap(),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Source(
                    Ipv4Addr::from_str("0.0.0.0").unwrap(),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Tos(0)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Ttl(0)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Flags(
                    // `IP_TUNNEL_VXLAN_OPT_BIT` of the flags.
                    RouteIpTunnelFlags::from_bits_retain(0x1000),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Opts(vec![
                    RouteLwTunnelOpt::Vxlan(100),
                ])),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ip),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

// nlmon capture(netlink message header removed) against command:
//   ip route show 10.33.0.0/16
#[test]
fn test_ip_tunnel_erspan_opts_dump() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x0a, 0x21, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x16, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x2c, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x06, 0x00, 0x40, 0x00, 0x00, 0x00, 0x18, 0x00, 0x08, 0x00,
        0x14, 0x00, 0x03, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x15, 0x00,
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
            RouteAttribute::Destination(Ipv4Addr::new(10, 33, 0, 0).into()),
            RouteAttribute::Oif(2),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Id(300)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Destination(
                    Ipv4Addr::from_str("0.0.0.0").unwrap(),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Source(
                    Ipv4Addr::from_str("0.0.0.0").unwrap(),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Tos(0)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Ttl(0)),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Flags(
                    // `IP_TUNNEL_ERSPAN_OPT_BIT` of the flags.
                    RouteIpTunnelFlags::from_bits_retain(0x4000),
                )),
                RouteLwTunnelEncap::Ip(RouteIpTunnel::Opts(vec![
                    erspan_dump_opt(),
                ])),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ip),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}

fn erspan_dump_opt() -> RouteLwTunnelOpt {
    RouteLwTunnelOpt::Erspan(RouteErspanOpt {
        ver: 1,
        index: Some(2),
        ..Default::default()
    })
}
