// SPDX-License-Identifier: MIT

use std::{net::Ipv6Addr, str::FromStr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        ioam6::{Ioam6Mode, Ioam6TraceHdr, RouteIoam6Tunnel},
        RouteAttribute, RouteCacheInfo, RouteFlags, RouteHeader,
        RouteLwEnCapType, RouteLwTunnelEncap, RouteMessage, RoutePreference,
        RouteProtocol, RouteScope, RouteType,
    },
    AddressFamily,
};

// Setup:
//      ip link add d0 type dummy
//      ip link set d0 up
//      ip -6 route add 2001:db8:7::/64 encap ioam6 mode inline \
//          trace prealloc type 0x800000 ns 1 size 12 dev d0
// nlmon capture(netlink message header removed) against command:
//      ip -6 route show 2001:db8:7::/64
#[test]
fn test_ioam6_tunnel() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x28, 0x00, 0x16, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x01, 0x08, 0x03, 0x80, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x15, 0x00, 0x09, 0x00, 0x00, 0x00, 0x24, 0x00, 0x0c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x14, 0x00,
        0x00, 0x00, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:7::").unwrap().into(),
            ),
            RouteAttribute::Priority(1024),
            RouteAttribute::Oif(11),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqK(1)),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqN(1)),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Mode(
                    Ioam6Mode::Inline,
                )),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Trace(
                    Ioam6TraceHdr {
                        namespace_id: 1,
                        nodelen: 1,
                        overflow: false,
                        remlen: 3,
                        trace_type: 0x800000,
                    },
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ioam6),
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
//   ip -6 route add 2001:db8:91::/64 \
//       encap ioam6 freq 2/3 mode encap tunsrc 2001:db8::8 \
//       tundst 2001:db8::9 trace prealloc type 0x800000 ns 7 size 8 dev d0
// The `NLA_F_NESTED` flag of `RTA_ENCAP` is only present in the request.
#[test]
fn test_ioam6_tunnel_request() {
    let raw = vec![
        0x0a, 0x40, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x01, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x91, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x16, 0x80,
        0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x06, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x14, 0x00, 0x02, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x09, 0x0c, 0x00, 0x03, 0x00, 0x00, 0x07, 0x00, 0x02,
        0x80, 0x00, 0x00, 0x00, 0x06, 0x00, 0x15, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00,
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
                Ipv6Addr::from_str("2001:db8:91::").unwrap().into(),
            ),
            RouteAttribute::Encap(vec![
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqK(2)),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::FreqN(3)),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Mode(
                    Ioam6Mode::Encap,
                )),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Src(
                    Ipv6Addr::from_str("2001:db8::8").unwrap(),
                )),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Dst(
                    Ipv6Addr::from_str("2001:db8::9").unwrap(),
                )),
                RouteLwTunnelEncap::Ioam6(RouteIoam6Tunnel::Trace(
                    Ioam6TraceHdr {
                        namespace_id: 7,
                        nodelen: 0,
                        overflow: false,
                        remlen: 2,
                        trace_type: 0x800000,
                    },
                )),
            ]),
            RouteAttribute::EncapType(RouteLwEnCapType::Ioam6),
            RouteAttribute::Oif(11),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
