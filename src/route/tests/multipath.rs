// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        flags::RouteFlags, RouteAddress, RouteAttribute, RouteHeader,
        RouteMessage, RouteMfcStats, RouteNextHop, RouteNextHopFlags,
        RouteProtocol, RouteScope, RouteType,
    },
    AddressFamily,
};

// wireshark capture(netlink message header removed) of nlmon against command:
//   ip route add 10.109.0.0/16 nexthop via 10.0.0.254 dev test-dummy weight 1
//       nexthop via 10.0.0.253 dev test-dummy weight 2
#[test]
fn test_route_multipath_two_nexthops() {
    let raw = vec![
        // rtmsg: family=AF_INET(2), dst_len=16, src_len=0, tos=0,
        //        table=main(254), proto=boot(3), scope=global(0),
        //        type=unicast(1), flags=0
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // RTA_TABLE(0x0f)=254
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00,
        // RTA_DST(0x01)=10.109.0.0
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x6d, 0x00, 0x00,
        // RTA_MULTIPATH(0x09) with 2 nexthops:
        //   nexthop 0: len=16, flags=0, hops=0(weight=1), ifindex=17
        //              RTA_GATEWAY=10.0.0.254
        //   nexthop 1: len=16, flags=0, hops=1(weight=2), ifindex=17
        //              RTA_GATEWAY=10.0.0.253
        0x24, 0x00, 0x09, 0x00, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x00, 0xfe, 0x10, 0x00, 0x00, 0x01,
        0x11, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x00, 0xfd,
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
            RouteAttribute::Table(254),
            RouteAttribute::Destination(Ipv4Addr::new(10, 109, 0, 0).into()),
            RouteAttribute::MultiPath(vec![
                RouteNextHop {
                    flags: RouteNextHopFlags::empty(),
                    hops: 0,
                    interface_index: 17,
                    attributes: vec![RouteAttribute::Gateway(
                        Ipv4Addr::new(10, 0, 0, 254).into(),
                    )],
                },
                RouteNextHop {
                    flags: RouteNextHopFlags::empty(),
                    hops: 1,
                    interface_index: 17,
                    attributes: vec![RouteAttribute::Gateway(
                        Ipv4Addr::new(10, 0, 0, 253).into(),
                    )],
                },
            ]),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

// wireshark capture(netlink message header removed) of nlmon against command:
/* python3 -c 'import socket, struct, signal
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
s.setsockopt(socket.IPPROTO_IPV6, 200, 1)  # MRT6_INIT
s.setsockopt(socket.IPPROTO_IPV6, 202, struct.pack("=HBBHxxI", 0, 0, 1, 1, 0))  # MRT6_ADD_MIF: mif 0 = lo
sin6 = lambda a: struct.pack("=HHI16sI", socket.AF_INET6, 0, 0, socket.inet_pton(socket.AF_INET6, a), 0)
s.setsockopt(socket.IPPROTO_IPV6, 204, sin6("2001:db8::1") + sin6("ff0e::1") + bytes(36))  # MRT6_ADD_MFC, empty oif set
signal.pause()'
*/
#[test]
fn test_route_multipath_zero_nexthops() {
    let raw = vec![
        // rtmsg: family=RTNL_FAMILY_IP6MR(0x81), dst_len=128, src_len=128,
        //        tos=0, table=main(254), proto=mrouted(17), scope=global(0),
        //        type=multicast(5), flags=0
        0x81, 0x80, 0x80, 0x00, 0xfe, 0x11, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
        // RTA_TABLE(0x0f)=254
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00,
        // RTA_SRC(0x02)=2001:db8::1
        0x14, 0x00, 0x02, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // RTA_DST(0x01)=ff0e::1
        0x14, 0x00, 0x01, 0x00, 0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // RTA_IIF(0x03)=1
        0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
        // RTA_MULTIPATH(0x09), empty
        0x04, 0x00, 0x09, 0x00,
        // RTA_MFC_STATS(0x11): packets=0, bytes=0, wrong_if=0
        0x1c, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, // RTA_EXPIRES(0x17)=100
        0x0c, 0x00, 0x17, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Other(0x81),
            destination_prefix_length: 128,
            source_prefix_length: 128,
            tos: 0,
            table: 254,
            protocol: RouteProtocol::Mrouted,
            scope: RouteScope::Universe,
            kind: RouteType::Multicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Table(254),
            RouteAttribute::Source(RouteAddress::Other(vec![
                // 2001:db8::1
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ])),
            RouteAttribute::Destination(RouteAddress::Other(vec![
                // ff0e::1
                0xff, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ])),
            RouteAttribute::Iif(1),
            RouteAttribute::MultiPath(vec![]),
            RouteAttribute::MfcStats(RouteMfcStats {
                bytes: 0,
                packets: 0,
                wrong_if: 0,
            }),
            RouteAttribute::MulticastExpires(100),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
