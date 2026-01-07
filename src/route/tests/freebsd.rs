// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage,
        RouteMessageBuffer, RouteProtocol, RouteScope, RouteType, RtFlags,
    },
    AddressFamily,
};

/// Setup
///
/// FreeBSD does not support to set RTA_WEIGHT attribute with built-in tools,
/// but it can be set via `rtsock` or `netlink`.
///
/// ```c
/// /* rt_msghdr */
/// rtm->rtm_version = RTM_VERSION;
/// rtm->rtm_type    = RTM_CHANGE;
/// rtm->rtm_flags   = RTF_UP;
/// rtm->rtm_addrs   = RTA_DST | RTA_NETMASK;
/// rtm->rtm_seq     = 1;
/// rtm->rtm_pid     = getpid();
///
/// /* set weight */
/// rtm->rtm_inits = RTV_WEIGHT;
/// rtm->rtm_rmx.rmx_weight = 10;
/// ```
#[test]
fn test_freebsd_rt_net() {
    // 10, 0, 5, 0, 0, 0 => RTA_KNH_ID = 5
    // 14, 0, 0, 0, 16, 0 => RTA_RTFLAGS = RTF_PINNED
    // 13, 0, 10, 0, 0, 0 => RTA_WEIGHT = 10
    let raw: [u8; _] = [
        2, 24, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 8, 0, 1,
        0, 192, 168, 1, 0, 8, 0, 10, 0, 5, 0, 0, 0, 8, 0, 14, 0, 0, 0, 16, 0,
        8, 0, 4, 0, 3, 0, 0, 0, 8, 0, 13, 0, 10, 0, 0, 0,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: 24,
            source_prefix_length: 0,
            tos: 0,
            table: 0,
            protocol: RouteProtocol::Kernel,
            scope: RouteScope::Universe,
            kind: RouteType::Unicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Table(0),
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(
                192, 168, 1, 0,
            ))),
            RouteAttribute::KernelNextHopId(5),
            RouteAttribute::RtFlags(RtFlags::Pinned),
            RouteAttribute::Oif(3),
            RouteAttribute::PathWeight(10),
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

#[test]
fn test_freebsd_rt_host() {
    // 10, 0, 3, 0, 0, 0 => RTA_KNH_ID = 3
    // 14, 0, 4, 8, 16, 0 => RTA_RTFLAGS = RTF_HOST | RTF_STATIC | RTF_PINNED
    let raw: [u8; _] = [
        2, 32, 0, 0, 0, 4, 0, 1, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 8, 0, 1,
        0, 192, 168, 56, 101, 8, 0, 10, 0, 3, 0, 0, 0, 8, 0, 14, 0, 4, 8, 16,
        0, 8, 0, 4, 0, 1, 0, 0, 0,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: 32,
            source_prefix_length: 0,
            tos: 0,
            table: 0,
            protocol: RouteProtocol::Static,
            scope: RouteScope::Universe,
            kind: RouteType::Unicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Table(0),
            RouteAttribute::Destination(RouteAddress::Inet(Ipv4Addr::new(
                192, 168, 56, 101,
            ))),
            RouteAttribute::KernelNextHopId(3),
            RouteAttribute::RtFlags(
                RtFlags::Host | RtFlags::Static | RtFlags::Pinned,
            ),
            RouteAttribute::Oif(1),
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
