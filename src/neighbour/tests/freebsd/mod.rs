// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    neighbour::{
        freebsd::FreeBsdNeighbourAttribute, NeighbourAttribute,
        NeighbourCacheInfo, NeighbourFlags, NeighbourHeader, NeighbourMessage,
        NeighbourMessageBuffer, NeighbourState,
    },
    route::RouteType,
    AddressFamily,
};

#[test]
fn test_freebsd_neighbour() {
    let raw: [u8; 72] = [
        2, 0, 0, 0, 3, 0, 0, 0, 2, 0, 66, 0, 8, 0, 1, 0, 192, 168, 8, 204, 10,
        0, 2, 0, 88, 156, 252, 16, 137, 144, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 20,
        0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 12, 0, 18, 0,
        8, 0, 1, 0, 0, 0, 0, 0,
    ];

    let expected = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Inet,
            ifindex: 3,
            state: NeighbourState::Reachable,
            flags: NeighbourFlags::Own | NeighbourFlags::Sticky,
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::Destination(
                IpAddr::V4(Ipv4Addr::new(192, 168, 8, 204)).into(),
            ),
            NeighbourAttribute::LinkLocalAddress(vec![
                88, 156, 252, 16, 137, 144,
            ]),
            NeighbourAttribute::Probes(0),
            NeighbourAttribute::CacheInfo(NeighbourCacheInfo {
                confirmed: 0,
                used: 0,
                updated: 0,
                refcnt: 1,
            }),
            NeighbourAttribute::FreeBSD(vec![
                FreeBsdNeighbourAttribute::NextStateTimeSecs(0),
            ]),
        ],
    };

    assert_eq!(
        expected,
        NeighbourMessage::parse(&NeighbourMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
