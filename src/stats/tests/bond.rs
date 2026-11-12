// SPDX-License-Identifier: MIT
use netlink_packet_core::{Emitable, Parseable};

use crate::{
    stats::{
        Bond3adStats, BondXstat, LinkXstatGroup, StatsAttribute,
        StatsFilterMask, StatsHeader, StatsMessage,
    },
    AddressFamily,
};

// nlmon capture of the kernel `RTM_NEWSTATS` reply (netlink header removed)
// on Linux 7.2.14, trimmed to `IFLA_STATS_LINK_XSTATS`. The capture was
// triggered by:
//
//      ip link add bondstat0 type bond mode 802.3ad
//      ip link set bondstat0 up
//      ip stats show dev bondstat0
#[cfg(not(target_endian = "big"))]
#[test]
fn test_parsing_bond_xstats() {
    let raw: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x79, 0x05, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00,
        0x78, 0x00, 0x02, 0x00, 0x74, 0x00, 0x02, 0x00, 0x70, 0x00, 0x01, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = StatsMessage {
        header: StatsHeader {
            family: AddressFamily::Unspec,
            ifindex: 1401,
            filter_mask: StatsFilterMask::Link64
                | StatsFilterMask::LinkXstats
                | StatsFilterMask::LinkXstatsPort
                | StatsFilterMask::LinkOffloadXstats
                | StatsFilterMask::AfSpec,
        },
        attributes: vec![StatsAttribute::LinkXstats(vec![
            LinkXstatGroup::Bond(vec![BondXstat::ThreeAd(vec![
                Bond3adStats::LacpduRx(0),
                Bond3adStats::LacpduTx(0),
                Bond3adStats::LacpduUnknownRx(0),
                Bond3adStats::LacpduIllegalRx(0),
                Bond3adStats::MarkerRx(0),
                Bond3adStats::MarkerTx(0),
                Bond3adStats::MarkerRespRx(0),
                Bond3adStats::MarkerRespTx(0),
                Bond3adStats::MarkerUnknownRx(0),
            ])]),
        ])],
    };

    assert_eq!(expected, StatsMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}
