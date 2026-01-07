// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    link::{
        freebsd::{FreeBsdLinkAttribute, IfCap2Flags, IfCapFlags, IfCaps},
        InfoKind, LinkAttribute, LinkFlags, LinkHeader, LinkInfo,
        LinkLayerType, LinkMessage, LinkMessageBuffer, State, Stats64,
    },
    AddressFamily,
};

#[test]
fn test_freebsd_spec_attr() {
    let raw: [u8; _] = [
        0, 0, 6, 0, 3, 0, 0, 0, 67, 136, 0, 0, 0, 0, 0, 0, 10, 0, 3, 0, 119,
        108, 97, 110, 48, 0, 0, 0, 5, 0, 16, 0, 0, 0, 0, 0, 5, 0, 33, 0, 0, 0,
        0, 0, 10, 0, 1, 0, 88, 156, 252, 16, 137, 144, 0, 0, 10, 0, 2, 0, 255,
        255, 255, 255, 255, 255, 0, 0, 8, 0, 4, 0, 220, 5, 0, 0, 52, 0, 64, 0,
        10, 0, 2, 0, 88, 156, 252, 16, 137, 144, 0, 0, 36, 0, 3, 0, 8, 0, 2, 0,
        35, 0, 0, 0, 12, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 196, 0, 23, 0, 49, 1, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0,
        0, 0, 0, 100, 84, 0, 0, 0, 0, 0, 0, 218, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 40, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 30, 0, 0, 0, 0, 0, 16,
        0, 18, 0, 9, 0, 1, 0, 119, 108, 97, 110, 0, 0, 0, 0,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 3,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Up
                | LinkFlags::Broadcast
                | LinkFlags::Running
                | LinkFlags::Simplex
                | LinkFlags::Multicast,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![
            LinkAttribute::IfName(format!("wlan0")),
            LinkAttribute::OperState(State::Unknown),
            LinkAttribute::Carrier(0),
            LinkAttribute::Address(vec![88, 156, 252, 16, 137, 144]),
            LinkAttribute::Broadcast(vec![255, 255, 255, 255, 255, 255]),
            LinkAttribute::Mtu(1500),
            LinkAttribute::FreeBSD(vec![
                FreeBsdLinkAttribute::OrigHwAddr([88, 156, 252, 16, 137, 144]),
                FreeBsdLinkAttribute::IfCaps(IfCaps {
                    cap_bit_size: 35,
                    supported_caps: (IfCapFlags::empty(), IfCap2Flags::empty()),
                    active_caps: (IfCapFlags::empty(), IfCap2Flags::empty()),
                }),
            ]),
            LinkAttribute::Stats64(Stats64 {
                rx_packets: 305,
                tx_packets: 11,
                rx_bytes: 21604,
                tx_bytes: 1498,
                rx_errors: 0,
                tx_errors: 9,
                rx_dropped: 0,
                tx_dropped: 0,
                multicast: 296,
                collisions: 0,
                rx_length_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                rx_frame_errors: 0,
                rx_fifo_errors: 0,
                rx_missed_errors: 0,
                tx_aborted_errors: 0,
                tx_carrier_errors: 0,
                tx_fifo_errors: 0,
                tx_heartbeat_errors: 0,
                tx_window_errors: 0,
                rx_compressed: 0,
                tx_compressed: 0,
                rx_nohandler: 0,
            }),
            LinkAttribute::Promiscuity(0),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Wlan)]),
        ],
    };

    assert_eq!(
        expected,
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
