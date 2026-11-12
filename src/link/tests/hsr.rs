// SPDX-License-Identifier: MIT
use netlink_packet_core::{Emitable, Parseable};

use crate::{
    link::{
        link_flag::LinkFlags, HsrProtocol, HsrVersion, InfoData, InfoHsr,
        InfoKind, LinkAttribute, LinkHeader, LinkInfo, LinkLayerType,
        LinkMessage,
    },
    AddressFamily,
};

#[cfg(not(target_endian = "big"))]
#[test]
fn test_parsing_link_hsr_version() {
    // nlmon capture of:
    //  ip link add hcap1 type hsr slave1 hsra0 slave2 hsrb0 version 1
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x68, 0x63, 0x61, 0x70,
        0x31, 0x00, 0x00, 0x00, 0x30, 0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x68, 0x73, 0x72, 0x00, 0x24, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x22, 0x05, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x23, 0x05, 0x00, 0x00,
        0x05, 0x00, 0x03, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00,
        0x01, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 0,
            link_layer_type: LinkLayerType::Netrom,
            flags: LinkFlags::empty(),
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![
            LinkAttribute::IfName("hcap1".to_string()),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Hsr),
                LinkInfo::Data(InfoData::Hsr(vec![
                    InfoHsr::Port1(0x0522),
                    InfoHsr::Port2(0x0523),
                    InfoHsr::MulticastSpec(45),
                    InfoHsr::Version(HsrVersion::V1),
                ])),
            ]),
        ],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

#[test]
fn test_parsing_link_hsr() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x68, 0x73, 0x72, 0x00, 0x30, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x2c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x2a, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x04, 0x00, 0x01, 0x15, 0x4e, 0x00, 0x01, 0x90, 0x00, 0x00,
        0x06, 0x00, 0x05, 0x00, 0x09, 0xfc, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 45,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Broadcast
                | LinkFlags::LowerUp
                | LinkFlags::Multicast
                | LinkFlags::Running
                | LinkFlags::Up,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Hsr),
            LinkInfo::Data(InfoData::Hsr(vec![
                InfoHsr::Port1(44),
                InfoHsr::Port2(42),
                InfoHsr::SupervisionAddr([0x01, 0x15, 0x4e, 0x00, 0x01, 0x90]),
                InfoHsr::SeqNr(64521),
                InfoHsr::Protocol(HsrProtocol::Hsr),
            ])),
        ])],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();

    expected.emit(&mut buf).unwrap();

    assert_eq!(buf, raw);
}

#[test]
fn test_parsing_interlink_hsr() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x68, 0x73, 0x72, 0x00, 0x40, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x08, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00,
        0x01, 0x15, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00,
        0xff, 0xfb, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 45,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Broadcast
                | LinkFlags::LowerUp
                | LinkFlags::Multicast
                | LinkFlags::Running
                | LinkFlags::Up,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Hsr),
            LinkInfo::Data(InfoData::Hsr(vec![
                InfoHsr::Port1(4),
                InfoHsr::Port2(6),
                InfoHsr::Interlink(9),
                InfoHsr::SupervisionAddr([0x01, 0x15, 0x4e, 0x00, 0x01, 0x00]),
                InfoHsr::SeqNr(64511),
                InfoHsr::Version(HsrVersion::V1),
                InfoHsr::Protocol(HsrProtocol::Hsr),
            ])),
        ])],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();

    expected.emit(&mut buf).unwrap();

    assert_eq!(buf, raw);
}
