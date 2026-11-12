// SPDX-License-Identifier: MIT
#![cfg(not(target_endian = "big"))]
use netlink_packet_core::{DefaultNla, Emitable, Parseable};

use crate::{
    link::{
        InfoData, InfoDsa, InfoKind, InfoOvpn, InfoPpp, InfoTun, LinkAttribute,
        LinkFlags, LinkHeader, LinkInfo, LinkLayerType, LinkMessage, OvpnMode,
    },
    AddressFamily,
};

// nlmon capture of the kernel `RTM_NEWLINK` notification (netlink header
// removed) on Linux 7.2.14 after:
//
//      ip link add ifbtest0 type ifb
#[test]
fn test_parsing_link_ifb() {
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x03, 0x00, 0x69, 0x66, 0x62, 0x74,
        0x65, 0x73, 0x74, 0x30, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x12, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x69, 0x66, 0x62, 0x00,
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
            LinkAttribute::IfName("ifbtest0".to_string()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Ifb)]),
        ],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

// nlmon capture of the kernel `RTM_NEWLINK` notification (netlink header
// removed) on Linux 7.2.14 after:
//
//      ip link add nlmontest0 type nlmon
#[test]
fn test_parsing_link_nlmon() {
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x03, 0x00, 0x6e, 0x6c, 0x6d, 0x6f,
        0x6e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x00, 0x00, 0x10, 0x00, 0x12, 0x00,
        0x0a, 0x00, 0x01, 0x00, 0x6e, 0x6c, 0x6d, 0x6f, 0x6e, 0x00, 0x00, 0x00,
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
            LinkAttribute::IfName("nlmontest0".to_string()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Nlmon)]),
        ],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

// nlmon capture of the kernel `RTM_NEWLINK` notification (netlink header
// removed) on Linux 7.2.14 after:
//
//      ip link add teamtest0 type team
#[test]
fn test_parsing_link_team() {
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x74, 0x65, 0x61, 0x6d,
        0x74, 0x65, 0x73, 0x74, 0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x12, 0x00,
        0x09, 0x00, 0x01, 0x00, 0x74, 0x65, 0x61, 0x6d, 0x00, 0x00, 0x00, 0x00,
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
            LinkAttribute::IfName("teamtest0".to_string()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Team)]),
        ],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

// nlmon capture of the kernel `RTM_NEWLINK` notification (netlink header
// removed) on Linux 7.2.14 after:
//
//      ip link add vwtest0 link eth0 type virt_wifi
#[test]
fn test_parsing_link_virt_wifi() {
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00, 0x69, 0x05, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x76, 0x77, 0x74, 0x65, 0x73, 0x74, 0x30, 0x00,
        0x14, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x76, 0x69, 0x72, 0x74,
        0x5f, 0x77, 0x69, 0x66, 0x69, 0x00, 0x00, 0x00,
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
            LinkAttribute::Link(1385),
            LinkAttribute::IfName("vwtest0".to_string()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::VirtWifi)]),
        ],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

// nlmon capture of the kernel reply to `ip -d link show lan1` (netlink
// header removed) on Linux 7.2.14, trimmed to `IFLA_LINKINFO`. The `lan1`
// port was created by the `dsa_loop` driver:
//
//      ip link add eth0 type dummy
//      ip link set eth0 up
//      modprobe dsa_loop
#[test]
fn test_parsing_link_dsa() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x73, 0x05, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x64, 0x73, 0x61, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x69, 0x05, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 1395,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Broadcast | LinkFlags::Multicast,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Dsa),
            LinkInfo::Data(InfoData::Dsa(vec![InfoDsa::Conduit(1385)])),
        ])],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

// nlmon capture of the kernel reply to `ip -d link show tuntest0` (netlink
// header removed) on Linux 7.2.14, trimmed to `IFLA_LINKINFO`. The device
// was created by:
//
//      ip tuntap add dev tuntest0 mode tun
#[test]
fn test_parsing_link_tun() {
    let raw = vec![
        0x00, 0x00, 0xfe, 0xff, 0x72, 0x05, 0x00, 0x00, 0x90, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x74, 0x75, 0x6e, 0x00, 0x2c, 0x00, 0x02, 0x00, 0x05, 0x00, 0x03, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 1394,
            link_layer_type: LinkLayerType::None,
            flags: LinkFlags::Pointopoint
                | LinkFlags::Noarp
                | LinkFlags::Multicast,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Tun),
            LinkInfo::Data(InfoData::Tun(vec![
                InfoTun::Other(DefaultNla::new(3, vec![1])),
                InfoTun::Other(DefaultNla::new(4, vec![0])),
                InfoTun::Other(DefaultNla::new(5, vec![0])),
                InfoTun::Other(DefaultNla::new(6, vec![1])),
                InfoTun::Other(DefaultNla::new(7, vec![0])),
            ])),
        ])],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

// nlmon capture of the kernel `RTM_NEWLINK` request (netlink header removed)
// generated after loading the `ovpn` module:
//
//      ip link add ovpntest0 type ovpn mode mp
//
// This specific `ip` build rejected the mode option, so the request was
// sent through rtnetlink directly.
#[test]
fn test_parsing_link_ovpn() {
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x6f, 0x76, 0x70, 0x6e,
        0x74, 0x65, 0x73, 0x74, 0x30, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x12, 0x00,
        0x09, 0x00, 0x01, 0x00, 0x6f, 0x76, 0x70, 0x6e, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
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
            LinkAttribute::IfName("ovpntest0".to_string()),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Ovpn),
                LinkInfo::Data(InfoData::Ovpn(vec![InfoOvpn::Mode(
                    OvpnMode::Mp,
                )])),
            ]),
        ],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}

// nlmon capture of the kernel `RTM_NEWLINK` request (netlink header removed)
// generated by:
//
//      ip link add ppptest0 type ppp fd 3
//
// The `ip` build does not support the ppp link kind, so the request was
// sent through rtnetlink directly with an open `/dev/ppp` file descriptor.
#[test]
fn test_parsing_link_ppp() {
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x03, 0x00, 0x70, 0x70, 0x70, 0x74,
        0x65, 0x73, 0x74, 0x30, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x12, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x70, 0x70, 0x70, 0x00, 0x0c, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
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
            LinkAttribute::IfName("ppptest0".to_string()),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Ppp),
                LinkInfo::Data(InfoData::Ppp(vec![InfoPpp::DevFd(3)])),
            ]),
        ],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = Vec::new();
    expected.emit(&mut buf).unwrap();
    assert_eq!(buf, raw);
}
