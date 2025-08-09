// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_packet_utils::{nla::DefaultNla, Emitable, Parseable};

use crate::link::{
    GreEncapFlags, GreEncapType, GreIOFlags, InfoData, InfoGreTun, InfoGreTun6,
    InfoKind, LinkAttribute, LinkInfo, LinkMessage, LinkMessageBuffer,
};

#[test]
fn test_create_gre6_external() {
    // This is nlmon capture for `ip link add name foo type ip6gre external`
    // on Linux kernel 6.15.9 with iproute2 version 6.16.0
    let raw: Vec<u8> = vec![
        0x00, // interface family AF_UNSPEC
        0x00, // reserved
        0x00, 0x00, // link layer type 0
        0x00, 0x00, 0x00, 0x00, // iface index 0
        0x00, 0x00, 0x00, 0x00, // device flags 0
        0x00, 0x00, 0x00, 0x00, // change flags 0
        0x08, 0x00, // length 8
        0x03, 0x00, // device name
        0x66, 0x6f, 0x6f, 0x00, // foo\0
        0x18, 0x00, // length 24
        0x12, 0x00, // IFLA_LINKINFO 18
        0x0b, 0x00, // length 12
        0x01, 0x00, // IFLA_INFO_KIND 1
        0x69, 0x70, 0x36, 0x67, 0x72, 0x65, 0x00, // ip6gre\0
        // NOTE: padding is included in the length (0x0b) by the Kernel
        //   response but iproute does not include the padding (0x0a).
        0x00, //padding
        0x08, 0x00, // length 8
        0x02, 0x00, // IFLA_INFO_DATA 2
        0x04, 0x00, // length 4
        0x12, 0x00, // IFLA_GRE_COLLECT_METADATA 18
    ];

    let expected = LinkMessage {
        attributes: vec![
            LinkAttribute::IfName("foo".to_string()),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::GreTun6),
                LinkInfo::Data(InfoData::GreTun6(vec![
                    InfoGreTun6::CollectMetadata,
                ])),
            ]),
        ],
        ..Default::default()
    };
    assert_eq!(
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap(),
        expected
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

#[test]
fn test_create_gre6() {
    // This is nlmon capture was created on Linux kernel 6.15.9 with iproute
    // version 6.16.0:
    // ```sh
    // ip link add name foo type ip6gre \
    //   ikey 42 okey 42 \
    //   local fc00::1 remote fc00::2 \
    //   ttl 64 encaplimit 2 flowlabel 42 \
    //   encap-sport 4242 encap-dport 4242
    // ```
    let raw: Vec<u8> = vec![
        0x00, // interface family AF_UNSPEC
        0x00, // reserved
        0x00, 0x00, // link layer type 0
        0x00, 0x00, 0x00, 0x00, // iface index 0
        0x00, 0x00, 0x00, 0x00, // device flags 0
        0x00, 0x00, 0x00, 0x00, // change flags 0
        0x08, 0x00, // length 8
        0x03, 0x00, // device name
        0x66, 0x6f, 0x6f, 0x00, // foo\0
        0xac, 0x00, // length 172
        0x12, 0x00, // IFLA_LINKINFO 18
        0x0b, 0x00, // length 12
        0x01, 0x00, // IFLA_INFO_KIND 1
        0x69, 0x70, 0x36, 0x67, 0x72, 0x65, 0x00, // ip6gre\0
        // NOTE: padding is included in the length (0x0b) by the Kernel
        // response   but iproute does not include the padding (0x0a).
        0x00, // padding
        0x9c, 0x00, // length 156
        0x02, 0x00, // IFLA_INFO_DATA 2
        0x08, 0x00, // length 8
        0x04, 0x00, // IFLA_GRE_IKEY 4
        0x00, 0x00, 0x00, 0x2a, // 42
        0x08, 0x00, // length 8
        0x05, 0x00, // IFLA_GRE_OKEY 5
        0x00, 0x00, 0x00, 0x2a, // 42
        0x06, 0x00, // length 6
        0x02, 0x00, // IFLA_GRE_IFLAGS 2
        0x20, 0x00, // GRE_KEY
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x03, 0x00, // IFLA_GRE_OFLAGS 3
        0x20, 0x00, // GRE_KEY
        0x00, 0x00, // padding
        0x14, 0x00, // length 20
        0x06, 0x00, // IFLA_LOCAL 6
        0xfc, 0x00, 0x00, 0x00, // fc00::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x14, 0x00, // length 20
        0x07, 0x00, // IFLA_REMOTE 7
        0xfc, 0x00, 0x00, 0x00, // fc00::2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x05, 0x00, // length 5
        0x08, 0x00, // IFLA_TTL 8
        0x40, // 64
        0x00, 0x00, 0x00, // padding
        0x05, 0x00, // length 5
        0x0b, 0x00, // IFLA_GRE_ENCAP_LIMIT 11
        0x02, // 2
        0x00, 0x00, 0x00, // padding
        0x08, 0x00, // length 8
        0x0c, 0x00, // IFLA_GRE_FLOWINFO 12
        0x00, 0x00, 0x00, 0x42, // 0x00042
        0x08, 0x00, // length 8
        0x0d, 0x00, // IFLA_GRE_FLAGS 13
        0x00, 0x00, 0x00, 0x00, // 0
        0x08, 0x00, // length 8
        0x14, 0x00, // IFLA_GRE_FWMARK 20
        0x00, 0x00, 0x00, 0x00, //
        0x05, 0x00, // length 5
        0x16, 0x00, // IFLA_GRE_ERSPAN_VER 22
        0x01, // 1
        0x00, 0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x0e, 0x00, // IFLA_GRE_ENCAP_TYPE 14
        0x00, 0x00, // UNSPEC
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x0f, 0x00, // IFLA_GRE_ENCAP_FLAGS 15
        0x02, 0x00, //
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x10, 0x00, // IFLA_GRE_ENCAP_SPORT 16
        0x10, 0x92, // 4242
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x11, 0x00, // IFLA_GRE_ENCAP_DPORT 17
        0x10, 0x92, // 4242
        0x00, 0x00, // padding
    ];

    let expected = LinkMessage {
        attributes: vec![
            LinkAttribute::IfName("foo".to_string()),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::GreTun6),
                LinkInfo::Data(InfoData::GreTun6(vec![
                    InfoGreTun6::IKey(42),
                    InfoGreTun6::OKey(42),
                    InfoGreTun6::IFlags(GreIOFlags::Key),
                    InfoGreTun6::OFlags(GreIOFlags::Key),
                    InfoGreTun6::Local(Ipv6Addr::new(
                        0xfc00, 0, 0, 0, 0, 0, 0, 0x01,
                    )),
                    InfoGreTun6::Remote(Ipv6Addr::new(
                        0xfc00, 0, 0, 0, 0, 0, 0, 0x02,
                    )),
                    InfoGreTun6::Ttl(64),
                    InfoGreTun6::EncapLimit(2),
                    InfoGreTun6::FlowLabel(0x42),
                    InfoGreTun6::Flags(0),
                    InfoGreTun6::FwMask(0),
                    InfoGreTun6::Other(DefaultNla::new(22, vec![0x01])),
                    InfoGreTun6::EncapType(GreEncapType::default()),
                    // enabled by default for IPv6
                    InfoGreTun6::EncapFlags(GreEncapFlags::Checksum6),
                    InfoGreTun6::SourcePort(4242),
                    InfoGreTun6::DestinationPort(4242),
                ])),
            ]),
        ],
        ..Default::default()
    };
    assert_eq!(
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap(),
        expected
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

#[test]
fn test_create_gre_external() {
    // This is nlmon capture for `ip link add name foo type gre external`
    // on Linux kernel 6.15.9 with iproute2 version 6.16.0
    let raw: Vec<u8> = vec![
        0x00, // interface family AF_UNSPEC
        0x00, // reserved
        0x00, 0x00, // link layer type 0
        0x00, 0x00, 0x00, 0x00, // iface index 0
        0x00, 0x00, 0x00, 0x00, // device flags 0
        0x00, 0x00, 0x00, 0x00, // change flags 0
        0x08, 0x00, // length 8
        0x03, 0x00, // device name
        0x66, 0x6f, 0x6f, 0x00, // foo\0
        0x14, 0x00, // length 20
        0x12, 0x00, // IFLA_LINKINFO 18
        0x08, 0x00, // length 7
        0x01, 0x00, // IFLA_INFO_KIND 1
        0x67, 0x72, 0x65, 0x00, // gre\0
        0x08, 0x00, // length 8
        0x02, 0x00, // IFLA_INFO_DATA 2
        0x04, 0x00, // length 4
        0x12, 0x00, // IFLA_GRE_COLLECT_METADATA 18
    ];

    let expected = LinkMessage {
        attributes: vec![
            LinkAttribute::IfName("foo".to_string()),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::GreTun),
                LinkInfo::Data(InfoData::GreTun(vec![
                    InfoGreTun::CollectMetadata,
                ])),
            ]),
        ],
        ..Default::default()
    };
    assert_eq!(
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap(),
        expected
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}

#[test]
fn test_create_gre() {
    // This is nlmon capture was created on Linux kernel 6.15.9 with iproute
    // version 6.16.0: ```sh
    // ip link add name foo type gre \
    //   ikey 42 okey 42 \
    //   local 192.0.2.1 remote 192.0.2.2 \
    //   ttl 64 encap-sport 4242 encap-dport 4242
    // ```
    let raw: Vec<u8> = vec![
        0x00, // interface family AF_UNSPEC
        0x00, // reserved
        0x00, 0x00, // link layer type 0
        0x00, 0x00, 0x00, 0x00, // iface index 0
        0x00, 0x00, 0x00, 0x00, // device flags 0
        0x00, 0x00, 0x00, 0x00, // change flags 0
        0x08, 0x00, // length 8
        0x03, 0x00, // device name
        0x66, 0x6f, 0x6f, 0x00, // foo\0
        0x80, 0x00, // length 128
        0x12, 0x00, // IFLA_LINKINFO 18
        0x08, 0x00, // length 12
        0x01, 0x00, // IFLA_INFO_KIND 1
        0x67, 0x72, 0x65, 0x00, // gre\0
        0x74, 0x00, // length 116
        0x02, 0x00, // IFLA_INFO_DATA 2
        0x08, 0x00, // length 8
        0x04, 0x00, // IFLA_GRE_IKEY 4
        0x00, 0x00, 0x00, 0x2a, // 42
        0x08, 0x00, // length 8
        0x05, 0x00, // IFLA_GRE_OKEY 5
        0x00, 0x00, 0x00, 0x2a, // 42
        0x06, 0x00, // length 6
        0x02, 0x00, // IFLA_GRE_IFLAGS 2
        0x20, 0x00, // GRE_KEY
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x03, 0x00, // IFLA_GRE_OFLAGS 3
        0x20, 0x00, // GRE_KEY
        0x00, 0x00, // padding
        0x08, 0x00, // length 8
        0x06, 0x00, // IFLA_LOCAL 6
        0xc0, 0x00, 0x02, 0x01, // 192.0.2.1
        0x08, 0x00, // length 8
        0x07, 0x00, // IFLA_REMOTE 7
        0xc0, 0x00, 0x02, 0x01, // 192.0.2.2
        0x05, 0x00, // length 5
        0x0a, 0x00, // IFLA_GRE_PMTUDISC 10
        0x01, //
        0x00, 0x00, 0x00, // padding
        0x05, 0x00, // length 5
        0x09, 0x00, // IFLA_GRE_TOS 9
        0x00, // 0
        0x00, 0x00, 0x00, // padding
        0x05, 0x00, // length 5
        0x08, 0x00, // IFLA_TTL 8
        0x40, // 64
        0x00, 0x00, 0x00, // padding
        0x08, 0x00, // length 8,
        0x14, 0x00, // IFLA_GRE_FWMARK 20
        0x00, 0x00, 0x00, 0x00, //
        0x06, 0x00, // length 6
        0x0e, 0x00, // IFLA_GRE_ENCAP_TYPE 14
        0x00, 0x00, // UNSPEC
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x0f, 0x00, // IFLA_GRE_ENCAP_FLAGS 15
        0x00, 0x00, //
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x10, 0x00, // IFLA_GRE_ENCAP_SPORT 16
        0x10, 0x92, // 4242
        0x00, 0x00, // padding
        0x06, 0x00, // length 6
        0x11, 0x00, // IFLA_GRE_ENCAP_DPORT 17
        0x10, 0x92, // 4242
        0x00, 0x00, // padding
    ];

    let expected = LinkMessage {
        attributes: vec![
            LinkAttribute::IfName("foo".to_string()),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::GreTun),
                LinkInfo::Data(InfoData::GreTun(vec![
                    InfoGreTun::IKey(42),
                    InfoGreTun::OKey(42),
                    InfoGreTun::IFlags(GreIOFlags::Key),
                    InfoGreTun::OFlags(GreIOFlags::Key),
                    InfoGreTun::Local(Ipv4Addr::new(192, 0, 2, 1)),
                    InfoGreTun::Remote(Ipv4Addr::new(192, 0, 2, 1)),
                    InfoGreTun::PathMTUDiscovery(true), // enabled by default
                    InfoGreTun::Tos(0),
                    InfoGreTun::Ttl(64),
                    InfoGreTun::FwMask(0),
                    InfoGreTun::EncapType(GreEncapType::default()),
                    InfoGreTun::EncapFlags(GreEncapFlags::default()),
                    InfoGreTun::SourcePort(4242),
                    InfoGreTun::DestinationPort(4242),
                ])),
            ]),
        ],
        ..Default::default()
    };
    assert_eq!(
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap(),
        expected
    );
    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
