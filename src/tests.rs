// SPDX-License-Identifier: MIT
// This file only contains testing parsing RouteNetlinkMessage, not
// focusing on detailed sub-component parsing. Each component has its own
// test module.
use netlink_packet_core::{
    Emitable, NetlinkHeader, NetlinkMessage, NetlinkPayload, Nla,
};

use crate::{
    link::{LinkAttribute, LinkExtentMask, LinkMessage},
    RouteNetlinkMessage,
};

// wireshark capture of nlmon against command:
//   ip link show dev lo
#[test]
fn test_get_link() {
    let raw: Vec<u8> = vec![
        0x30, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x00, 0xe6, 0x9c, 0x69, 0x65,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1d, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x07, 0x00, 0x03, 0x00, 0x6c, 0x6f, 0x00, 0x00,
    ];

    let mut header = NetlinkHeader::default();
    header.length = 48;
    header.message_type = 18;
    header.flags = 1;
    header.sequence_number = 1701420262;

    let expected = NetlinkMessage::new(
        header,
        NetlinkPayload::from(RouteNetlinkMessage::GetLink(LinkMessage {
            attributes: vec![
                LinkAttribute::ExtMask(vec![
                    LinkExtentMask::Vf,
                    LinkExtentMask::SkipStats,
                ]),
                LinkAttribute::IfName("lo".to_string()),
            ],
            ..Default::default()
        })),
    );

    assert_eq!(NetlinkMessage::deserialize(&raw).unwrap(), expected);
    let mut buffer = Vec::new();
    expected.emit(&mut buffer).unwrap();
    assert_eq!(buffer.as_slice(), raw);
}

// Emission appends to the buffer and zeroes the padding after the attribute
// value instead of leaving whatever was previously stored there.
#[test]
fn test_emit_appends_and_zeroes_nla_padding() {
    let attribute = LinkAttribute::IfName("lo".to_string());
    let mut buffer = vec![0xaa, 0xbb];
    attribute.emit(&mut buffer).unwrap();

    assert_eq!(&buffer[..2], &[0xaa, 0xbb]);
    // IFLA_IFNAME: len=7, type=3, value="lo\0", followed by one zero padding
    // byte.
    assert_eq!(
        &buffer[2..],
        &[0x07, 0x00, 0x03, 0x00, b'l', b'o', 0x00, 0x00]
    );
}
