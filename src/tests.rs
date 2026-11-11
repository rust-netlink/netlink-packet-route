// SPDX-License-Identifier: MIT
// This file only contains testing parsing RouteNetlinkMessage, not
// focusing on detailed sub-component parsing. Each component has its own
// test module.
use netlink_packet_core::{
    Emitable, NetlinkHeader, NetlinkMessage, NetlinkPayload, Nla,
    ParseableParametrized,
};

use crate::{
    link::{LinkAttribute, LinkExtentMask, LinkMessage},
    RouteNetlinkMessage,
};

fn link_capture() -> Vec<u8> {
    // wireshark capture of nlmon against command:
    //   ip link show dev lo
    vec![
        0x30, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x00, 0xe6, 0x9c, 0x69, 0x65,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1d, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x07, 0x00, 0x03, 0x00, 0x6c, 0x6f, 0x00, 0x00,
    ]
}

// wireshark capture of nlmon against command:
//   ip link show dev lo
#[test]
fn test_get_link() {
    let raw = link_capture();

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

// Payload parsing must reject a buffer shorter than the message header
// instead of slicing it.
#[test]
fn test_short_message_payloads_return_error() {
    // One RTM_NEW* message type per supported family, with the length of
    // its wire header.
    for (message_type, header_len) in [
        (16u16, 16usize), // RTM_NEWLINK
        (20, 8),          // RTM_NEWADDR
        (24, 12),         // RTM_NEWROUTE
        (28, 12),         // RTM_NEWNEIGH
        (32, 12),         // RTM_NEWRULE
        (36, 20),         // RTM_NEWQDISC
        (48, 4),          // RTM_NEWACTION
        (52, 12),         // RTM_NEWPREFIX
        (64, 4),          // RTM_NEWNEIGHTBL
        (72, 12),         // RTM_NEWADDRLABEL
        (88, 4),          // RTM_NEWNSID
        (92, 12),         // RTM_NEWSTATS
    ] {
        for len in 0..header_len {
            let buffer = vec![0u8; len];
            let result =
                RouteNetlinkMessage::parse_with_param(&buffer, message_type);
            assert!(
                result.is_err(),
                "message type {message_type} accepted a {len}-byte buffer"
            );
        }
    }
}

// Truncating a valid netlink message at any point must return an error, not
// panic in a parser slicing the payload.
#[test]
fn test_deserialize_does_not_panic_on_truncated_input() {
    let raw = link_capture();
    for len in 0..=raw.len() {
        let result = std::panic::catch_unwind(|| {
            let _ =
                NetlinkMessage::<RouteNetlinkMessage>::deserialize(&raw[..len]);
        });
        assert!(result.is_ok(), "deserialize panicked for {len} bytes");
    }
}
