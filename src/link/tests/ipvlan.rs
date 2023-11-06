// SPDX-License-Identifier: MIT

use netlink_packet_utils::{Emitable, Parseable};

use crate::link::{
    InfoData, InfoIpVlan, InfoKind, LinkAttribute, LinkFlag, LinkHeader,
    LinkInfo, LinkLayerType, LinkMessage, LinkMessageBuffer,
};
use crate::AddressFamily;

#[test]
fn test_ipvlan_link_info() {
    let raw: Vec<u8> = vec![
        0x00, 0x00, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x12, 0x00, 0x0b, 0x00, 0x01, 0x00,
        0x69, 0x70, 0x76, 0x6c, 0x61, 0x6e, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00,
        0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x02, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 18,
            link_layer_type: LinkLayerType::Ether,
            flags: vec![LinkFlag::Broadcast, LinkFlag::Multicast],
            change_mask: 0,
        },
        attributes: vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::IpVlan),
            LinkInfo::Data(InfoData::IpVlan(vec![
                InfoIpVlan::Mode(0),
                InfoIpVlan::Flags(2),
            ])),
        ])],
    };

    assert_eq!(
        expected,
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
