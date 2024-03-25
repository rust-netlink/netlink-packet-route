// SPDX-License-Identifier: MIT

use netlink_packet_utils::{Emitable, Parseable};

use crate::link::link_flag::LinkFlags;
use crate::link::{
    InfoData, InfoKind, InfoVrf, LinkAttribute, LinkHeader, LinkInfo,
    LinkLayerType, LinkMessage, LinkMessageBuffer,
};
use crate::AddressFamily;

#[test]
fn test_parsing_link_vrf() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0xc1, 0x04, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x12, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x76, 0x72, 0x66, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x0a, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 34,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Controller
                | LinkFlags::LowerUp
                | LinkFlags::Noarp
                | LinkFlags::Running
                | LinkFlags::Up,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vrf),
            LinkInfo::Data(InfoData::Vrf(vec![InfoVrf::TableId(10)])),
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
