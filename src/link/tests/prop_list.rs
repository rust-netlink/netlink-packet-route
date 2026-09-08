// SPDX-License-Identifier: MIT

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use netlink_packet_core::Emitable;
#[cfg(target_os = "linux")]
use netlink_packet_core::Parseable;
#[cfg(target_os = "freebsd")]
use netlink_packet_core::{NlaBuffer, ParseableParametrized};

#[cfg(target_os = "linux")]
use crate::link::{
    link_flag::LinkFlags, LinkHeader, LinkLayerType, LinkMessage,
};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::{
    link::{LinkAttribute, Prop},
    AddressFamily,
};

#[cfg(target_os = "linux")]
#[test]
fn test_wlan0_with_prop_altname() {
    // nlmon dump of `ip link show wlan0` with two alt_name for wlan0 with
    // IFLA_PROP_LIST only
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x34, 0x80, 0x0e, 0x00, 0x35, 0x00,
        0x77, 0x6c, 0x70, 0x30, 0x73, 0x32, 0x30, 0x66, 0x33, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x35, 0x00, 0x77, 0x69, 0x66, 0x69, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 2,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Broadcast
                | LinkFlags::LowerUp
                | LinkFlags::Multicast
                | LinkFlags::Running
                | LinkFlags::Up,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![LinkAttribute::PropList(vec![
            Prop::AltIfName("wlp0s20f3".to_string()),
            Prop::AltIfName("wifi".to_string()),
        ])],
    };

    assert_eq!(expected, LinkMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

#[cfg(target_os = "freebsd")]
#[test]
fn test_freebsd_prop_list_roundtrip() {
    let raw = [
        0x20, 0x00, 0x34, 0x80, // IFLA_PROP_LIST | NLA_F_NESTED
        0x0e, 0x00, 0x35, 0x00, // IFLA_ALT_IFNAME: wlp0s20f3
        0x77, 0x6c, 0x70, 0x30, 0x73, 0x32, 0x30, 0x66, 0x33, 0x00, 0x00,
        0x00, // padding
        0x09, 0x00, 0x35, 0x00, // IFLA_ALT_IFNAME: wifi
        0x77, 0x69, 0x66, 0x69, 0x00, 0x00, 0x00, 0x00, // padding
    ];
    let expected = LinkAttribute::PropList(vec![
        Prop::AltIfName("wlp0s20f3".into()),
        Prop::AltIfName("wifi".into()),
    ]);

    let parsed = LinkAttribute::parse_with_param(
        &NlaBuffer::new_checked(&raw).unwrap(),
        AddressFamily::Unspec,
    )
    .unwrap();
    assert_eq!(parsed, expected);

    let mut buf = vec![0; expected.buffer_len()];
    expected.emit(&mut buf);
    assert_eq!(buf, raw);
}
