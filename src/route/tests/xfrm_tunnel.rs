// SPDX-License-Identifier: MIT

use std::{net::Ipv4Addr, str::FromStr};

use netlink_packet_core::{Emitable, Parseable};

use crate::{
    route::{
        RouteAttribute, RouteFlags, RouteHeader, RouteLwEnCapType,
        RouteLwTunnelEncap, RouteMessage, RouteProtocol, RouteScope, RouteType,
        RouteXfrmTunnel,
    },
    AddressFamily,
};

// Setup:
//      ip link add d0 type dummy
//      ip link set d0 up
//      ip route add 10.118.0.0/16 dev d0 encap xfrm if_id 1
// nlmon capture(netlink message header removed) against command:
//      ip route show 10.118.0.0/16
#[test]
fn test_xfrm_tunnel() {
    let raw = vec![
        0x02, 0x10, 0x00, 0x00, 0xfe, 0x03, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x0a, 0x76, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x16, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x15, 0x00, 0x0a, 0x00, 0x00, 0x00,
    ];

    let expected = RouteMessage {
        header: RouteHeader {
            address_family: AddressFamily::Inet,
            destination_prefix_length: 16,
            source_prefix_length: 0,
            tos: 0,
            table: 254,
            protocol: RouteProtocol::Boot,
            scope: RouteScope::Link,
            kind: RouteType::Unicast,
            flags: RouteFlags::empty(),
        },
        attributes: vec![
            RouteAttribute::Table(254),
            RouteAttribute::Destination(
                Ipv4Addr::from_str("10.118.0.0").unwrap().into(),
            ),
            RouteAttribute::Oif(11),
            RouteAttribute::Encap(vec![RouteLwTunnelEncap::Xfrm(
                RouteXfrmTunnel::IfId(1),
            )]),
            RouteAttribute::EncapType(RouteLwEnCapType::Xfrm),
        ],
    };

    assert_eq!(expected, RouteMessage::parse(&raw).unwrap());

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    // The capture above comes from a kernel dump which does not set
    // `NLA_F_NESTED` on `RTA_ENCAP`, while `iproute2` and this crate do
    // because the kernel requires the flag for `LWTUNNEL_ENCAP_XFRM`.
    assert_eq!(expected, RouteMessage::parse(&buf).unwrap());
}
