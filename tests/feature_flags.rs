// SPDX-License-Identifier: MIT

#[test]
#[cfg(not(feature = "address"))]
fn disabled_message_family_is_rejected() {
    use netlink_packet_core::ParseableParametrized;
    use netlink_packet_route::RouteNetlinkMessage;

    // RTM_NEWADDR must be rejected even when the payload is otherwise valid.
    let error = RouteNetlinkMessage::parse_with_param(&[0; 8], 20).unwrap_err();
    assert!(error.to_string().contains("Unknown message type: 20"));
}

#[test]
#[cfg(all(
    feature = "link",
    any(
        not(feature = "link-info"),
        not(feature = "link-sriov"),
        not(feature = "link-af-spec")
    )
))]
fn disabled_link_attributes_round_trip_as_opaque_data() {
    use netlink_packet_core::{
        Emitable, NlaBuffer, ParseableParametrized, NLA_F_NESTED,
    };
    use netlink_packet_route::{link::LinkAttribute, AddressFamily};

    let mut kinds = Vec::new();
    #[cfg(not(feature = "link-info"))]
    kinds.push(18u16); // IFLA_LINKINFO
    #[cfg(not(feature = "link-sriov"))]
    kinds.extend([22u16, 24, 25]); // VFINFO_LIST, VF_PORTS, PORT_SELF
    #[cfg(not(feature = "link-af-spec"))]
    kinds.push(26u16); // IFLA_AF_SPEC

    for kind in kinds {
        let mut bytes = [0u8; 8];
        bytes[..2].copy_from_slice(&8u16.to_ne_bytes());
        bytes[2..4].copy_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        bytes[4..].copy_from_slice(&[1, 2, 3, 4]);
        let nla = NlaBuffer::new_checked(&bytes).unwrap();
        let attr = LinkAttribute::parse_with_param(&nla, AddressFamily::Unspec)
            .unwrap();
        assert!(matches!(attr, LinkAttribute::Other(_)));
        let mut emitted = [0u8; 8];
        attr.emit(&mut emitted);
        assert_eq!(emitted, bytes);
    }
}
