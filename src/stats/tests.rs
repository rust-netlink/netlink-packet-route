// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, Nla, NlaBuffer, NlasIterator,
    Parseable,
};

use crate::{
    stats::{
        BridgeMcastStats, BridgeStpXstats, BridgeVlanXstats, BridgeXstat,
        HwStats64, LinkXstatGroup, OffloadXstat, StatsAttribute, StatsHeader,
        StatsMessage, StatsMessageBuffer,
    },
    RouteNetlinkMessage,
};

// ---------------------------------------------------------------------------
// nlmon capture: ip stats show dev br-8fd093ec54e9 group xstats
//   -> RTM_GETSTATS request, kernel responds with RTM_NEWSTATS
// Expected: bridge LINK_XSTATS with VLAN + MCAST data
// ---------------------------------------------------------------------------
#[test]
fn test_bridge_xstats_from_nlmon() {
    let raw: Vec<u8> = vec![
        0x44, 0x01, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x28, 0x58, 0x32, 0x6a,
        0x23, 0x76, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x28, 0x01, 0x02, 0x00, 0x24, 0x01, 0x01, 0x00,
        0x2c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&raw)
        .expect("failed to deserialize bridge xstats");

    let stats = match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewStats(s)) => s,
        _ => panic!("expected NewStats"),
    };

    assert_eq!(stats.header.ifindex, 3);
    assert_eq!(stats.header.filter_mask, 2);
    assert_eq!(stats.attributes.len(), 1);

    let attr = &stats.attributes[0];
    match attr {
        StatsAttribute::LinkXstats(groups) => {
            assert_eq!(groups.len(), 1);
            match &groups[0] {
                LinkXstatGroup::Bridge(entries) => {
                    assert_eq!(entries.len(), 2);
                    // First entry should be VLAN, second should be MCAST
                    match &entries[0] {
                        BridgeXstat::Vlan(vlan) => {
                            assert_eq!(vlan.vid, 1);
                            assert_eq!(vlan.flags, 0x27);
                        }
                        other => panic!("expected Vlan, got {:?}", other),
                    }
                    match &entries[1] {
                        BridgeXstat::Mcast(mcast) => {
                            // All zero bridge mcast stats
                            assert_eq!(mcast.igmp_v1queries_rx, 0);
                            assert_eq!(mcast.igmp_v1queries_tx, 0);
                        }
                        other => panic!("expected Mcast, got {:?}", other),
                    }
                }
                other => panic!("expected Bridge, got {:?}", other),
            }
        }
        other => panic!("expected LinkXstats, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// nlmon capture: ip stats show dev enp2s0 group offload
//   -> RTM_NEWSTATS with IFLA_STATS_LINK_OFFLOAD_XSTATS
// Expected: HW_S_INFO containing L3_STATS (both request/used = 0)
// ---------------------------------------------------------------------------
#[test]
fn test_offload_xstats_from_nlmon() {
    let raw: Vec<u8> = vec![
        0x38, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x29, 0x58, 0x32, 0x6a,
        0x25, 0x76, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x18, 0x00, 0x02, 0x80,
        0x14, 0x00, 0x03, 0x80, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&raw)
        .expect("failed to deserialize offload xstats");

    let stats = match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewStats(s)) => s,
        _ => panic!("expected NewStats"),
    };

    assert_eq!(stats.header.ifindex, 2);
    assert_eq!(stats.header.filter_mask, 8);
    assert_eq!(stats.attributes.len(), 1);

    match &stats.attributes[0] {
        StatsAttribute::LinkOffloadXstats(entries) => {
            assert_eq!(entries.len(), 1);
            match &entries[0] {
                OffloadXstat::HwSInfo(info) => {
                    assert_eq!(info.request, Some(0));
                    assert_eq!(info.used, Some(0));
                }
                other => panic!("expected HwSInfo, got {:?}", other),
            }
        }
        other => panic!("expected LinkOffloadXstats, got {:?}", other),
    }
}

#[test]
fn test_offload_xstats_parse_inner_nlas() {
    // Manually verify the NLA structure of offload xstats.
    // Raw offload xstats NLA payload from nlmon capture
    let payload: Vec<u8> = vec![
        0x18, 0x00, 0x02, 0x80, 0x14, 0x00, 0x03, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let entries = NlasIterator::new(&payload)
        .filter_map(|nla| nla.ok())
        .collect::<Vec<_>>();

    assert_eq!(entries.len(), 1);
    // The first NLA has type 0x8002 = NLA_F_NESTED |
    // IFLA_OFFLOAD_XSTATS_HW_S_INFO
    assert_eq!(entries[0].kind() & !0x8000, 2);
    // L3_STATS (type 3) is nested inside HW_S_INFO
    let inner = NlasIterator::new(entries[0].value())
        .filter_map(|nla| nla.ok())
        .collect::<Vec<_>>();
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].kind() & !0x8000, 3); // L3_STATS
                                              // Inside L3_STATS, we have request and used NLAs
    let l3_inner = NlasIterator::new(inner[0].value())
        .filter_map(|nla| nla.ok())
        .collect::<Vec<_>>();
    assert_eq!(l3_inner.len(), 2);
    assert_eq!(l3_inner[0].kind() & !0x8000, 1); // request
    assert_eq!(l3_inner[1].kind() & !0x8000, 2); // used
}

// ---------------------------------------------------------------------------
// nlmon capture: ip stats show dev lo
//   -> RTM_NEWSTATS with all filter_mask bits set (0x1f)
// Expected: LINK_64 + LINK_OFFLOAD_XSTATS + AF_SPEC attributes
// ---------------------------------------------------------------------------
#[test]
fn test_combined_stats_from_nlmon() {
    // nlmon capture: ip stats show dev lo (all filter_mask bits set)
    let raw: Vec<u8> = vec![
        0x08, 0x01, 0x00, 0x00, 0x5c, 0x00, 0x02, 0x00, 0x2b, 0x58, 0x32, 0x6a,
        0x2a, 0x76, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x1f, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x01, 0x00, 0x81, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xca, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xca, 0x30, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x00, 0x18, 0x00, 0x02, 0x80,
        0x14, 0x00, 0x03, 0x80, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00,
    ];
    assert_eq!(raw.len(), 264);
    assert_eq!(raw.len(), 264);

    let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&raw)
        .expect("failed to deserialize combined stats");

    let stats = match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewStats(s)) => s,
        _ => panic!("expected NewStats"),
    };

    assert_eq!(stats.header.ifindex, 1);
    assert_eq!(stats.header.filter_mask, 0x1f);
    // Should have 3 attributes: LINK_64, LINK_OFFLOAD_XSTATS, AF_SPEC
    assert_eq!(stats.attributes.len(), 3);

    // First attribute: LINK_64
    match &stats.attributes[0] {
        StatsAttribute::Link64(s64) => {
            assert_eq!(s64.rx_packets, 0x81);
            assert_eq!(s64.tx_packets, 0x81);
            assert_eq!(s64.rx_bytes, 0x30ca);
            assert_eq!(s64.tx_bytes, 0x30ca);
        }
        other => panic!("expected Link64, got {:?}", other),
    }

    // Second attribute: LINK_OFFLOAD_XSTATS
    match &stats.attributes[1] {
        StatsAttribute::LinkOffloadXstats(entries) => {
            assert_eq!(entries.len(), 1);
            match &entries[0] {
                OffloadXstat::HwSInfo(info) => {
                    assert_eq!(info.request, Some(0));
                    assert_eq!(info.used, Some(0));
                }
                other => panic!("expected HwSInfo, got {:?}", other),
            }
        }
        other => panic!("expected LinkOffloadXstats, got {:?}", other),
    }

    // Third attribute: AF_SPEC (empty for lo)
    match &stats.attributes[2] {
        StatsAttribute::AfSpec(spec) => {
            assert_eq!(spec.0.len(), 0);
        }
        other => panic!("expected AfSpec, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Existing tests (kept for backward compatibility)
// ---------------------------------------------------------------------------

#[test]
fn test_bridge_xstats_vlan_roundtrip() {
    let vlan = BridgeVlanXstats {
        vid: 1,
        flags: 0x27,
        ..Default::default()
    };
    let len = 4 + vlan.value_len();
    let mut buf = vec![0u8; len];
    buf[0..2].copy_from_slice(&(len as u16).to_ne_bytes());
    buf[2..4].copy_from_slice(&vlan.kind().to_ne_bytes());
    vlan.emit_value(&mut buf[4..]);

    let nla = NlaBuffer::new_checked(&buf).unwrap();
    assert_eq!(nla.kind(), 1);
    let parsed_val = BridgeVlanXstats::parse(nla.value()).unwrap();
    assert_eq!(parsed_val.vid, 1);
    assert_eq!(parsed_val.flags, 0x27);
    assert_eq!(parsed_val.rx_bytes, 0);
}

#[test]
fn test_bridge_xstats_construct_roundtrip() {
    let mcast = BridgeMcastStats::default();
    let stp = BridgeStpXstats::default();
    let vlan = BridgeVlanXstats {
        vid: 1,
        flags: 0x27,
        ..Default::default()
    };

    let groups = vec![LinkXstatGroup::Bridge(vec![
        BridgeXstat::Vlan(vlan),
        BridgeXstat::Mcast(mcast),
        BridgeXstat::Stp(stp),
    ])];

    let msg = StatsMessage {
        header: StatsHeader {
            family: 0u8.into(),
            ifindex: 3,
            filter_mask: 2,
        },
        attributes: vec![StatsAttribute::LinkXstats(groups)],
    };

    let len = msg.buffer_len();
    let mut buf = vec![0; len];
    msg.emit(&mut buf);

    let parsed =
        StatsMessage::parse(&StatsMessageBuffer::new_checked(&buf).unwrap())
            .expect("failed to parse stats message");

    assert_eq!(parsed.header, msg.header);
    assert_eq!(parsed.attributes, msg.attributes);
}

#[test]
fn test_offload_xstats_hw_stats64_roundtrip() {
    let hw = HwStats64 {
        rx_packets: 0x12345678,
        rx_errors: 1,
        multicast: 42,
        ..Default::default()
    };

    let len = hw.buffer_len();
    let mut buf = vec![0; len];
    hw.emit(&mut buf);

    let parsed = HwStats64::parse(&buf).unwrap();
    assert_eq!(parsed.rx_packets, 0x12345678);
    assert_eq!(parsed.rx_errors, 1);
    assert_eq!(parsed.multicast, 42);
}

#[test]
fn test_stats_header_roundtrip() {
    let header = StatsHeader {
        family: 0u8.into(),
        ifindex: 42,
        filter_mask: 6,
    };

    let len = header.buffer_len();
    let mut buf = vec![0; len];
    header.emit(&mut buf);

    let parsed = StatsHeader::parse(&StatsMessageBuffer::new(&buf))
        .expect("failed to parse stats header");
    assert_eq!(parsed, header);
}
