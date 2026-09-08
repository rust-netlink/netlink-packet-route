// SPDX-License-Identifier: MIT
//
// Unit tests for FreeBSD-specific type mappings that do not require a
// full captured packet: InfoKind driver-name mapping, link flags and
// layer types, and the 192-byte FreeBSD rtnetlink_stats64 layout.

use netlink_packet_core::{Emitable, NlaBuffer, Parseable};

use crate::{
    buffer_freebsd::FreeBSDBuffer,
    link::{
        freebsd::FreeBsdLinkAttribute, link_info::InfoKind, LinkFlags,
        LinkLayerType, Stats64,
    },
};

const IFLA_INFO_KIND: u16 = 1;

#[test]
fn test_freebsd_info_kind_driver_names() {
    // FreeBSD registers cloner names: "wlan" for wireless (net80211) and
    // "lo" for loopback; WireGuard is named "wg" there.
    let wlan = nla_of_str("wlan");
    let lo = nla_of_str("lo");
    assert_eq!(
        InfoKind::parse(&NlaBuffer::new(&wlan)).unwrap(),
        InfoKind::Wlan
    );
    assert_eq!(
        InfoKind::parse(&NlaBuffer::new(&lo)).unwrap(),
        InfoKind::Loopback
    );
    assert_eq!(InfoKind::Wlan.to_string(), "wlan");
    assert_eq!(InfoKind::Loopback.to_string(), "lo");
}

#[test]
fn test_freebsd_link_flags_values() {
    // Values per sys/net/if.h: IFF_UP=0x1, IFF_BROADCAST=0x2,
    // IFF_RUNNING=0x40, IFF_SIMPLEX=0x800, IFF_MULTICAST=0x8000.
    let flags = LinkFlags::Up
        | LinkFlags::Broadcast
        | LinkFlags::Running
        | LinkFlags::Simplex
        | LinkFlags::Multicast;
    assert_eq!(flags.bits(), 0x1 | 0x2 | 0x40 | 0x800 | 0x8000);
}

#[test]
fn test_freebsd_link_layer_types() {
    // IFT_ETHER = 0x6 and IFT_LOOP = 0x18 per sys/net/if_types.h.
    assert_eq!(LinkLayerType::from(6), LinkLayerType::Ether);
    assert_eq!(LinkLayerType::from(0x18), LinkLayerType::Loop);
}

#[test]
fn test_freebsd_stats64_emit_is_192_bytes() {
    let stats = Stats64 {
        rx_packets: 305,
        tx_packets: 11,
        rx_bytes: 21_604,
        tx_bytes: 1_498,
        multicast: 296,
        tx_errors: 9,
        ..Default::default()
    };
    // FreeBSD's struct rtnetlink_stats64 has no rx_otherhost_dropped.
    assert_eq!(stats.buffer_len(), 192);

    let mut buf = vec![0xff; stats.buffer_len()];
    stats.emit(&mut buf);

    let parsed = Stats64::parse(&buf).unwrap();
    assert_eq!(parsed, stats);
}

#[test]
fn test_freebsd_attribute_parse_rejects_short_payload() {
    // A nested FreeBSD attribute whose header claims more bytes than the
    // buffer holds must be rejected, not panic.
    // Header: length = 10 (native endian), type = 1; only 2 value bytes follow.
    let raw = [10u8, 0, 1, 0, 0xaa, 0xbb];
    let buf = FreeBSDBuffer::new(&raw[..]);
    assert!(FreeBsdLinkAttribute::parse(&buf).is_err());
}

/// Build an `IFLA_INFO_KIND`-style NLA holding `s`, mirroring how the
/// FreeBSD kernel writes strings (`nlattr_add_string`: length covers
// strlen + 1, alignment padding lies outside the declared length).
fn nla_of_str(s: &str) -> Vec<u8> {
    let value_len = s.len() + 1; // trailing NUL, like the kernel
    let total = 4 + value_len;
    let mut buf = vec![0u8; (total + 3) & !3]; // align the buffer
    buf[..2].copy_from_slice(&(total as u16).to_ne_bytes());
    buf[2..4].copy_from_slice(&IFLA_INFO_KIND.to_ne_bytes());
    buf[4..4 + s.len()].copy_from_slice(s.as_bytes());
    // buf[total] stays 0 (the NUL); padding beyond it also stays 0
    buf
}
