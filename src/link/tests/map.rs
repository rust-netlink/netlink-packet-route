// SPDX-License-Identifier: MIT

use netlink_packet_core::{Emitable, NlaBuffer, ParseableParametrized};

use crate::{
    link::{LinkAttribute, Map},
    AddressFamily,
};

// `struct rtnl_link_ifmap` is three u64 followed by u16 + u8 + u8. Those
// fields always sit at offsets 0/8/16/24/26/27, but the struct's size follows
// the target's `u64` alignment: 32 bytes where it is 8 (x86-64, arm, aarch64)
// and 28 where it is 4 (the i386 psABI). The kernel emits IFLA_MAP at its own
// native size, so both forms appear on the wire and both must parse.

const IFLA_MAP: u16 = 14;

const EXPECTED: Map = Map {
    memory_start: 0xdead_beef_0000_1000,
    memory_end: 0xdead_beef_0000_2000,
    base_address: 0x0000_0000_0000_c000,
    irq: 11,
    dma: 3,
    port: 1,
};

/// The 28 bytes the six fields occupy, identical on every ABI.
const FIELD_BYTES: [u8; 28] = [
    0x00, 0x10, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // memory_start
    0x00, 0x20, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // memory_end
    0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // base_address
    0x0b, 0x00, // irq 11
    0x03, // dma 3
    0x01, // port 1
];

fn parse(payload: &[u8]) -> LinkAttribute {
    let mut raw = Vec::new();
    raw.extend_from_slice(&(payload.len() as u16 + 4).to_ne_bytes());
    raw.extend_from_slice(&IFLA_MAP.to_ne_bytes());
    raw.extend_from_slice(payload);

    LinkAttribute::parse_with_param(
        &NlaBuffer::new_checked(&raw[..]).unwrap(),
        AddressFamily::Unspec,
    )
    .unwrap()
}

/// The padded 32-byte form a 64-bit or ARM kernel emits.
#[test]
fn test_link_map_padded_32_bytes() {
    let mut payload = FIELD_BYTES.to_vec();
    payload.extend_from_slice(&[0x00; 4]); // trailing alignment padding
    assert_eq!(payload.len(), 32);
    assert_eq!(parse(&payload), LinkAttribute::Map(EXPECTED));
}

/// The unpadded 28-byte form a 32-bit x86 kernel emits. This previously failed
/// with "Invalid buffer MapBuffer. Expected at least 32 bytes, received 28
/// bytes" which, because one bad NLA fails the whole message, dropped every
/// RTM_GETLINK reply on i586/i686.
#[test]
fn test_link_map_unpadded_28_bytes() {
    assert_eq!(FIELD_BYTES.len(), 28);
    assert_eq!(parse(&FIELD_BYTES), LinkAttribute::Map(EXPECTED));
}

/// Both forms decode to the same value: the padding is not significant.
#[test]
fn test_link_map_padding_is_not_significant() {
    let mut padded = FIELD_BYTES.to_vec();
    padded.extend_from_slice(&[0x00; 4]);
    assert_eq!(parse(&padded), parse(&FIELD_BYTES));
}

/// Emitting produces this target's native size, and round-trips.
#[test]
fn test_link_map_emit_uses_native_size() {
    let attr = LinkAttribute::Map(EXPECTED);
    let mut buf = vec![0u8; attr.buffer_len()];
    attr.emit(&mut buf);

    // Payload is the NLA header (4) plus the native struct size: 28 on i386,
    // 32 wherever `u64` is 8-byte aligned.
    let payload = &buf[4..];
    assert_eq!(payload.len(), EXPECTED.buffer_len());
    assert!(matches!(payload.len(), 28 | 32));
    assert_eq!(&payload[..28], &FIELD_BYTES[..]);

    assert_eq!(parse(payload), LinkAttribute::Map(EXPECTED));
}
