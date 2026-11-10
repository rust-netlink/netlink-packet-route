// SPDX-License-Identifier: MIT
use netlink_packet_core::{Nla, NlaBuffer, Parseable};

use crate::link::dpll_pin::DpllPin;

// A nested IFLA_DPLL_PIN containing a single DPLL_A_PIN_ID = 42
//   8 bytes total: 4-byte NLA header + 4-byte u32 value
static DPLL_PIN_ID: [u8; 8] = [
    0x08, 0x00, // length = 8
    0x01, 0x00, // type = 1 = DPLL_A_PIN_ID
    0x2a, 0x00, 0x00, 0x00, // value = 42 (little-endian)
];

#[test]
fn parse_dpll_pin_id() {
    let nla = NlaBuffer::new(&DPLL_PIN_ID[..]).unwrap();
    let parsed = DpllPin::parse(&nla).unwrap();
    assert_eq!(parsed, DpllPin::PinId(42));
}

#[test]
fn emit_dpll_pin_id() {
    let nla = DpllPin::PinId(42);
    let mut buf = Vec::new();
    nla.emit(&mut buf).unwrap();
    assert_eq!(buf.len(), 8);
    assert_eq!(buf.as_slice(), &DPLL_PIN_ID[..]);
}

#[test]
fn parse_unknown_dpll_pin_attr() {
    // An NLA with type=99 (unknown), value = [0xde, 0xad]
    let raw: [u8; 8] = [
        0x06, 0x00, // length = 6
        0x63, 0x00, // type = 99 (unknown)
        0xde, 0xad, // value bytes
        0x00, 0x00, // padding
    ];
    let nla = NlaBuffer::new(&raw[..]).unwrap();
    let parsed = DpllPin::parse(&nla).unwrap();
    assert!(matches!(parsed, DpllPin::Other(_)));
}
