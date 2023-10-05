// SPDX-License-Identifier: MIT

use crate::rtnl::address::nlas::{Inet6AddrFlag, Nla};
use netlink_packet_utils::{nla::NlaBuffer, Emitable, Parseable};

#[test]
fn test_ipv6_addr_flags() {
    let nla = Nla::Flags(vec![
        Inet6AddrFlag::Permanent,
        Inet6AddrFlag::StablePrivacy,
    ]);

    let raw: [u8; 8] = [
        0x08, 0x00, // length 8
        0x08, 0x00, // IFA_FLAGS
        0x80, 0x08, 0x00, 0x00, // IFA_F_PERMANENT | IFA_F_STABLE_PRIVACY
    ];

    let nla_buffer = NlaBuffer::new_checked(&raw).unwrap();
    let parsed = Nla::parse(&nla_buffer).unwrap();
    assert_eq!(parsed, nla);

    assert_eq!(nla.buffer_len(), 8);

    let mut buffer: [u8; 8] = [0; 8];
    nla.emit(&mut buffer);
    assert_eq!(buffer, raw);
}
