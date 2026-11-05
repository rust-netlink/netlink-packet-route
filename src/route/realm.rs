// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_u32, DecodeError, Emitable, EncodeError};

const RULE_REALM_LEN: usize = 4;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
pub struct RouteRealm {
    pub source: u16,
    pub destination: u16,
}

#[allow(dead_code)]
impl RouteRealm {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() == RULE_REALM_LEN {
            let all = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Ok(Self {
                source: (all >> 16) as u16,
                destination: (all & 0xFFFF) as u16,
            })
        } else {
            Err(DecodeError::from(format!(
                "Invalid rule port range data, expecting {RULE_REALM_LEN} u8 \
                 array, but got {buf:?}"
            )))
        }
    }
}

impl Emitable for RouteRealm {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let all = ((self.source as u32) << 16) | self.destination as u32;
        append_u32(out, all);
        Ok(())
    }
}
