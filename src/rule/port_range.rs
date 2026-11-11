// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_u16, DecodeError, Emitable, EncodeError};

const RULE_PORT_RANGE_LEN: usize = 4;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
pub struct RulePortRange {
    pub start: u16,
    pub end: u16,
}

impl RulePortRange {
    pub const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub(crate) fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() == RULE_PORT_RANGE_LEN {
            Ok(Self {
                start: u16::from_ne_bytes([buf[0], buf[1]]),
                end: u16::from_ne_bytes([buf[2], buf[3]]),
            })
        } else {
            Err(DecodeError::from(format!(
                "Invalid rule port range data, expecting \
                 {RULE_PORT_RANGE_LEN} u8 array, but got {buf:?}"
            )))
        }
    }
}

impl Emitable for RulePortRange {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u16(out, self.start);
        append_u16(out, self.end);
        Ok(())
    }
}
