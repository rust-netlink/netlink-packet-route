// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_u32, DecodeError, Emitable, EncodeError};

const RULE_UID_RANGE_LEN: usize = 8;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
pub struct RuleUidRange {
    pub start: u32,
    pub end: u32,
}

impl RuleUidRange {
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    pub(crate) fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() == RULE_UID_RANGE_LEN {
            Ok(Self {
                start: u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]),
                end: u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]),
            })
        } else {
            Err(DecodeError::from(format!(
                "Invalid rule port range data, expecting {RULE_UID_RANGE_LEN} \
                 u8 array, but got {buf:?}"
            )))
        }
    }
}

impl Emitable for RuleUidRange {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.start);
        append_u32(out, self.end);
        Ok(())
    }
}
