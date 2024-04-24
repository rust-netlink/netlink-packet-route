// SPDX-License-Identifier: MIT

use crate::rule::RuleError;
use netlink_packet_utils::Emitable;

const RULE_UID_RANGE_LEN: usize = 8;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
pub struct RuleUidRange {
    pub start: u32,
    pub end: u32,
}

impl RuleUidRange {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self, RuleError> {
        if buf.len() == RULE_UID_RANGE_LEN {
            Ok(Self {
                start: u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]),
                end: u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]),
            })
        } else {
            Err(RuleError::ParseUidRange {
                expected: RULE_UID_RANGE_LEN,
                got: buf.len(),
            })
        }
    }
}

impl Emitable for RuleUidRange {
    fn buffer_len(&self) -> usize {
        RULE_UID_RANGE_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0..4].copy_from_slice(&self.start.to_ne_bytes());
        buffer[4..8].copy_from_slice(&self.end.to_ne_bytes());
    }
}
