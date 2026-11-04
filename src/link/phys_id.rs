// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, Emitable, EncodeError, Parseable,
};

const MAX_PHYS_ITEM_ID_LEN: usize = 32;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct LinkPhysId {
    pub id: [u8; MAX_PHYS_ITEM_ID_LEN],
    pub len: usize,
}

#[allow(dead_code)]
impl Parseable<[u8]> for LinkPhysId {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let len = buf.len().min(MAX_PHYS_ITEM_ID_LEN);
        let mut id = [0; MAX_PHYS_ITEM_ID_LEN];
        id[..len].copy_from_slice(&buf[..len]);
        Ok(Self { id, len })
    }
}

impl Emitable for LinkPhysId {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_bytes(out, &self.id[..self.len]);
        Ok(())
    }
}
