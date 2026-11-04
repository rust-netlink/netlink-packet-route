// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, Emitable, EncodeError, EncodeErrorKind,
    Parseable,
};

const MAX_PHYS_ITEM_ID_LEN: usize = 32;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct LinkPhysId {
    pub id: [u8; MAX_PHYS_ITEM_ID_LEN],
    pub len: usize,
}

impl Parseable<[u8]> for LinkPhysId {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let len = buf.len().min(MAX_PHYS_ITEM_ID_LEN);
        let mut id = [0; MAX_PHYS_ITEM_ID_LEN];
        id[..len].copy_from_slice(&buf[..len]);
        Ok(Self { id, len })
    }
}

impl Emitable for LinkPhysId {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let value = self.id.get(..self.len).ok_or_else(|| {
            EncodeError::new(
                EncodeErrorKind::InvalidValue,
                format!(
                    "physical id length {} exceeds the maximum of {} bytes",
                    self.len, MAX_PHYS_ITEM_ID_LEN
                ),
            )
        })?;
        append_bytes(out, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::{Emitable, EncodeErrorKind};

    use super::*;

    #[test]
    fn emit_rejects_length_beyond_storage() {
        let phys_id = LinkPhysId {
            id: [0; MAX_PHYS_ITEM_ID_LEN],
            len: MAX_PHYS_ITEM_ID_LEN + 1,
        };
        let mut out = Vec::new();
        let error = phys_id.emit(&mut out).unwrap_err();
        assert_eq!(error.kind(), EncodeErrorKind::InvalidValue);
        assert!(out.is_empty());
    }
}
