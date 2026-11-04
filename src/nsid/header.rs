// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::AddressFamily;

pub(crate) const NSID_HEADER_LEN: usize = 4;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct NsidMessageBuffer {
    family: u8,
    _pad: [u8; 3],
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NsidHeader {
    pub family: AddressFamily,
}

#[allow(dead_code)]
impl NsidHeader {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            NsidMessageBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), NSID_HEADER_LEN)
            })?;
        Ok(NsidHeader {
            family: raw.family.into(),
        })
    }
}

#[allow(dead_code)]
impl From<&NsidHeader> for NsidMessageBuffer {
    fn from(header: &NsidHeader) -> Self {
        Self {
            family: header.family.into(),
            _pad: [0; 3],
        }
    }
}

impl Emitable for NsidHeader {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = NsidMessageBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
