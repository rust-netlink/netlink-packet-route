// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::AddressFamily;

pub(crate) const NEIGHBOUR_TABLE_HEADER_LEN: usize = 4;

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
pub struct NeighbourTableMessageBuffer {
    family: u8,
    _pad: [u8; 3],
}

// kernel code is `struct rtgenmsg`
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct NeighbourTableHeader {
    pub family: AddressFamily,
}

#[allow(dead_code)]
impl NeighbourTableHeader {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = NeighbourTableMessageBuffer::ref_from_prefix(payload)
            .map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    NEIGHBOUR_TABLE_HEADER_LEN,
                )
            })?;
        Ok(Self {
            family: raw.family.into(),
        })
    }
}

#[allow(dead_code)]
impl From<&NeighbourTableHeader> for NeighbourTableMessageBuffer {
    fn from(header: &NeighbourTableHeader) -> Self {
        Self {
            family: header.family.into(),
            _pad: [0; 3],
        }
    }
}

impl Emitable for NeighbourTableHeader {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = NeighbourTableMessageBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
