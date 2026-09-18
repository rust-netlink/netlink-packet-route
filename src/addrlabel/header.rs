// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::super::AddressFamily;

pub(crate) const ADDRLABEL_HEADER_LEN: usize = 12;

// Linux kernel code `struct ifaddrlblmsg`
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
pub struct AddrLabelMessageBuffer {
    family: u8,
    reserved: u8,
    prefix_len: u8,
    flags: u8,
    index: u32,
    sequence: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AddrLabelHeader {
    pub family: AddressFamily,
    pub prefix_len: u8,
    pub flags: u8,
    pub index: u32,
    pub sequence: u32,
}

impl AddrLabelHeader {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = AddrLabelMessageBuffer::ref_from_prefix(payload)
            .map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    ADDRLABEL_HEADER_LEN,
                )
            })?;
        Ok(Self {
            family: raw.family.into(),
            prefix_len: raw.prefix_len,
            flags: raw.flags,
            index: raw.index,
            sequence: raw.sequence,
        })
    }
}

impl From<&AddrLabelHeader> for AddrLabelMessageBuffer {
    fn from(header: &AddrLabelHeader) -> Self {
        Self {
            family: header.family.into(),
            reserved: 0,
            prefix_len: header.prefix_len,
            flags: header.flags,
            index: header.index,
            sequence: header.sequence,
        }
    }
}

impl Emitable for AddrLabelHeader {
    fn buffer_len(&self) -> usize {
        ADDRLABEL_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = AddrLabelMessageBuffer::from(self);
        buffer[..ADDRLABEL_HEADER_LEN].copy_from_slice(raw.as_bytes());
    }
}
