// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, emit_nlas_into, DecodeError, Emitable, EncodeError,
    ErrorContext, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    address::{
        attribute::VecAddressAttribute, AddressAttribute, AddressHeaderFlags,
        AddressScope,
    },
    AddressFamily,
};

const ADDRESS_HEADER_LEN: usize = 8;

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
pub struct AddressMessageBuffer {
    family: u8,
    prefix_len: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct AddressMessage {
    pub header: AddressHeader,
    pub attributes: Vec<AddressAttribute>,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AddressHeader {
    pub family: AddressFamily,
    pub prefix_len: u8,
    pub flags: AddressHeaderFlags,
    pub scope: AddressScope,
    pub index: u32,
}

#[allow(dead_code)]
impl AddressHeader {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            AddressMessageBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), ADDRESS_HEADER_LEN)
            })?;
        Ok(Self {
            family: raw.family.into(),
            prefix_len: raw.prefix_len,
            flags: AddressHeaderFlags::from_bits_retain(raw.flags),
            scope: raw.scope.into(),
            index: raw.index,
        })
    }
}

#[allow(dead_code)]
impl From<&AddressHeader> for AddressMessageBuffer {
    fn from(header: &AddressHeader) -> Self {
        Self {
            family: header.family.into(),
            prefix_len: header.prefix_len,
            flags: header.flags.bits(),
            scope: header.scope.into(),
            index: header.index,
        }
    }
}

impl Emitable for AddressHeader {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = AddressMessageBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

impl Emitable for AddressMessage {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        let result = (|| -> Result<(), EncodeError> {
            self.header.emit_into(out)?;
            emit_nlas_into(&self.attributes, out)?;
            Ok(())
        })();
        if result.is_err() {
            out.truncate(start);
        }
        result
    }
}

impl Parseable<[u8]> for AddressMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = AddressHeader::parse(buf)
            .context("failed to parse address message header")?;
        Ok(AddressMessage {
            header,
            attributes: VecAddressAttribute::parse(&buf[ADDRESS_HEADER_LEN..])
                .context("failed to parse address message NLAs")?
                .0,
        })
    }
}
