// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{NlaBuffer, NlaError, NlasIterator},
    traits::{Emitable, Parseable},
    DecodeError,
};

use crate::{
    address::{AddressAttribute, AddressHeaderFlags, AddressScope},
    AddressFamily,
};

const ADDRESS_HEADER_LEN: usize = 8;

buffer!(AddressMessageBuffer(ADDRESS_HEADER_LEN) {
    family: (u8, 0),
    prefix_len: (u8, 1),
    flags: (u8, 2),
    scope: (u8, 3),
    index: (u32, 4..ADDRESS_HEADER_LEN),
    payload: (slice, ADDRESS_HEADER_LEN..),
});

impl<T: AsRef<[u8]> + ?Sized> AddressMessageBuffer<&T> {
    pub fn attributes(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&[u8]>, NlaError>> {
        NlasIterator::new(self.payload())
    }
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

impl Emitable for AddressHeader {
    fn buffer_len(&self) -> usize {
        ADDRESS_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = AddressMessageBuffer::new(buffer);
        packet.set_family(self.family.into());
        packet.set_prefix_len(self.prefix_len);
        packet.set_flags(self.flags.bits());
        packet.set_scope(self.scope.into());
        packet.set_index(self.index);
    }
}

impl Emitable for AddressMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.attributes.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.attributes
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl<T: AsRef<[u8]>> Parseable<AddressMessageBuffer<T>> for AddressHeader {
    type Error = DecodeError;

    fn parse(buf: &AddressMessageBuffer<T>) -> Result<Self, Self::Error> {
        Ok(Self {
            family: buf.family().into(),
            prefix_len: buf.prefix_len(),
            flags: AddressHeaderFlags::from_bits_retain(buf.flags()),
            scope: buf.scope().into(),
            index: buf.index(),
        })
    }
}

impl<T: AsRef<[u8]>> Parseable<AddressMessageBuffer<&T>> for AddressMessage {
    type Error = DecodeError;

    fn parse(buf: &AddressMessageBuffer<&T>) -> Result<Self, Self::Error> {
        Ok(AddressMessage {
            header: AddressHeader::parse(buf)?,
            attributes: Vec::<AddressAttribute>::parse(buf)?,
        })
    }
}

impl<T: AsRef<[u8]>> Parseable<AddressMessageBuffer<&T>>
    for Vec<AddressAttribute>
{
    type Error = DecodeError;

    fn parse(buf: &AddressMessageBuffer<&T>) -> Result<Self, Self::Error> {
        let mut attributes = vec![];
        for nla_buf in buf.attributes() {
            attributes.push(AddressAttribute::parse(&nla_buf?)?);
        }
        Ok(attributes)
    }
}
