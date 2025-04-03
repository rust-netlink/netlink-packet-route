// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    traits::{Emitable, Parseable},
    DecodeError,
};

use super::{
    NeighbourTableAttribute, NeighbourTableHeader, NeighbourTableMessageBuffer,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NeighbourTableMessage {
    pub header: NeighbourTableHeader,
    pub attributes: Vec<NeighbourTableAttribute>,
}

impl Emitable for NeighbourTableMessage {
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

impl<T: AsRef<[u8]>> Parseable<NeighbourTableMessageBuffer<&T>>
    for NeighbourTableMessage
{
    type Error = DecodeError;

    fn parse(
        buf: &NeighbourTableMessageBuffer<&T>,
    ) -> Result<Self, Self::Error> {
        Ok(NeighbourTableMessage {
            header: NeighbourTableHeader::parse(buf)?,
            attributes: Vec::<NeighbourTableAttribute>::parse(buf)?,
        })
    }
}

impl<T: AsRef<[u8]>> Parseable<NeighbourTableMessageBuffer<&T>>
    for Vec<NeighbourTableAttribute>
{
    type Error = DecodeError;

    fn parse(
        buf: &NeighbourTableMessageBuffer<&T>,
    ) -> Result<Self, Self::Error> {
        let mut attributes = vec![];
        for nla_buf in buf.attributes() {
            attributes.push(NeighbourTableAttribute::parse(&nla_buf?)?);
        }
        Ok(attributes)
    }
}
