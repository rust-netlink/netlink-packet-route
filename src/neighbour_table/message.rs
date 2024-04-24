// SPDX-License-Identifier: MIT

use super::{
    NeighbourTableAttribute, NeighbourTableError, NeighbourTableHeader,
    NeighbourTableMessageBuffer,
};
use netlink_packet_utils::traits::{Emitable, Parseable};

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

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourTableMessageBuffer<&'a T>>
    for NeighbourTableMessage
{
    type Error = NeighbourTableError;
    fn parse(
        buf: &NeighbourTableMessageBuffer<&'a T>,
    ) -> Result<Self, NeighbourTableError> {
        Ok(NeighbourTableMessage {
            // unwrap: we always succeed at parsing the header
            header: NeighbourTableHeader::parse(buf).unwrap(),
            attributes: Vec::<NeighbourTableAttribute>::parse(buf)?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NeighbourTableMessageBuffer<&'a T>>
    for Vec<NeighbourTableAttribute>
{
    type Error = NeighbourTableError;
    fn parse(
        buf: &NeighbourTableMessageBuffer<&'a T>,
    ) -> Result<Self, NeighbourTableError> {
        let mut attributes = vec![];
        for nla_buf in buf.attributes() {
            attributes.push(NeighbourTableAttribute::parse(&nla_buf?)?);
        }
        Ok(attributes)
    }
}
