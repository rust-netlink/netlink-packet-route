// SPDX-License-Identifier: MIT

use crate::nsid::{NsidAttribute, NsidError, NsidHeader, NsidMessageBuffer};
use netlink_packet_utils::traits::{Emitable, Parseable};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NsidMessage {
    pub header: NsidHeader,
    pub attributes: Vec<NsidAttribute>,
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NsidMessageBuffer<&'a T>>
    for NsidMessage
{
    type Error = NsidError;
    fn parse(buf: &NsidMessageBuffer<&'a T>) -> Result<Self, NsidError> {
        Ok(Self {
            // unwrap: parsing the header can't fail
            header: NsidHeader::parse(buf).unwrap(),
            attributes: Vec::<NsidAttribute>::parse(buf)?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NsidMessageBuffer<&'a T>>
    for Vec<NsidAttribute>
{
    type Error = NsidError;
    fn parse(buf: &NsidMessageBuffer<&'a T>) -> Result<Self, NsidError> {
        let mut attributes = vec![];
        for nla_buf in buf.attributes() {
            attributes.push(NsidAttribute::parse(&nla_buf?)?);
        }
        Ok(attributes)
    }
}

impl Emitable for NsidMessage {
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
