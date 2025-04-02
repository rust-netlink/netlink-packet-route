// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    traits::{Emitable, Parseable},
    DecodeError,
};

use crate::nsid::{NsidAttribute, NsidHeader, NsidMessageBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NsidMessage {
    pub header: NsidHeader,
    pub attributes: Vec<NsidAttribute>,
}

impl<T: AsRef<[u8]>> Parseable<NsidMessageBuffer<&T>> for NsidMessage {
    type Error = DecodeError;

    fn parse(buf: &NsidMessageBuffer<&T>) -> Result<Self, Self::Error> {
        Ok(Self {
            header: NsidHeader::parse(buf)?,
            attributes: Vec::<NsidAttribute>::parse(buf)?,
        })
    }
}

impl<T: AsRef<[u8]>> Parseable<NsidMessageBuffer<&T>> for Vec<NsidAttribute> {
    type Error = DecodeError;

    fn parse(buf: &NsidMessageBuffer<&T>) -> Result<Self, Self::Error> {
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
