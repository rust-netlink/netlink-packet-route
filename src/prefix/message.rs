// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    traits::{Emitable, Parseable},
    DecodeError,
};

use super::{
    attribute::PrefixAttribute,
    header::{PrefixHeader, PrefixMessageBuffer},
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct PrefixMessage {
    pub header: PrefixHeader,
    pub attributes: Vec<PrefixAttribute>,
}

impl Emitable for PrefixMessage {
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

impl<T: AsRef<[u8]>> Parseable<PrefixMessageBuffer<T>> for PrefixHeader {
    type Error = DecodeError;

    fn parse(buf: &PrefixMessageBuffer<T>) -> Result<Self, Self::Error> {
        Ok(Self {
            prefix_family: buf.prefix_family(),
            ifindex: buf.ifindex(),
            prefix_type: buf.prefix_type(),
            prefix_len: buf.prefix_len(),
            flags: buf.flags(),
        })
    }
}

impl<T: AsRef<[u8]>> Parseable<PrefixMessageBuffer<&T>> for PrefixMessage {
    type Error = DecodeError;

    fn parse(buf: &PrefixMessageBuffer<&T>) -> Result<Self, Self::Error> {
        Ok(Self {
            header: PrefixHeader::parse(buf)?,
            attributes: Vec::<PrefixAttribute>::parse(buf)?,
        })
    }
}

impl<T: AsRef<[u8]>> Parseable<PrefixMessageBuffer<&T>>
    for Vec<PrefixAttribute>
{
    type Error = DecodeError;

    fn parse(buf: &PrefixMessageBuffer<&T>) -> Result<Self, Self::Error> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(PrefixAttribute::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
