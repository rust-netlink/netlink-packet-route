// SPDX-License-Identifier: MIT

use super::{TcAttribute, TcError, TcHeader, TcMessageBuffer};
use netlink_packet_utils::traits::{
    Emitable, Parseable, ParseableParametrized,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcMessage {
    pub header: TcHeader,
    pub attributes: Vec<TcAttribute>,
}

impl TcMessage {
    pub fn into_parts(self) -> (TcHeader, Vec<TcAttribute>) {
        (self.header, self.attributes)
    }

    pub fn from_parts(header: TcHeader, attributes: Vec<TcAttribute>) -> Self {
        TcMessage { header, attributes }
    }

    /// Create a new `TcMessage` with the given index
    pub fn with_index(index: i32) -> Self {
        Self {
            header: TcHeader {
                index,
                ..Default::default()
            },
            attributes: Vec::new(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<TcMessageBuffer<&'a T>> for TcMessage {
    type Error = TcError;
    fn parse(buf: &TcMessageBuffer<&'a T>) -> Result<Self, TcError> {
        Ok(Self {
            header: TcHeader::parse(buf).unwrap(),
            attributes: Vec::<TcAttribute>::parse(buf)?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<TcMessageBuffer<&'a T>>
    for Vec<TcAttribute>
{
    type Error = TcError;
    fn parse(buf: &TcMessageBuffer<&'a T>) -> Result<Self, TcError> {
        let mut attributes = vec![];
        let mut kind = String::new();

        for nla_buf in buf.attributes() {
            let attribute =
                TcAttribute::parse_with_param(&nla_buf?, kind.as_str())?;
            if let TcAttribute::Kind(s) = &attribute {
                kind = s.to_string();
            }
            attributes.push(attribute)
        }
        Ok(attributes)
    }
}

impl Emitable for TcMessage {
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
