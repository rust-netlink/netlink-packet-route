// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use crate::stats::{StatsAttribute, StatsHeader, StatsMessageBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct StatsMessage {
    pub header: StatsHeader,
    pub attributes: Vec<StatsAttribute>,
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<StatsMessageBuffer<&'a T>>
    for StatsMessage
{
    fn parse(buf: &StatsMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            header: StatsHeader::parse(buf)
                .context("failed to parse stats message header")?,
            attributes: Vec::<StatsAttribute>::parse(buf)
                .context("failed to parse stats message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<StatsMessageBuffer<&'a T>>
    for Vec<StatsAttribute>
{
    fn parse(buf: &StatsMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        for nla_buf in buf.attributes() {
            attributes.push(StatsAttribute::parse(&nla_buf?)?);
        }
        Ok(attributes)
    }
}

impl Emitable for StatsMessage {
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
