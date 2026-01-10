// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, Parseable, ParseableParametrized,
};

use super::{NexthopAttribute, NexthopHeader, NexthopMessageBuffer};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NexthopMessage {
    pub header: NexthopHeader,
    pub nlas: Vec<NexthopAttribute>,
}

impl Emitable for NexthopMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NexthopMessageBuffer<&'a T>>
    for NexthopMessage
{
    fn parse(buf: &NexthopMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let header = NexthopHeader::parse(buf)
            .context("failed to parse nexthop message header")?;
        Ok(NexthopMessage {
            header,
            nlas: Vec::<NexthopAttribute>::parse(buf)
                .context("failed to parse nexthop message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NexthopMessageBuffer<&'a T>>
    for Vec<NexthopAttribute>
{
    fn parse(buf: &NexthopMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.attributes() {
            let nla = nla_buf?;
            nlas.push(NexthopAttribute::parse_with_param(
                &(nla.value(), nla.kind()),
                (),
            )?);
        }
        Ok(nlas)
    }
}
