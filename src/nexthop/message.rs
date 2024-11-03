// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

use super::{
    super::AddressFamily, NexthopAttribute, NexthopHeader, NexthopMessageBuffer,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NexthopMessage {
    pub header: NexthopHeader,
    pub attributes: Vec<NexthopAttribute>,
}

impl Emitable for NexthopMessage {
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

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NexthopMessageBuffer<&'a T>>
    for NexthopMessage
{
    fn parse(buf: &NexthopMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let header = NexthopHeader::parse(buf)
            .context("failed to parse nexthop message header")?;
        let address_family = header.address_family;
        Ok(NexthopMessage {
            header,
            attributes: Vec::<NexthopAttribute>::parse_with_param(
                buf,
                address_family,
            )
            .context("failed to parse nexthop message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a>
    ParseableParametrized<NexthopMessageBuffer<&'a T>, AddressFamily>
    for Vec<NexthopAttribute>
{
    fn parse_with_param(
        buf: &NexthopMessageBuffer<&'a T>,
        address_family: AddressFamily,
    ) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        for nla_buf in buf.attributes() {
            attributes.push(NexthopAttribute::parse_with_param(
                &nla_buf?,
                address_family,
            )?);
        }
        Ok(attributes)
    }
}
