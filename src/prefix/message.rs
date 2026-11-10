// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{
    attribute::PrefixAttribute,
    header::{PrefixHeader, PREFIX_HEADER_LEN},
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct PrefixMessage {
    pub header: PrefixHeader,
    pub attributes: Vec<PrefixAttribute>,
}

impl Emitable for PrefixMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        self.attributes.emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for PrefixMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            header: PrefixHeader::parse(buf)
                .context("failed to parse prefix message header")?,
            attributes: Vec::<PrefixAttribute>::parse(
                &buf[PREFIX_HEADER_LEN..],
            )
            .context("failed to parse prefix message attributes")?,
        })
    }
}
