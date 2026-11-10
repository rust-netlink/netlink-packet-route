// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
    ParseableParametrized,
};

use crate::link::{header::LINK_HEADER_LEN, LinkAttribute, LinkHeader};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct LinkMessage {
    pub header: LinkHeader,
    pub attributes: Vec<LinkAttribute>,
}

impl Emitable for LinkMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        self.attributes.emit(out)?;
        Ok(())
    }
}

impl Parseable<[u8]> for LinkMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = LinkHeader::parse(buf)
            .context("failed to parse link message header")?;
        let interface_family = header.interface_family;
        let attributes = Vec::<LinkAttribute>::parse_with_param(
            &buf[LINK_HEADER_LEN..],
            interface_family,
        )
        .context("failed to parse link message NLAs")?;
        Ok(LinkMessage { header, attributes })
    }
}
