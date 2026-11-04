// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, NlasIterator, Parseable,
    ParseableParametrized,
};

use crate::{
    link::{header::LINK_HEADER_LEN, LinkAttribute, LinkHeader},
    AddressFamily,
};

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

impl ParseableParametrized<[u8], AddressFamily> for Vec<LinkAttribute> {
    fn parse_with_param(
        buf: &[u8],
        family: AddressFamily,
    ) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        for nla_buf in NlasIterator::new(buf) {
            attributes
                .push(LinkAttribute::parse_with_param(&nla_buf?, family)?);
        }
        Ok(attributes)
    }
}
