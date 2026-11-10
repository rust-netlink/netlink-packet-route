// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
    ParseableParametrized,
};

use super::{
    header::NEIGHBOUR_HEADER_LEN, NeighbourAttribute, NeighbourHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NeighbourMessage {
    pub header: NeighbourHeader,
    pub attributes: Vec<NeighbourAttribute>,
}

impl Emitable for NeighbourMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        self.attributes.emit(out)
    }
}

impl Parseable<[u8]> for NeighbourMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = NeighbourHeader::parse(buf)
            .context("failed to parse neighbour message header")?;
        let address_family = header.family;
        let attributes = Vec::<NeighbourAttribute>::parse_with_param(
            &buf[NEIGHBOUR_HEADER_LEN..],
            address_family,
        )
        .context("failed to parse neighbour message NLAs")?;
        Ok(NeighbourMessage { header, attributes })
    }
}
