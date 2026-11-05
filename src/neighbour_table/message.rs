// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{
    attribute::VecNeighbourTableAttribute, header::NEIGHBOUR_TABLE_HEADER_LEN,
    NeighbourTableAttribute, NeighbourTableHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NeighbourTableMessage {
    pub header: NeighbourTableHeader,
    pub attributes: Vec<NeighbourTableAttribute>,
}

impl Emitable for NeighbourTableMessage {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit_into(out)?;
        emit_nlas_into(&self.attributes, out)
    }
}

impl Parseable<[u8]> for NeighbourTableMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(NeighbourTableMessage {
            header: NeighbourTableHeader::parse(buf)
                .context("failed to parse neighbour table message header")?,
            attributes: VecNeighbourTableAttribute::parse(
                &buf[NEIGHBOUR_TABLE_HEADER_LEN..],
            )
            .context("failed to parse neighbour table message NLAs")?
            .0,
        })
    }
}
