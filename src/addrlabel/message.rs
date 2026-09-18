// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable, ErrorContext, Parseable};

use super::{
    attribute::VecAddrLabelAttribute, header::ADDRLABEL_HEADER_LEN,
    AddrLabelAttribute, AddrLabelHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct AddrLabelMessage {
    pub header: AddrLabelHeader,
    pub attributes: Vec<AddrLabelAttribute>,
}

impl Parseable<[u8]> for AddrLabelMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = AddrLabelHeader::parse(buf)
            .context("failed to parse addrlabel message header")?;
        let attributes =
            VecAddrLabelAttribute::parse(&buf[ADDRLABEL_HEADER_LEN..])
                .context("failed to parse addrlabel message NLAs")?
                .0;
        Ok(Self { header, attributes })
    }
}

impl Emitable for AddrLabelMessage {
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
