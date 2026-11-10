// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{
    header::ADDRLABEL_HEADER_LEN, AddrLabelAttribute, AddrLabelHeader,
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
            Vec::<AddrLabelAttribute>::parse(&buf[ADDRLABEL_HEADER_LEN..])
                .context("failed to parse addrlabel message NLAs")?;
        Ok(Self { header, attributes })
    }
}

impl Emitable for AddrLabelMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        self.attributes.emit(out)?;
        Ok(())
    }
}
