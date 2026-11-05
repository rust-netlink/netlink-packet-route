// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

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

#[allow(dead_code)]
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
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        let result = (|| -> Result<(), EncodeError> {
            self.header.emit_into(out)?;
            emit_nlas_into(&self.attributes, out)?;
            Ok(())
        })();
        if result.is_err() {
            out.truncate(start);
        }
        result
    }
}
