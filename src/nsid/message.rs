// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{
    attribute::VecNsidAttribute, header::NSID_HEADER_LEN, NsidAttribute,
    NsidHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NsidMessage {
    pub header: NsidHeader,
    pub attributes: Vec<NsidAttribute>,
}

#[allow(dead_code)]
impl Parseable<[u8]> for NsidMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            header: NsidHeader::parse(buf)
                .context("failed to parse nsid message header")?,
            attributes: VecNsidAttribute::parse(&buf[NSID_HEADER_LEN..])
                .context("failed to parse nsid message NLAs")?
                .0,
        })
    }
}

impl Emitable for NsidMessage {
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
