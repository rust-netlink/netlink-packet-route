// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{header::NSID_HEADER_LEN, NsidAttribute, NsidHeader};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NsidMessage {
    pub header: NsidHeader,
    pub attributes: Vec<NsidAttribute>,
}

impl Parseable<[u8]> for NsidMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            header: NsidHeader::parse(buf)
                .context("failed to parse nsid message header")?,
            attributes: Vec::<NsidAttribute>::parse(&buf[NSID_HEADER_LEN..])
                .context("failed to parse nsid message NLAs")?,
        })
    }
}

impl Emitable for NsidMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        self.attributes.emit(out)?;
        Ok(())
    }
}
