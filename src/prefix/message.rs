// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{
    attribute::{PrefixAttribute, VecPrefixAttribute},
    header::{PrefixHeader, PREFIX_HEADER_LEN},
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct PrefixMessage {
    pub header: PrefixHeader,
    pub attributes: Vec<PrefixAttribute>,
}

impl Emitable for PrefixMessage {
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

impl Parseable<[u8]> for PrefixMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            header: PrefixHeader::parse(buf)
                .context("failed to parse prefix message header")?,
            attributes: VecPrefixAttribute::parse(&buf[PREFIX_HEADER_LEN..])
                .context("failed to parse prefix message attributes")?
                .0,
        })
    }
}
