// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{
    attribute::VecTcAttribute, header::TC_HEADER_LEN, TcAttribute, TcHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcMessage {
    pub header: TcHeader,
    pub attributes: Vec<TcAttribute>,
}

#[allow(dead_code)]
impl TcMessage {
    pub fn into_parts(self) -> (TcHeader, Vec<TcAttribute>) {
        (self.header, self.attributes)
    }

    pub fn from_parts(header: TcHeader, attributes: Vec<TcAttribute>) -> Self {
        TcMessage { header, attributes }
    }

    /// Create a new `TcMessage` with the given index
    pub fn with_index(index: i32) -> Self {
        Self {
            header: TcHeader {
                index,
                ..Default::default()
            },
            attributes: Vec::new(),
        }
    }
}

#[allow(dead_code)]
impl Parseable<[u8]> for TcMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = TcHeader::parse(buf)
            .context("failed to parse tc message header")?;
        Ok(Self {
            header,
            attributes: VecTcAttribute::parse(&buf[TC_HEADER_LEN..])
                .context("failed to parse tc message NLAs")?
                .0,
        })
    }
}

impl Emitable for TcMessage {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit_into(out)?;
        emit_nlas_into(&self.attributes, out)
    }
}
