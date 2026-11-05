// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use crate::stats::{
    attribute::VecStatsAttribute, header::STATS_HEADER_LEN, StatsAttribute,
    StatsHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct StatsMessage {
    pub header: StatsHeader,
    pub attributes: Vec<StatsAttribute>,
}

#[allow(dead_code)]
impl Parseable<[u8]> for StatsMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            header: StatsHeader::parse(buf)
                .context("failed to parse stats message header")?,
            attributes: VecStatsAttribute::parse(&buf[STATS_HEADER_LEN..])
                .context("failed to parse stats message NLAs")?
                .0,
        })
    }
}

impl Emitable for StatsMessage {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit_into(out)?;
        emit_nlas_into(&self.attributes, out)
    }
}
