// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext, Parseable,
};

use super::{
    attribute::VecRuleAttribute, header::RULE_HEADER_LEN, RuleAttribute,
    RuleHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct RuleMessage {
    pub header: RuleHeader,
    pub attributes: Vec<RuleAttribute>,
}

impl Emitable for RuleMessage {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit_into(out)?;
        emit_nlas_into(&self.attributes, out)
    }
}

impl Parseable<[u8]> for RuleMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = RuleHeader::parse(buf)
            .context("failed to parse rule message header")?;
        let attributes = VecRuleAttribute::parse(&buf[RULE_HEADER_LEN..])
            .context("failed to parse rule message NLAs")?
            .0;
        Ok(RuleMessage { header, attributes })
    }
}
