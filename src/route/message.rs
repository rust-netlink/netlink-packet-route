// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_nlas_into, DecodeError, Emitable, EncodeError, ErrorContext,
    Parseable, ParseableParametrized,
};

use super::{
    attribute::VecRouteAttribute, header::ROUTE_HEADER_LEN, RouteAttribute,
    RouteHeader,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct RouteMessage {
    pub header: RouteHeader,
    pub attributes: Vec<RouteAttribute>,
}

impl Emitable for RouteMessage {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let start = out.len();
        let result = (|| -> Result<(), EncodeError> {
            self.header.emit_into(out)?;
            emit_nlas_into(&self.attributes, out)
        })();
        if result.is_err() {
            out.truncate(start);
        }
        result
    }
}

impl Parseable<[u8]> for RouteMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = RouteHeader::parse(buf)
            .context("failed to parse route message header")?;
        let address_family = header.address_family;
        let route_type = header.kind;
        Ok(RouteMessage {
            header,
            attributes: VecRouteAttribute::parse_with_param(
                &buf[ROUTE_HEADER_LEN..],
                (address_family, route_type),
            )
            .context("failed to parse route message NLAs")?
            .0,
        })
    }
}
