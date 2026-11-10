// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_XFRM_LINK: u16 = 1;
const IFLA_XFRM_IF_ID: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoXfrm {
    Link(u32),
    IfId(u32),
    Other(DefaultNla),
}

impl Nla for InfoXfrm {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Link(value) => append_u32(out, *value),
            Self::IfId(value) => append_u32(out, *value),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Link(_) => IFLA_XFRM_LINK,
            Self::IfId(_) => IFLA_XFRM_IF_ID,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoXfrm {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_XFRM_LINK => Self::Link(
                parse_u32(payload).context("invalid IFLA_XFRM_LINK value")?,
            ),
            IFLA_XFRM_IF_ID => Self::IfId(
                parse_u32(payload).context("invalid IFLA_XFRM_IF_ID value")?,
            ),
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for IFLA_INFO_DATA(xfrm)")
            })?),
        })
    }
}
