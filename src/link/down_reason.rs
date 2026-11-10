// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_PROTO_DOWN_REASON_MASK: u16 = 1;
const IFLA_PROTO_DOWN_REASON_VALUE: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum LinkProtocolDownReason {
    Value(u32),
    Mask(u32),
    Other(DefaultNla),
}

impl<'a> Parseable<NlaBuffer<'a>> for LinkProtocolDownReason {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_PROTO_DOWN_REASON_MASK => {
                Self::Mask(parse_u32(payload).with_context(|| {
                    format!("invalid IFLA_PROTO_DOWN_REASON_MASK {payload:?}")
                })?)
            }
            IFLA_PROTO_DOWN_REASON_VALUE => {
                Self::Value(parse_u32(payload).with_context(|| {
                    format!("invalid IFLA_PROTO_DOWN_REASON_VALUE {payload:?}")
                })?)
            }
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!(
                    "unknown NLA type {kind} for IFLA_PROTO_DOWN_REASON: \
                     {payload:?}"
                )
            })?),
        })
    }
}

impl Nla for LinkProtocolDownReason {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Value(v) | Self::Mask(v) => append_u32(out, *v),
            Self::Other(v) => append_bytes(out, v.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Value(_) => IFLA_PROTO_DOWN_REASON_VALUE,
            Self::Mask(_) => IFLA_PROTO_DOWN_REASON_MASK,
            Self::Other(v) => v.kind(),
        }
    }
}
