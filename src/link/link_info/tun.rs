// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, EncodeError, ErrorContext, Nla,
    NlaBuffer, Parseable,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoTun {
    Other(DefaultNla),
}

impl Nla for InfoTun {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoTun {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        #[allow(clippy::match_single_binding)]
        Ok(match buf.kind() {
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for IFLA_INFO_DATA(vrf)")
            })?),
        })
    }
}
