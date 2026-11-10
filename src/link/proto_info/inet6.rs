// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, EncodeError, ErrorContext, Nla,
    NlaBuffer, Parseable,
};

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum LinkProtoInfoInet6 {
    Other(DefaultNla),
}

impl Nla for LinkProtoInfoInet6 {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match *self {
            Self::Other(ref nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for LinkProtoInfoInet6 {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self::Other(DefaultNla::parse(buf).with_context(|| {
            format!("invalid inet6 IFLA_PROTINFO {:?}", buf.value())
        })?))
    }
}
