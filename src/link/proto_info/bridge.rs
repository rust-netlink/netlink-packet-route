// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, parse_u8, DecodeError, DefaultNla, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

const IFLA_BRPORT_NEIGH_FORWARD_GRAT: u16 = 45;

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum LinkProtoInfoBridge {
    NeighForwardGrat(bool),
    Other(DefaultNla),
}

impl Nla for LinkProtoInfoBridge {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match *self {
            Self::NeighForwardGrat(value) => {
                out.push(if value { 1 } else { 0 })
            }
            Self::Other(ref nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::NeighForwardGrat(_) => IFLA_BRPORT_NEIGH_FORWARD_GRAT,
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for LinkProtoInfoBridge {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            IFLA_BRPORT_NEIGH_FORWARD_GRAT => Self::NeighForwardGrat(
                parse_u8(buf.value())
                    .context("invalid IFLA_BRPORT_NEIGH_FORWARD_GRAT value")?
                    > 0,
            ),
            _ => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("invalid bridge IFLA_PROTINFO {:?}", buf.value())
            })?),
        })
    }
}
