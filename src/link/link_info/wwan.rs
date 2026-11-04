// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_WWAN_LINK_ID: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoWwan {
    LinkId(u32),
    Other(DefaultNla),
}

impl Nla for InfoWwan {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::LinkId(value) => append_u32(out, *value),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <Self>::kind(self)
    }
}

impl InfoWwan {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::LinkId(_) => IFLA_WWAN_LINK_ID,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoWwan {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_WWAN_LINK_ID => Self::LinkId(
                parse_u32(payload)
                    .context("invalid IFLA_WWAN_LINK_ID value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("unknown NLA type for wwan")?,
            ),
        })
    }
}
