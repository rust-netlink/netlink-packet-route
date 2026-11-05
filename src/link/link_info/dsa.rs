// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_DSA_UNSPEC: u16 = 0;
const IFLA_DSA_CONDUIT: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoDsa {
    Conduit(u32),
    Other(DefaultNla),
}

impl Nla for InfoDsa {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Conduit(v) => append_u32(out, *v),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <InfoDsa>::kind(self)
    }
}

impl InfoDsa {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::Conduit(_) => IFLA_DSA_CONDUIT,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoDsa {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_DSA_UNSPEC => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid IFLA_DSA_UNSPEC value")?,
            ),
            IFLA_DSA_CONDUIT => Self::Conduit(
                parse_u32(payload).context("invalid IFLA_DSA_CONDUIT value")?,
            ),
            unknown_kind => {
                Self::Other(DefaultNla::parse(buf).with_context(|| {
                    format!("unknown NLA type {unknown_kind} for dsa")
                })?)
            }
        })
    }
}
