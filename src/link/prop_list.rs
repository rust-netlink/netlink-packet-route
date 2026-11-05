// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, parse_string, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_ALT_IFNAME: u16 = 53;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Prop {
    AltIfName(String),
    Other(DefaultNla),
}

impl Nla for Prop {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::AltIfName(ref string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <Self>::kind(self)
    }
}

impl Prop {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::AltIfName(_) => IFLA_ALT_IFNAME,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Prop {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_ALT_IFNAME => Prop::AltIfName(
                parse_string(payload)
                    .context("invalid IFLA_ALT_IFNAME value")?,
            ),
            kind => Prop::Other(
                DefaultNla::parse(buf)
                    .with_context(|| format!("Unknown NLA type {kind}"))?,
            ),
        })
    }
}
