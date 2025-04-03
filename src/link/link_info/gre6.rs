// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    DecodeError, Parseable,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoGreTun6 {
    Other(DefaultNla),
}

impl Nla for InfoGreTun6 {
    fn value_len(&self) -> usize {
        match self {
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>> for InfoGreTun6 {
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, DecodeError> {
        #[allow(clippy::match_single_binding)]
        Ok(match buf.kind() {
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
