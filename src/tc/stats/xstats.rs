// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::NlaBuffer,
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

use crate::tc::{TcFqCodelXstats, TcQdiscFqCodel};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcXstats {
    FqCodel(TcFqCodelXstats),
    Other(Vec<u8>),
}

impl Emitable for TcXstats {
    fn buffer_len(&self) -> usize {
        match self {
            Self::FqCodel(v) => v.buffer_len(),
            Self::Other(v) => v.len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::FqCodel(v) => v.emit(buffer),
            Self::Other(v) => buffer.copy_from_slice(v.as_slice()),
        }
    }
}

impl<T> ParseableParametrized<NlaBuffer<&T>, &str> for TcXstats
where
    T: AsRef<[u8]> + ?Sized,
{
    type Error = DecodeError;

    fn parse_with_param(
        buf: &NlaBuffer<&T>,
        kind: &str,
    ) -> Result<TcXstats, Self::Error> {
        Ok(match kind {
            TcQdiscFqCodel::KIND => {
                TcXstats::FqCodel(TcFqCodelXstats::parse(buf.value())?)
            }
            _ => TcXstats::Other(buf.value().to_vec()),
        })
    }
}
