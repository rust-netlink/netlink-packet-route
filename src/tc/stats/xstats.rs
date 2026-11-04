// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, Emitable, EncodeError, NlaBuffer, Parseable,
    ParseableParametrized,
};

use crate::tc::{TcFqCodelXstats, TcQdiscFqCodel};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcXstats {
    FqCodel(TcFqCodelXstats),
    Other(Vec<u8>),
}

impl Emitable for TcXstats {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::FqCodel(v) => v.emit(out),
            Self::Other(v) => {
                append_bytes(out, v.as_slice());
                Ok(())
            }
        }
    }
}

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, &str> for TcXstats
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        kind: &str,
    ) -> Result<TcXstats, DecodeError> {
        Ok(match kind {
            TcQdiscFqCodel::KIND => {
                TcXstats::FqCodel(TcFqCodelXstats::parse(buf.value())?)
            }
            _ => TcXstats::Other(buf.value().to_vec()),
        })
    }
}
