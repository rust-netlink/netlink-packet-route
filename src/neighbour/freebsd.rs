// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, Parseable,
};

use crate::buffer_freebsd::FreeBSDBuffer;

const NDAF_NEXT_STATE_TS: u16 = 1;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FreeBsdNeighbourAttribute {
    NextStateTimeSecs(u32),
    Other(DefaultNla),
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<FreeBSDBuffer<&'buffer T>>
    for FreeBsdNeighbourAttribute
{
    fn parse(buf: &FreeBSDBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        if buf.inner().len() < buf.length() as usize {
            return Err(DecodeError::from(
                "Buffer length is smaller than indicated length",
            ));
        }

        let value = match buf.value_type() {
            1 => {
                let secs = parse_u32(buf.value()).context(
                    "failed to parse NDA_FREEBSD NDAF_NEXT_STATE_TS value",
                )?;
                FreeBsdNeighbourAttribute::NextStateTimeSecs(secs)
            }
            kind => FreeBsdNeighbourAttribute::Other(DefaultNla::new(
                kind,
                buf.value().to_vec(),
            )),
        };

        Ok(value)
    }
}

impl Nla for FreeBsdNeighbourAttribute {
    fn kind(&self) -> u16 {
        match self {
            FreeBsdNeighbourAttribute::NextStateTimeSecs(_) => {
                NDAF_NEXT_STATE_TS
            }
            FreeBsdNeighbourAttribute::Other(nla) => nla.kind(),
        }
    }

    fn value_len(&self) -> usize {
        match self {
            FreeBsdNeighbourAttribute::NextStateTimeSecs(_) => 4,
            FreeBsdNeighbourAttribute::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            FreeBsdNeighbourAttribute::NextStateTimeSecs(secs) => {
                buffer.copy_from_slice(&secs.to_ne_bytes());
            }
            FreeBsdNeighbourAttribute::Other(nla) => nla.emit_value(buffer),
        }
    }
}
