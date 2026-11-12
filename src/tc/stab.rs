// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    append_bytes, append_u16, DecodeError, DefaultNla, Emitable, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const TCA_STAB_BASE: u16 = 1;
const TCA_STAB_DATA: u16 = 2;

/// Size table specification (`struct tc_sizespec`).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcSizeSpec {
    pub cell_log: u8,
    pub size_log: u8,
    pub cell_align: i16,
    pub overhead: i32,
    pub linklayer: u32,
    pub mpu: u32,
    pub mtu: u32,
    pub tsize: u32,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct TcSizeSpecBuffer {
    cell_log: u8,
    size_log: u8,
    cell_align: i16,
    overhead: i32,
    linklayer: u32,
    mpu: u32,
    mtu: u32,
    tsize: u32,
}

impl TcSizeSpec {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcSizeSpecBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcSizeSpecBuffer>(),
                )
            })?;
        Ok(Self {
            cell_log: raw.cell_log,
            size_log: raw.size_log,
            cell_align: raw.cell_align,
            overhead: raw.overhead,
            linklayer: raw.linklayer,
            mpu: raw.mpu,
            mtu: raw.mtu,
            tsize: raw.tsize,
        })
    }
}

impl From<&TcSizeSpec> for TcSizeSpecBuffer {
    fn from(value: &TcSizeSpec) -> Self {
        Self {
            cell_log: value.cell_log,
            size_log: value.size_log,
            cell_align: value.cell_align,
            overhead: value.overhead,
            linklayer: value.linklayer,
            mpu: value.mpu,
            mtu: value.mtu,
            tsize: value.tsize,
        }
    }
}

impl Emitable for TcSizeSpec {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TcSizeSpecBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

/// Nested `TCA_STAB` attributes.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcStab {
    Base(TcSizeSpec),
    Data(Vec<u16>),
    Other(DefaultNla),
}

impl Nla for TcStab {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Base(value) => value.emit(out),
            Self::Data(values) => {
                for value in values {
                    append_u16(out, *value);
                }
                Ok(())
            }
            Self::Other(nla) => {
                append_bytes(out, nla.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Base(_) => TCA_STAB_BASE,
            Self::Data(_) => TCA_STAB_DATA,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcStab {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_STAB_BASE => Self::Base(
                TcSizeSpec::parse(payload)
                    .context("invalid TCA_STAB_BASE value")?,
            ),
            TCA_STAB_DATA => {
                if payload.len() % 2 != 0 {
                    return Err(DecodeError::from(format!(
                        "Invalid TCA_STAB_DATA, odd payload length {}",
                        payload.len()
                    )));
                }
                let mut values = Vec::with_capacity(payload.len() / 2);
                for chunk in payload.chunks_exact(2) {
                    values.push(u16::from_ne_bytes([chunk[0], chunk[1]]));
                }
                Self::Data(values)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
