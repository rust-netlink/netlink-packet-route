// SPDX-License-Identifier: MIT

// TODO: If you have hardware to simulate DPLL pins, please add unit tests for
// this module.

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const DPLL_A_PIN_ID: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum DpllPin {
    /// The unique pin identifier within the DPLL subsystem.
    PinId(u32),
    Other(DefaultNla),
}

impl Nla for DpllPin {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::PinId(v) => append_u32(out, *v),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <Self>::kind(self)
    }
}

impl DpllPin {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::PinId(_) => DPLL_A_PIN_ID,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for DpllPin {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            DPLL_A_PIN_ID => Self::PinId(
                parse_u32(payload).context("invalid DPLL_A_PIN_ID value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown DPLL_A_PIN type {}", buf.kind())
            })?),
        })
    }
}
