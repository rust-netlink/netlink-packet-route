// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    nla::{self, DefaultNla, NlaBuffer},
    traits::{Parseable, ParseableParametrized},
    DecodeError,
};

use crate::tc::{ingress, u32};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcOpt {
    // Qdisc specific options
    Ingress,
    // Filter specific options
    U32(u32::Nla),
    // Other options
    Other(DefaultNla),
}

impl nla::Nla for TcOpt {
    fn value_len(&self) -> usize {
        match self {
            Self::Ingress => 0,
            Self::U32(u) => u.value_len(),
            Self::Other(o) => o.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Ingress => unreachable!(),
            Self::U32(u) => u.emit_value(buffer),
            Self::Other(o) => o.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Ingress => unreachable!(),
            Self::U32(u) => u.kind(),
            Self::Other(o) => o.kind(),
        }
    }
}

impl<'a, T, S> ParseableParametrized<NlaBuffer<&'a T>, S> for TcOpt
where
    T: AsRef<[u8]> + ?Sized,
    S: AsRef<str>,
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        kind: S,
    ) -> Result<Self, DecodeError> {
        Ok(match kind.as_ref() {
            ingress::KIND => TcOpt::Ingress,
            u32::KIND => Self::U32(
                u32::Nla::parse(buf).context("failed to parse u32 nlas")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
