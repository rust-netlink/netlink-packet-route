// SPDX-License-Identifier: MIT

/// Matchall filter
///
/// Matches all packets and performs an action on them.
use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    Nla, NlaBuffer, Parseable,
};
use netlink_packet_core::{Emitable, ErrorContext};

use crate::tc::{TcAction, TcHandle};

const TCA_MATCHALL_CLASSID: u16 = 1;
const TCA_MATCHALL_ACT: u16 = 2;
const TCA_MATCHALL_FLAGS: u16 = 3;
const TCA_MATCHALL_PCNT: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcFilterMatchAll {}
impl TcFilterMatchAll {
    pub const KIND: &'static str = "matchall";
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcFilterMatchAllOption {
    ClassId(TcHandle),
    Action(Vec<TcAction>),
    Pnct(Vec<u8>),
    Flags(u32),
    Other(DefaultNla),
}

impl Nla for TcFilterMatchAllOption {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Pnct(b) => append_bytes(out, b.as_slice()),
            Self::ClassId(i) => append_u32(out, (*i).into()),
            Self::Flags(i) => append_u32(out, *i),
            Self::Action(acts) => (acts).emit(out)?,
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::ClassId(_) => TCA_MATCHALL_CLASSID,
            Self::Action(_) => TCA_MATCHALL_ACT,
            Self::Pnct(_) => TCA_MATCHALL_PCNT,
            Self::Flags(_) => TCA_MATCHALL_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcFilterMatchAllOption {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_MATCHALL_CLASSID => Self::ClassId(
                parse_u32(payload)
                    .context("failed to parse TCA_MATCHALL_CLASSID")?
                    .into(),
            ),
            TCA_MATCHALL_ACT => {
                let mut acts = vec![];
                for act in buf.nlas().context("invalid TCA_MATCHALL_ACT")? {
                    acts.push(
                        TcAction::parse(&act)
                            .context("failed to parse TCA_MATCHALL_ACT")?,
                    );
                }
                Self::Action(acts)
            }
            TCA_MATCHALL_PCNT => Self::Pnct(payload.to_vec()),
            TCA_MATCHALL_FLAGS => Self::Flags(
                parse_u32(payload)
                    .context("failed to parse TCA_MATCHALL_FLAGS")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("failed to parse matchall nla")?,
            ),
        })
    }
}
