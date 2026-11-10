// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, Nla,
    NlaBuffer, Parseable, ParseableParametrized,
};

use super::{TcStatsBasic, TcStatsQueue, TcXstats};

const TCA_STATS_BASIC: u16 = 1;
// const TCA_STATS_RATE_EST: u16 = 2; // TODO
const TCA_STATS_QUEUE: u16 = 3;
const TCA_STATS_APP: u16 = 4;
// const TCA_STATS_RATE_EST64: u16 = 5; // TODO
// const TCA_STATS_PAD: u16 = 6;
const TCA_STATS_BASIC_HW: u16 = 7;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcStats2 {
    App(TcXstats),
    Basic(TcStatsBasic),
    Queue(TcStatsQueue),
    BasicHw(TcStatsBasic),
    Other(DefaultNla),
}

impl Nla for TcStats2 {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::App(v) => v.emit(out)?,
            Self::Basic(v) => v.emit(out)?,
            Self::Queue(v) => v.emit(out)?,
            Self::BasicHw(v) => v.emit(out)?,
            Self::Other(ref nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::App(_) => TCA_STATS_APP,
            Self::Basic(_) => TCA_STATS_BASIC,
            Self::Queue(_) => TCA_STATS_QUEUE,
            Self::BasicHw(_) => TCA_STATS_BASIC_HW,
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a> ParseableParametrized<NlaBuffer<'a>, &str> for TcStats2 {
    fn parse_with_param(
        buf: &NlaBuffer<'a>,
        kind: &str,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_STATS_APP => Self::App(TcXstats::parse_with_param(buf, kind)?),
            TCA_STATS_BASIC => Self::Basic(TcStatsBasic::parse(payload)?),
            TCA_STATS_QUEUE => Self::Queue(TcStatsQueue::parse(payload)?),
            TCA_STATS_BASIC_HW => Self::BasicHw(TcStatsBasic::parse(payload)?),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
