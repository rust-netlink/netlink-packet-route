// SPDX-License-Identifier: MIT

use super::{
    TcStatsBasic, TcStatsBasicBuffer, TcStatsQueue, TcStatsQueueBuffer,
    TcXstats,
};
use crate::tc::TcError;
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    traits::{Emitable, Parseable, ParseableParametrized},
};

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
    fn value_len(&self) -> usize {
        match self {
            Self::App(v) => v.buffer_len(),
            Self::Basic(v) => v.buffer_len(),
            Self::Queue(v) => v.buffer_len(),
            Self::BasicHw(v) => v.buffer_len(),
            Self::Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::App(v) => v.emit(buffer),
            Self::Basic(v) => v.emit(buffer),
            Self::Queue(v) => v.emit(buffer),
            Self::BasicHw(v) => v.emit(buffer),
            Self::Other(ref nla) => nla.emit_value(buffer),
        }
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

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, &str> for TcStats2
where
    T: AsRef<[u8]> + ?Sized,
{
    type Error = TcError;
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        kind: &str,
    ) -> Result<Self, TcError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_STATS_APP => Self::App(TcXstats::parse_with_param(buf, kind)?),
            TCA_STATS_BASIC => Self::Basic(
                // unwrap: TCStatsBasic doesn't fail to parse.
                TcStatsBasic::parse(&TcStatsBasicBuffer::new(payload)).unwrap(),
            ),
            TCA_STATS_QUEUE => Self::Queue(
                // unwrap: TCStatsQueue doesn't fail to parse.
                TcStatsQueue::parse(&TcStatsQueueBuffer::new(payload)).unwrap(),
            ),
            TCA_STATS_BASIC_HW => Self::BasicHw(
                // unwrap: TCStatsBasic doesn't fail to parse.
                TcStatsBasic::parse(&TcStatsBasicBuffer::new(payload)).unwrap(),
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .map_err(|error| TcError::UnknownNla { kind, error })?,
            ),
        })
    }
}
