// SPDX-License-Identifier: MIT

use super::{
    TcError, TcOption, TcStats, TcStats2, TcStatsBuffer, TcXstats, VecTcOption,
};
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_string, parse_u32, parse_u8},
    Emitable, Parseable, ParseableParametrized,
};

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_STATS: u16 = 3;
const TCA_XSTATS: u16 = 4;
const TCA_RATE: u16 = 5;
const TCA_FCNT: u16 = 6;
const TCA_STATS2: u16 = 7;
const TCA_STAB: u16 = 8;
// const TCA_PAD: u16 = 9;
const TCA_DUMP_INVISIBLE: u16 = 10;
const TCA_CHAIN: u16 = 11;
const TCA_HW_OFFLOAD: u16 = 12;
// const TCA_INGRESS_BLOCK: u16 = 13; // TODO
// const TCA_EGRESS_BLOCK: u16 = 14; // TODO

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcAttribute {
    /// Name of queueing discipline
    Kind(String),
    /// Options follow
    Options(Vec<TcOption>),
    /// Statistics
    Stats(TcStats),
    /// Module-specific statistics
    Xstats(TcXstats),
    /// Rate limit
    Rate(Vec<u8>),
    Fcnt(Vec<u8>),
    Stats2(Vec<TcStats2>),
    Stab(Vec<u8>),
    Chain(u32),
    HwOffload(u8),
    DumpInvisible(bool),
    Other(DefaultNla),
}

impl Nla for TcAttribute {
    fn value_len(&self) -> usize {
        match *self {
            Self::Rate(ref bytes)
            | Self::Fcnt(ref bytes)
            | Self::Stab(ref bytes) => bytes.len(),
            Self::Chain(_) => 4,
            Self::Xstats(ref v) => v.buffer_len(),
            Self::HwOffload(_) => 1,
            Self::Stats2(ref v) => v.as_slice().buffer_len(),
            Self::Stats(ref v) => v.buffer_len(),
            Self::Kind(ref string) => string.as_bytes().len() + 1,
            Self::Options(ref opt) => opt.as_slice().buffer_len(),
            Self::DumpInvisible(_) => 0, // The existence of NLA means true
            Self::Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Rate(ref bytes)
            | Self::Fcnt(ref bytes)
            | Self::Stab(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Self::Chain(v) => NativeEndian::write_u32(buffer, v),
            Self::Xstats(ref v) => v.emit(buffer),
            Self::HwOffload(ref val) => buffer[0] = *val,
            Self::Stats2(ref stats) => stats.as_slice().emit(buffer),
            Self::Stats(ref stats) => stats.emit(buffer),
            Self::Kind(ref string) => {
                buffer[..string.as_bytes().len()]
                    .copy_from_slice(string.as_bytes());
                buffer[string.as_bytes().len()] = 0;
            }
            Self::Options(ref opt) => opt.as_slice().emit(buffer),
            Self::DumpInvisible(_) => (),
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Kind(_) => TCA_KIND,
            Self::Options(_) => TCA_OPTIONS,
            Self::Stats(_) => TCA_STATS,
            Self::Xstats(_) => TCA_XSTATS,
            Self::Rate(_) => TCA_RATE,
            Self::Fcnt(_) => TCA_FCNT,
            Self::Stats2(_) => TCA_STATS2,
            Self::Stab(_) => TCA_STAB,
            Self::Chain(_) => TCA_CHAIN,
            Self::HwOffload(_) => TCA_HW_OFFLOAD,
            Self::DumpInvisible(_) => TCA_DUMP_INVISIBLE,
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<NlaBuffer<&'a T>, &str>
    for TcAttribute
{
    type Error = TcError;
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        kind: &str,
    ) -> Result<Self, Self::Error> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_KIND => {
                TcAttribute::Kind(parse_string(payload).map_err(|error| {
                    TcError::InvalidValue {
                        kind: "TCA_KIND",
                        error,
                    }
                })?)
            }
            TCA_OPTIONS => TcAttribute::Options(
                VecTcOption::parse_with_param(buf, kind)?.0,
            ),
            TCA_STATS => TcAttribute::Stats(
                TcStats::parse(&TcStatsBuffer::new_checked(payload).map_err(
                    |error| TcError::InvalidValue {
                        kind: "TCA_STATS",
                        error,
                    },
                )?)
                .map_err(|error| TcError::InvalidValue {
                    kind: "TCA_STATS",
                    error,
                })?,
            ),
            TCA_XSTATS => {
                TcAttribute::Xstats(TcXstats::parse_with_param(buf, kind)?)
            }
            TCA_RATE => TcAttribute::Rate(payload.to_vec()),
            TCA_FCNT => TcAttribute::Fcnt(payload.to_vec()),
            TCA_STATS2 => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = nla?;
                    nlas.push(TcStats2::parse_with_param(&nla, kind)?);
                }
                TcAttribute::Stats2(nlas)
            }
            TCA_STAB => TcAttribute::Stab(payload.to_vec()),
            TCA_CHAIN => {
                TcAttribute::Chain(parse_u32(payload).map_err(|error| {
                    TcError::InvalidValue {
                        kind: "TCA_CHAIN",
                        error,
                    }
                })?)
            }
            TCA_HW_OFFLOAD => {
                TcAttribute::HwOffload(parse_u8(payload).map_err(|error| {
                    TcError::InvalidValue {
                        kind: "TCA_HW_OFFLOAD",
                        error,
                    }
                })?)
            }
            TCA_DUMP_INVISIBLE => TcAttribute::DumpInvisible(true),
            kind => TcAttribute::Other(
                DefaultNla::parse(buf)
                    .map_err(|error| TcError::UnknownNla { kind, error })?,
            ),
        })
    }
}
