// SPDX-License-Identifier: MIT

use super::{
    param::VecNeighbourTableParameter, NeighbourTableConfig,
    NeighbourTableConfigBuffer, NeighbourTableError, NeighbourTableParameter,
    NeighbourTableStats, NeighbourTableStatsBuffer,
};
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_string, parse_u32, parse_u64},
    Emitable, Parseable,
};

const NDTA_NAME: u16 = 1;
const NDTA_THRESH1: u16 = 2;
const NDTA_THRESH2: u16 = 3;
const NDTA_THRESH3: u16 = 4;
const NDTA_CONFIG: u16 = 5;
const NDTA_PARMS: u16 = 6;
const NDTA_STATS: u16 = 7;
const NDTA_GC_INTERVAL: u16 = 8;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NeighbourTableAttribute {
    Parms(Vec<NeighbourTableParameter>),
    Name(String),
    Threshold1(u32),
    Threshold2(u32),
    Threshold3(u32),
    Config(NeighbourTableConfig),
    Stats(NeighbourTableStats),
    GcInterval(u64),
    Other(DefaultNla),
}

impl Nla for NeighbourTableAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Parms(v) => v.as_slice().buffer_len(),
            Self::Stats(v) => v.buffer_len(),
            Self::Config(v) => v.buffer_len(),
            // strings: +1 because we need to append a nul byte
            Self::Name(s) => s.len() + 1,
            Self::Threshold1(_) | Self::Threshold2(_) | Self::Threshold3(_) => {
                4
            }
            Self::GcInterval(_) => 8,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Parms(v) => v.as_slice().emit(buffer),
            Self::Stats(v) => v.emit(buffer),
            Self::Config(v) => v.emit(buffer),
            Self::Name(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::GcInterval(value) => NativeEndian::write_u64(buffer, *value),
            Self::Threshold1(value)
            | Self::Threshold2(value)
            | Self::Threshold3(value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Name(_) => NDTA_NAME,
            Self::Config(_) => NDTA_CONFIG,
            Self::Stats(_) => NDTA_STATS,
            Self::Parms(_) => NDTA_PARMS,
            Self::GcInterval(_) => NDTA_GC_INTERVAL,
            Self::Threshold1(_) => NDTA_THRESH1,
            Self::Threshold2(_) => NDTA_THRESH2,
            Self::Threshold3(_) => NDTA_THRESH3,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for NeighbourTableAttribute
{
    type Error = NeighbourTableError;
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, Self::Error> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NDTA_NAME => {
                Self::Name(parse_string(payload).map_err(|error| {
                    NeighbourTableError::InvalidValue {
                        kind: "NDTA_NAME",
                        error,
                    }
                })?)
            }
            NDTA_CONFIG => Self::Config(
                NeighbourTableConfig::parse(
                    &NeighbourTableConfigBuffer::new_checked(payload).map_err(
                        |error| NeighbourTableError::InvalidValue {
                            kind: "NDTA_CONFIG",
                            error,
                        },
                    )?,
                )
                .map_err(|error| {
                    NeighbourTableError::InvalidValue {
                        kind: "NDTA_CONFIG",
                        error,
                    }
                })?,
            ),
            NDTA_STATS => Self::Stats(
                NeighbourTableStats::parse(
                    &NeighbourTableStatsBuffer::new_checked(payload).map_err(
                        |error| NeighbourTableError::InvalidValue {
                            kind: "NDTA_STATS",
                            error,
                        },
                    )?,
                )
                .map_err(|error| {
                    NeighbourTableError::InvalidValue {
                        kind: "NDTA_STATS",
                        error,
                    }
                })?,
            ),
            NDTA_PARMS => Self::Parms(
                VecNeighbourTableParameter::parse(&NlaBuffer::new(payload))?.0,
            ),
            NDTA_GC_INTERVAL => {
                Self::GcInterval(parse_u64(payload).map_err(|error| {
                    NeighbourTableError::InvalidValue {
                        kind: "NDTA_GC_INTERVAL",
                        error,
                    }
                })?)
            }
            NDTA_THRESH1 => {
                Self::Threshold1(parse_u32(payload).map_err(|error| {
                    NeighbourTableError::InvalidValue {
                        kind: "NDTA_THRESH1",
                        error,
                    }
                })?)
            }
            NDTA_THRESH2 => {
                Self::Threshold2(parse_u32(payload).map_err(|error| {
                    NeighbourTableError::InvalidValue {
                        kind: "NDTA_THRESH2",
                        error,
                    }
                })?)
            }
            NDTA_THRESH3 => {
                Self::Threshold3(parse_u32(payload).map_err(|error| {
                    NeighbourTableError::InvalidValue {
                        kind: "NDTA_THRESH3",
                        error,
                    }
                })?)
            }
            kind => Self::Other(DefaultNla::parse(buf).map_err(|error| {
                NeighbourTableError::UnknownNla { kind, error }
            })?),
        })
    }
}
