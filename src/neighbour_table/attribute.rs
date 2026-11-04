// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, append_u64, parse_string, parse_u32, parse_u64,
    DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable,
};

use super::{
    param::VecNeighbourTableParameter, NeighbourTableConfig,
    NeighbourTableParameter, NeighbourTableStats,
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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Parms(v) => (v.as_slice()).emit(out),
            Self::Stats(v) => v.emit(out),
            Self::Config(v) => v.emit(out),
            Self::Name(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
                Ok(())
            }
            Self::GcInterval(value) => {
                append_u64(out, *value);
                Ok(())
            }
            Self::Threshold1(value)
            | Self::Threshold2(value)
            | Self::Threshold3(value) => {
                append_u32(out, *value);
                Ok(())
            }
            Self::Other(attr) => {
                append_bytes(out, attr.value());
                Ok(())
            }
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
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NDTA_NAME => Self::Name(
                parse_string(payload).context("invalid NDTA_NAME value")?,
            ),
            NDTA_CONFIG => Self::Config(
                NeighbourTableConfig::parse(payload).with_context(|| {
                    format!("invalid NDTA_CONFIG {payload:?}")
                })?,
            ),
            NDTA_STATS => {
                Self::Stats(NeighbourTableStats::parse(payload).with_context(
                    || format!("invalid NDTA_STATS {payload:?}"),
                )?)
            }
            NDTA_PARMS => {
                let err = || format!("invalid NDTA_PARMS {payload:?}");
                Self::Parms(
                    VecNeighbourTableParameter::parse(
                        &NlaBuffer::new_checked(payload).with_context(err)?,
                    )
                    .with_context(err)?
                    .0,
                )
            }
            NDTA_GC_INTERVAL => Self::GcInterval(
                parse_u64(payload).context("invalid NDTA_GC_INTERVAL value")?,
            ),
            NDTA_THRESH1 => Self::Threshold1(
                parse_u32(payload).context("invalid NDTA_THRESH1 value")?,
            ),
            NDTA_THRESH2 => Self::Threshold2(
                parse_u32(payload).context("invalid NDTA_THRESH2 value")?,
            ),
            NDTA_THRESH3 => Self::Threshold3(
                parse_u32(payload).context("invalid NDTA_THRESH3 value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .with_context(|| format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}

pub(crate) struct VecNeighbourTableAttribute(
    pub(crate) Vec<NeighbourTableAttribute>,
);

impl Parseable<[u8]> for VecNeighbourTableAttribute {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        for nla_buf in NlasIterator::new(buf) {
            attributes.push(NeighbourTableAttribute::parse(&nla_buf?)?);
        }
        Ok(Self(attributes))
    }
}
