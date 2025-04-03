// SPDX-License-Identifier: MIT

use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator, NLA_F_NESTED},
    parsers::{parse_u32, parse_u8},
    traits::Emitable,
    DecodeError, Parseable,
};

/*
 * NLA layout:
 * TCA_FLOWER_KEY_MPLS_OPTS
 *   TCA_FLOWER_KEY_MPLS_OPT_LSE
 *     TCA_FLOWER_KEY_MPLS_OPT_LSE_*
 *     ..
 *     TCA_FLOWER_KEY_MPLS_OPT_LSE_*
 *   ..
 *   TCA_FLOWER_KEY_MPLS_OPT_LSE
 *     TCA_FLOWER_KEY_MPLS_OPT_LSE_*
 */

const TCA_FLOWER_KEY_MPLS_OPT_LSE: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcFilterFlowerMplsOption {
    Lse(Vec<TcFilterFlowerMplsLseOption>),
    Other(DefaultNla),
}

impl Nla for TcFilterFlowerMplsOption {
    fn value_len(&self) -> usize {
        match self {
            Self::Lse(attr) => attr.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Lse(attr) => attr.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Lse(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>>
    for TcFilterFlowerMplsOption
{
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_MPLS_OPT_LSE => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(buf.value()) {
                    nlas.push(TcFilterFlowerMplsLseOption::parse(&nla?)?)
                }
                Self::Lse(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

const TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH: u16 = 1;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL: u16 = 2;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS: u16 = 3;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_TC: u16 = 4;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL: u16 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcFilterFlowerMplsLseOption {
    LseDepth(u8),
    LseTtl(u8),
    LseBos(u8),
    LseTc(u8),
    LseLabel(u32),

    Other(DefaultNla),
}

impl Nla for TcFilterFlowerMplsLseOption {
    fn value_len(&self) -> usize {
        match self {
            Self::LseDepth(_) => 1,
            Self::LseTtl(_) => 1,
            Self::LseBos(_) => 1,
            Self::LseTc(_) => 1,
            Self::LseLabel(_) => 4,

            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::LseDepth(i) => buffer[0] = *i,
            Self::LseTtl(i) => buffer[0] = *i,
            Self::LseBos(i) => buffer[0] = *i,
            Self::LseTc(i) => buffer[0] = *i,
            Self::LseLabel(i) => NativeEndian::write_u32(buffer, *i & 0xFFFFF),

            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::LseDepth(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH,
            Self::LseTtl(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL,
            Self::LseBos(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS,
            Self::LseTc(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_TC,
            Self::LseLabel(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL,

            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>>
    for TcFilterFlowerMplsLseOption
{
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH => {
                Self::LseDepth(parse_u8(payload)?)
            }
            TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL => Self::LseTtl(parse_u8(payload)?),
            TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS => Self::LseBos(parse_u8(payload)?),

            TCA_FLOWER_KEY_MPLS_OPT_LSE_TC => Self::LseTc(parse_u8(payload)?),

            TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL => {
                Self::LseLabel(parse_u32(payload)?)
            }

            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
