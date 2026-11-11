// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, parse_u8, DecodeError, DefaultNla,
    Emitable, EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
    NLA_F_NESTED,
};

macro_rules! nla_err {
    // Shorthand for an NLA parse error message; expands to a &'static str
    ($message:ident) => {
        concat!("failed to parse ", stringify!($message), " value")
    };
}

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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Lse(attr) => (attr).emit(out)?,
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Lse(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcFilterFlowerMplsOption {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_MPLS_OPT_LSE => {
                let mut nlas = vec![];
                for nla in
                    buf.nlas().context(nla_err!(TCA_FLOWER_KEY_MPLS_OPT_LSE))?
                {
                    nlas.push(
                        TcFilterFlowerMplsLseOption::parse(&nla)
                            .context(nla_err!(TCA_FLOWER_KEY_MPLS_OPT_LSE))?,
                    )
                }
                Self::Lse(nlas)
            }
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("failed to parse mpls option nla")?,
            ),
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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::LseDepth(i)
            | Self::LseTtl(i)
            | Self::LseBos(i)
            | Self::LseTc(i) => out.push(*i),
            Self::LseLabel(i) => append_u32(out, *i & 0xFFFFF),

            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
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

impl<'a> Parseable<NlaBuffer<'a>> for TcFilterFlowerMplsLseOption {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH => Self::LseDepth(
                parse_u8(payload)
                    .context(nla_err!(TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH))?,
            ),
            TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL => Self::LseTtl(
                parse_u8(payload)
                    .context(nla_err!(TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL))?,
            ),
            TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS => Self::LseBos(
                parse_u8(payload)
                    .context(nla_err!(TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS))?,
            ),

            TCA_FLOWER_KEY_MPLS_OPT_LSE_TC => Self::LseTc(
                parse_u8(payload)
                    .context(nla_err!(TCA_FLOWER_KEY_MPLS_OPT_LSE_TC))?,
            ),

            TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL => Self::LseLabel(
                parse_u32(payload)
                    .context(nla_err!(TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL))?,
            ),

            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse mpls nla")?,
            ),
        })
    }
}
