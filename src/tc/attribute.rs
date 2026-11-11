// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, append_u8, parse_string, parse_u32, parse_u8,
    DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, ParseableParametrized,
};

use super::{TcOption, TcStats, TcStats2, TcXstats, VecTcOption};

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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match *self {
            Self::Rate(ref bytes)
            | Self::Fcnt(ref bytes)
            | Self::Stab(ref bytes) => append_bytes(out, bytes.as_slice()),
            Self::Chain(v) => append_u32(out, v),
            Self::Xstats(ref v) => v.emit(out)?,
            Self::HwOffload(ref val) => append_u8(out, *val),
            Self::Stats2(ref stats) => (stats.as_slice()).emit(out)?,
            Self::Stats(ref stats) => stats.emit(out)?,
            Self::Kind(ref string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Options(ref opt) => (opt.as_slice()).emit(out)?,
            Self::DumpInvisible(_) => (),
            Self::Other(ref attr) => append_bytes(out, attr.value()),
        }
        Ok(())
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

impl<'a> ParseableParametrized<NlaBuffer<'a>, &str> for TcAttribute {
    fn parse_with_param(
        buf: &NlaBuffer<'a>,
        kind: &str,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_KIND => TcAttribute::Kind(
                parse_string(payload).context("invalid TCA_KIND")?,
            ),
            TCA_OPTIONS => TcAttribute::Options(
                VecTcOption::parse_with_param(buf, kind)
                    .with_context(|| {
                        format!("Invalid TCA_OPTIONS for kind: {kind}")
                    })?
                    .0,
            ),
            TCA_STATS => TcAttribute::Stats(
                TcStats::parse(payload).context("failed to parse TCA_STATS")?,
            ),
            TCA_XSTATS => TcAttribute::Xstats(
                TcXstats::parse_with_param(buf, kind)
                    .context("invalid TCA_XSTATS")?,
            ),
            TCA_RATE => TcAttribute::Rate(payload.to_vec()),
            TCA_FCNT => TcAttribute::Fcnt(payload.to_vec()),
            TCA_STATS2 => {
                let mut nlas = vec![];
                for nla in buf.nlas().context("invalid TCA_STATS2")? {
                    let stats = TcStats2::parse_with_param(&nla, kind)
                        .with_context(|| {
                            format!(
                                "failed to parse TCA_STATS2 for kind {kind}"
                            )
                        })?;
                    nlas.push(stats);
                }
                TcAttribute::Stats2(nlas)
            }
            TCA_STAB => TcAttribute::Stab(payload.to_vec()),
            TCA_CHAIN => TcAttribute::Chain(
                parse_u32(payload).context("failed to parse TCA_CHAIN")?,
            ),
            TCA_HW_OFFLOAD => TcAttribute::HwOffload(
                parse_u8(payload).context("failed to parse TCA_HW_OFFLOAD")?,
            ),
            TCA_DUMP_INVISIBLE => TcAttribute::DumpInvisible(true),
            _ => TcAttribute::Other(
                DefaultNla::parse(buf).context("failed to parse tc nla")?,
            ),
        })
    }
}

pub(crate) struct VecTcAttribute(pub(crate) Vec<TcAttribute>);

impl Parseable<[u8]> for VecTcAttribute {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        let mut kind = String::new();

        for nla_buf in NlasIterator::new(buf)? {
            let attribute =
                TcAttribute::parse_with_param(&nla_buf, kind.as_str())?;
            if let TcAttribute::Kind(s) = &attribute {
                kind = s.to_string();
            }
            attributes.push(attribute)
        }
        Ok(Self(attributes))
    }
}
