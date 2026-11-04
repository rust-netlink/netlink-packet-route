// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, emit_nlas_into, DecodeError, DefaultNla, Emitable,
    EncodeError, ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
};

use super::{
    af_spec::AfSpecStats,
    offload::{parse_offload_xstats_inner, OffloadXstat},
    xstats::{LinkXstatGroup, VecLinkXstats},
};
use crate::link::Stats64;

pub(crate) const IFLA_STATS_LINK_64: u16 = 1;
pub(crate) const IFLA_STATS_LINK_XSTATS: u16 = 2;
pub(crate) const IFLA_STATS_LINK_XSTATS_SLAVE: u16 = 3;
pub(crate) const IFLA_STATS_LINK_OFFLOAD_XSTATS: u16 = 4;
pub(crate) const IFLA_STATS_AF_SPEC: u16 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum StatsAttribute {
    Link64(Stats64),
    LinkXstats(Vec<LinkXstatGroup>),
    LinkXstatsPort(Vec<LinkXstatGroup>),
    LinkOffloadXstats(Vec<OffloadXstat>),
    AfSpec(AfSpecStats),
    Other(DefaultNla),
}

impl Nla for StatsAttribute {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Link64(v) => v.emit_into(out),
            Self::LinkXstats(v) | Self::LinkXstatsPort(v) => {
                emit_nlas_into(v, out)
            }
            Self::LinkOffloadXstats(v) => emit_nlas_into(v, out),
            Self::AfSpec(v) => v.emit_into(out),
            Self::Other(attr) => {
                append_bytes(out, attr.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        <StatsAttribute>::kind(self)
    }
}

impl StatsAttribute {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::Link64(_) => IFLA_STATS_LINK_64,
            Self::LinkXstats(_) => IFLA_STATS_LINK_XSTATS,
            Self::LinkXstatsPort(_) => IFLA_STATS_LINK_XSTATS_SLAVE,
            Self::LinkOffloadXstats(_) => IFLA_STATS_LINK_OFFLOAD_XSTATS,
            Self::AfSpec(_) => IFLA_STATS_AF_SPEC,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for StatsAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_STATS_LINK_64 => Self::Link64(
                Stats64::parse(payload)
                    .context("invalid IFLA_STATS_LINK_64 value")?,
            ),
            IFLA_STATS_LINK_XSTATS => {
                let err = "invalid IFLA_STATS_LINK_XSTATS value";
                Self::LinkXstats(
                    VecLinkXstats::parse(&NlaBuffer::new(payload))
                        .context(err)?
                        .0,
                )
            }
            IFLA_STATS_LINK_XSTATS_SLAVE => {
                let err = "invalid IFLA_STATS_LINK_XSTATS_SLAVE value";
                Self::LinkXstatsPort(
                    VecLinkXstats::parse(&NlaBuffer::new(payload))
                        .context(err)?
                        .0,
                )
            }
            IFLA_STATS_LINK_OFFLOAD_XSTATS => {
                let err = "invalid IFLA_STATS_LINK_OFFLOAD_XSTATS value";
                Self::LinkOffloadXstats(
                    parse_offload_xstats_inner(payload).context(err)?,
                )
            }
            IFLA_STATS_AF_SPEC => Self::AfSpec(
                AfSpecStats::parse(payload).context("invalid AF_SPEC stats")?,
            ),
            kind => {
                Self::Other(DefaultNla::parse(buf).with_context(|| {
                    format!("unknown IFLA_STATS type {kind}")
                })?)
            }
        })
    }
}

pub(crate) struct VecStatsAttribute(pub(crate) Vec<StatsAttribute>);

impl Parseable<[u8]> for VecStatsAttribute {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        for nla_buf in NlasIterator::new(buf) {
            attributes.push(StatsAttribute::parse(&nla_buf?)?);
        }
        Ok(Self(attributes))
    }
}
