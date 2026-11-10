// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

use super::{
    af_spec::AfSpecStats,
    offload::{parse_offload_xstats_inner, OffloadXstat},
    xstats::LinkXstatGroup,
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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Link64(v) => v.emit(out),
            Self::LinkXstats(v) | Self::LinkXstatsPort(v) => (v).emit(out),
            Self::LinkOffloadXstats(v) => (v).emit(out),
            Self::AfSpec(v) => v.emit(out),
            Self::Other(attr) => {
                append_bytes(out, attr.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
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

impl<'a> Parseable<NlaBuffer<'a>> for StatsAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_STATS_LINK_64 => Self::Link64(
                Stats64::parse(payload)
                    .context("invalid IFLA_STATS_LINK_64 value")?,
            ),
            IFLA_STATS_LINK_XSTATS => {
                let err = "invalid IFLA_STATS_LINK_XSTATS value";
                Self::LinkXstats(
                    Vec::<LinkXstatGroup>::parse(buf).context(err)?,
                )
            }
            IFLA_STATS_LINK_XSTATS_SLAVE => {
                let err = "invalid IFLA_STATS_LINK_XSTATS_SLAVE value";
                Self::LinkXstatsPort(
                    Vec::<LinkXstatGroup>::parse(buf).context(err)?,
                )
            }
            IFLA_STATS_LINK_OFFLOAD_XSTATS => {
                let err = "invalid IFLA_STATS_LINK_OFFLOAD_XSTATS value";
                Self::LinkOffloadXstats(
                    parse_offload_xstats_inner(buf).context(err)?,
                )
            }
            IFLA_STATS_AF_SPEC => Self::AfSpec(
                AfSpecStats::parse(buf).context("invalid AF_SPEC stats")?,
            ),
            kind => {
                Self::Other(DefaultNla::parse(buf).with_context(|| {
                    format!("unknown IFLA_STATS type {kind}")
                })?)
            }
        })
    }
}
