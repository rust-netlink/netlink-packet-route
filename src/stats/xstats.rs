// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

use super::{
    bond::{parse_bond_xstats, BondXstat},
    bridge::{parse_bridge_xstats, BridgeXstat},
};

const LINK_XSTATS_TYPE_BRIDGE: u16 = 1;
const LINK_XSTATS_TYPE_BOND: u16 = 2;

// ---------------------------------------------------------------------------
// Link xstats (inside IFLA_STATS_LINK_XSTATS / _PORT)
// ---------------------------------------------------------------------------

/// A fully parsed entry inside `IFLA_STATS_LINK_XSTATS` or
/// `IFLA_STATS_LINK_XSTATS_PORT`. The inner data is parsed at
/// construction time.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum LinkXstatGroup {
    Bridge(Vec<BridgeXstat>),
    Bond(Vec<BondXstat>),
    Other(DefaultNla),
}

impl Nla for LinkXstatGroup {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Bridge(v) => (v).emit(out),
            Self::Bond(v) => (v).emit(out),
            Self::Other(v) => {
                append_bytes(out, v.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Bridge(_) => LINK_XSTATS_TYPE_BRIDGE,
            Self::Bond(_) => LINK_XSTATS_TYPE_BOND,
            Self::Other(v) => v.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for LinkXstatGroup {
    fn parse(nla: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match nla.kind() {
            LINK_XSTATS_TYPE_BRIDGE => LinkXstatGroup::Bridge(
                parse_bridge_xstats(nla)
                    .context("invalid bridge xstats in link xstats")?,
            ),
            LINK_XSTATS_TYPE_BOND => LinkXstatGroup::Bond(
                parse_bond_xstats(nla)
                    .context("invalid bond xstats in link xstats")?,
            ),
            _ => LinkXstatGroup::Other(DefaultNla::parse(nla)?),
        })
    }
}
