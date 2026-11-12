// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::link::Stats64;

const IFLA_OFFLOAD_XSTATS_CPU_HIT: u16 = 1;
const IFLA_OFFLOAD_XSTATS_HW_S_INFO: u16 = 2;
const IFLA_OFFLOAD_XSTATS_L3_STATS: u16 = 3;

const IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST: u16 = 1;
const IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED: u16 = 2;

/// A fully parsed entry inside `IFLA_STATS_LINK_OFFLOAD_XSTATS`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum OffloadXstat {
    CpuHit(Stats64),
    HwStatsInfo(HwStatsInfo),
    L3Stats(HwStats64),
    Other(DefaultNla),
}

impl Nla for OffloadXstat {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::CpuHit(v) => v.emit(out),
            Self::HwStatsInfo(v) => v.emit(out),
            Self::L3Stats(v) => v.emit(out),
            Self::Other(v) => {
                append_bytes(out, v.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::CpuHit(_) => IFLA_OFFLOAD_XSTATS_CPU_HIT,
            Self::HwStatsInfo(_) => {
                IFLA_OFFLOAD_XSTATS_HW_S_INFO | NLA_F_NESTED
            }
            Self::L3Stats(_) => IFLA_OFFLOAD_XSTATS_L3_STATS,
            Self::Other(v) => v.kind(),
        }
    }
}

pub(crate) fn parse_offload_xstats_inner(
    buf: &NlaBuffer<'_>,
) -> Result<Vec<OffloadXstat>, DecodeError> {
    let mut result = Vec::new();
    for nla in buf.nlas().context("invalid NLA in offload xstats")? {
        let kind = nla.kind();
        let val = nla.value();
        result.push(match kind {
            IFLA_OFFLOAD_XSTATS_CPU_HIT => OffloadXstat::CpuHit(
                Stats64::parse(val).context("invalid cpu hit stats")?,
            ),
            IFLA_OFFLOAD_XSTATS_HW_S_INFO => OffloadXstat::HwStatsInfo(
                HwStatsInfo::parse(&nla).context("invalid hw stats info")?,
            ),
            IFLA_OFFLOAD_XSTATS_L3_STATS => OffloadXstat::L3Stats(
                HwStats64::parse(val).context("invalid l3 stats")?,
            ),
            _ => OffloadXstat::Other(DefaultNla::parse(&nla)?),
        });
    }
    Ok(result)
}

/// Parsed `struct rtnl_hw_stats64` (72 bytes).
///
/// Layout-similar to [`MplsLinkStats`](super::MplsLinkStats) (both are
/// 72 bytes with 9 × u64), but they map to distinct kernel structs with
/// different semantics: the 9th field is `multicast` here vs `rx_noroute`
/// in `struct mpls_link_stats`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct HwStats64 {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct HwStats64Buffer {
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    multicast: u64,
}

impl HwStats64 {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            HwStats64Buffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<HwStats64Buffer>(),
                )
            })?;
        Ok(Self {
            rx_packets: raw.rx_packets,
            tx_packets: raw.tx_packets,
            rx_bytes: raw.rx_bytes,
            tx_bytes: raw.tx_bytes,
            rx_errors: raw.rx_errors,
            tx_errors: raw.tx_errors,
            rx_dropped: raw.rx_dropped,
            tx_dropped: raw.tx_dropped,
            multicast: raw.multicast,
        })
    }
}

impl From<&HwStats64> for HwStats64Buffer {
    fn from(value: &HwStats64) -> Self {
        Self {
            rx_packets: value.rx_packets,
            tx_packets: value.tx_packets,
            rx_bytes: value.rx_bytes,
            tx_bytes: value.tx_bytes,
            rx_errors: value.rx_errors,
            tx_errors: value.tx_errors,
            rx_dropped: value.rx_dropped,
            tx_dropped: value.tx_dropped,
            multicast: value.multicast,
        }
    }
}

impl Emitable for HwStats64 {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = HwStats64Buffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

/// Parsed HW stats info nest (`IFLA_OFFLOAD_XSTATS_HW_S_INFO`).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct HwStatsInfo {
    pub request: Option<u8>,
    pub used: Option<u8>,
}

impl HwStatsInfo {
    pub fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut info = HwStatsInfo::default();
        for nla in buf.nlas().context("invalid NLA in hw stats info")? {
            let val = nla.value();
            match nla.kind() {
                IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST if !val.is_empty() => {
                    info.request = Some(val[0])
                }
                IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED if !val.is_empty() => {
                    info.used = Some(val[0])
                }
                // L3_STATS is nested inside HW_S_INFO; descend to find
                // request/used
                IFLA_OFFLOAD_XSTATS_L3_STATS => {
                    for inner in nla
                        .nlas()
                        .context("invalid NLA in hw stats info L3 stats")?
                    {
                        let iv = inner.value();
                        match inner.kind() {
                            IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST
                                if !iv.is_empty() =>
                            {
                                info.request = Some(iv[0])
                            }
                            IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED
                                if !iv.is_empty() =>
                            {
                                info.used = Some(iv[0])
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(info)
    }
}

impl Emitable for HwStatsInfo {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let mut inner = Vec::new();
        if let Some(v) = self.request {
            DefaultNla::new(IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST, vec![v])
                .emit(&mut inner)?;
        }
        if let Some(v) = self.used {
            DefaultNla::new(IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED, vec![v])
                .emit(&mut inner)?;
        }
        if inner.is_empty() {
            return Ok(());
        }
        DefaultNla::new(IFLA_OFFLOAD_XSTATS_L3_STATS | NLA_F_NESTED, inner)
            .emit(out)
    }
}
