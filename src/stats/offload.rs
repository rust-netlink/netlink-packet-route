// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{
    append_bytes, append_u16, append_u8, DecodeError, DefaultNla, Emitable,
    EncodeError, ErrorContext, Nla, NlasIterator, Parseable, NLA_F_NESTED,
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
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::CpuHit(v) => v.emit_into(out),
            Self::HwStatsInfo(v) => v.emit_into(out),
            Self::L3Stats(v) => v.emit_into(out),
            Self::Other(v) => {
                append_bytes(out, v.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        <OffloadXstat>::kind(self)
    }
}

impl OffloadXstat {
    pub(crate) fn kind(&self) -> u16 {
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
    payload: &[u8],
) -> Result<Vec<OffloadXstat>, DecodeError> {
    let mut result = Vec::new();
    for nla in NlasIterator::new(payload) {
        let nla = nla.context("invalid NLA in offload xstats")?;
        let kind = nla.kind() & !NLA_F_NESTED;
        let val = nla.value();
        result.push(match kind {
            IFLA_OFFLOAD_XSTATS_CPU_HIT => OffloadXstat::CpuHit(
                Stats64::parse(val).context("invalid cpu hit stats")?,
            ),
            IFLA_OFFLOAD_XSTATS_HW_S_INFO => OffloadXstat::HwStatsInfo(
                HwStatsInfo::parse(val).context("invalid hw stats info")?,
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
pub struct HwStats64Buffer {
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

#[allow(dead_code)]
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
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
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
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut info = HwStatsInfo::default();
        for nla in NlasIterator::new(payload) {
            let nla = nla.context("invalid NLA in hw stats info")?;
            let val = nla.value();
            match nla.kind() & !NLA_F_NESTED {
                IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST if !val.is_empty() => {
                    info.request = Some(val[0])
                }
                IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED if !val.is_empty() => {
                    info.used = Some(val[0])
                }
                // L3_STATS is nested inside HW_S_INFO; descend to find
                // request/used
                IFLA_OFFLOAD_XSTATS_L3_STATS => {
                    for inner in NlasIterator::new(val) {
                        let inner = inner
                            .context("invalid NLA in hw stats info L3 stats")?;
                        let iv = inner.value();
                        match inner.kind() & !NLA_F_NESTED {
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
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // L3_STATS NLA header(4) + inner NLAs (8 bytes each: hdr(4) + u8 + 3
        // pad)
        let inner_count =
            self.request.is_some() as usize + self.used.is_some() as usize;
        if inner_count == 0 {
            return Ok(());
        }
        let l3_len = 4 + inner_count * 8;
        // L3_STATS NLA header
        append_u16(out, l3_len as u16);
        append_u16(out, IFLA_OFFLOAD_XSTATS_L3_STATS | NLA_F_NESTED);
        if let Some(v) = self.request {
            append_u16(out, 5);
            append_u16(out, IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST);
            append_u8(out, v);
            append_bytes(out, &[0, 0, 0]);
        }
        if let Some(v) = self.used {
            append_u16(out, 5);
            append_u16(out, IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED);
            append_u8(out, v);
            append_bytes(out, &[0, 0, 0]);
        }
        Ok(())
    }
}
