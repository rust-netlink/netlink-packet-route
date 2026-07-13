// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlasIterator,
    Parseable, NLA_F_NESTED,
};

use crate::link::{Stats64, Stats64Buffer};

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
    fn value_len(&self) -> usize {
        match self {
            Self::CpuHit(v) => v.buffer_len(),
            Self::L3Stats(v) => v.buffer_len(),
            Self::HwStatsInfo(v) => v.buffer_len(),
            Self::Other(v) => v.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::CpuHit(v) => v.emit(buffer),
            Self::L3Stats(v) => v.emit(buffer),
            Self::HwStatsInfo(v) => v.emit(buffer),
            Self::Other(v) => v.emit_value(buffer),
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
    payload: &[u8],
) -> Result<Vec<OffloadXstat>, DecodeError> {
    let mut result = Vec::new();
    for nla in NlasIterator::new(payload) {
        let nla = nla.context("invalid NLA in offload xstats")?;
        let kind = nla.kind() & !NLA_F_NESTED;
        let val = nla.value();
        result.push(match kind {
            IFLA_OFFLOAD_XSTATS_CPU_HIT => OffloadXstat::CpuHit(
                Stats64::parse(
                    &Stats64Buffer::new_checked(val)
                        .context("invalid cpu hit stats")?,
                )
                .context("invalid cpu hit stats")?,
            ),
            IFLA_OFFLOAD_XSTATS_HW_S_INFO => OffloadXstat::HwStatsInfo(
                HwStatsInfo::parse(val).context("invalid hw stats info")?,
            ),
            IFLA_OFFLOAD_XSTATS_L3_STATS => OffloadXstat::L3Stats(
                HwStats64::parse(
                    &HwStats64Buffer::new_checked(val)
                        .context("invalid l3 stats")?,
                )
                .context("invalid l3 stats")?,
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

const HW_STATS64_LEN: usize = 72;

buffer!(HwStats64Buffer(HW_STATS64_LEN) {
    rx_packets: (u64, 0..8),
    tx_packets: (u64, 8..16),
    rx_bytes: (u64, 16..24),
    tx_bytes: (u64, 24..32),
    rx_errors: (u64, 32..40),
    tx_errors: (u64, 40..48),
    rx_dropped: (u64, 48..56),
    tx_dropped: (u64, 56..64),
    multicast: (u64, 64..72),
});

impl<T: AsRef<[u8]>> Parseable<HwStats64Buffer<T>> for HwStats64 {
    fn parse(buf: &HwStats64Buffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            rx_packets: buf.rx_packets(),
            tx_packets: buf.tx_packets(),
            rx_bytes: buf.rx_bytes(),
            tx_bytes: buf.tx_bytes(),
            rx_errors: buf.rx_errors(),
            tx_errors: buf.tx_errors(),
            rx_dropped: buf.rx_dropped(),
            tx_dropped: buf.tx_dropped(),
            multicast: buf.multicast(),
        })
    }
}

impl Emitable for HwStats64 {
    fn buffer_len(&self) -> usize {
        HW_STATS64_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buf = HwStats64Buffer::new(buffer);
        buf.set_rx_packets(self.rx_packets);
        buf.set_tx_packets(self.tx_packets);
        buf.set_rx_bytes(self.rx_bytes);
        buf.set_tx_bytes(self.tx_bytes);
        buf.set_rx_errors(self.rx_errors);
        buf.set_tx_errors(self.tx_errors);
        buf.set_rx_dropped(self.rx_dropped);
        buf.set_tx_dropped(self.tx_dropped);
        buf.set_multicast(self.multicast);
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
    fn buffer_len(&self) -> usize {
        // L3_STATS NLA header(4) + inner NLAs (8 bytes each: hdr(4) + u8 + 3
        // pad)
        let inner_count =
            self.request.is_some() as usize + self.used.is_some() as usize;
        if inner_count == 0 {
            return 0;
        }
        4 + inner_count * 8
    }

    fn emit(&self, buffer: &mut [u8]) {
        let l3_len = self.buffer_len();
        if l3_len == 0 {
            return;
        }
        // L3_STATS NLA header
        buffer[0..2].copy_from_slice(&(l3_len as u16).to_ne_bytes());
        buffer[2..4].copy_from_slice(
            &(IFLA_OFFLOAD_XSTATS_L3_STATS | NLA_F_NESTED).to_ne_bytes(),
        );
        let mut off = 4;
        if let Some(v) = self.request {
            buffer[off..off + 2].copy_from_slice(&5u16.to_ne_bytes());
            buffer[off + 2..off + 4].copy_from_slice(
                &IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST.to_ne_bytes(),
            );
            buffer[off + 4] = v;
            buffer[off + 5..off + 8].fill(0);
            off += 8;
        }
        if let Some(v) = self.used {
            buffer[off..off + 2].copy_from_slice(&5u16.to_ne_bytes());
            buffer[off + 2..off + 4].copy_from_slice(
                &IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED.to_ne_bytes(),
            );
            buffer[off + 4] = v;
            buffer[off + 5..off + 8].fill(0);
        }
    }
}
