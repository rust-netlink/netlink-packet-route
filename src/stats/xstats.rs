// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, Nla, NlaBuffer, NlasIterator,
    Parseable, NLA_F_NESTED,
};

const LINK_XSTATS_TYPE_BRIDGE: u16 = 1;
const LINK_XSTATS_TYPE_BOND: u16 = 2;

const BRIDGE_XSTATS_VLAN: u16 = 1;
const BRIDGE_XSTATS_MCAST: u16 = 2;
const BRIDGE_XSTATS_STP: u16 = 4;

const BOND_XSTATS_3AD: u16 = 1;

const IFLA_OFFLOAD_XSTATS_CPU_HIT: u16 = 1;
const IFLA_OFFLOAD_XSTATS_HW_S_INFO: u16 = 2;
const IFLA_OFFLOAD_XSTATS_L3_STATS: u16 = 3;

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
    Other(u16, Vec<u8>),
}

impl Nla for LinkXstatGroup {
    fn value_len(&self) -> usize {
        match self {
            Self::Bridge(v) => v.as_slice().buffer_len(),
            Self::Bond(v) => v.as_slice().buffer_len(),
            Self::Other(_, d) => d.len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Bridge(v) => v.as_slice().emit(buffer),
            Self::Bond(v) => v.as_slice().emit(buffer),
            Self::Other(_, d) => buffer.copy_from_slice(d),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Bridge(_) => LINK_XSTATS_TYPE_BRIDGE | NLA_F_NESTED,
            Self::Bond(_) => LINK_XSTATS_TYPE_BOND | NLA_F_NESTED,
            Self::Other(k, _) => *k,
        }
    }
}

pub(crate) struct VecLinkXstats(pub(crate) Vec<LinkXstatGroup>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for VecLinkXstats
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut groups = Vec::new();
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = nla?;
            let kind = nla.kind() & !NLA_F_NESTED;
            let val = nla.value();
            groups.push(match kind {
                LINK_XSTATS_TYPE_BRIDGE => LinkXstatGroup::Bridge(
                    parse_bridge_xstats(val)
                        .context("invalid bridge xstats in link xstats")?,
                ),
                LINK_XSTATS_TYPE_BOND => LinkXstatGroup::Bond(
                    parse_bond_xstats(val)
                        .context("invalid bond xstats in link xstats")?,
                ),
                _ => LinkXstatGroup::Other(kind, val.to_vec()),
            });
        }
        Ok(Self(groups))
    }
}

fn parse_bridge_xstats(
    payload: &[u8],
) -> Result<Vec<BridgeXstat>, DecodeError> {
    let mut result = Vec::new();
    for nla in NlasIterator::new(payload) {
        let nla = nla.context("invalid NLA in bridge xstats")?;
        let kind = nla.kind() & !NLA_F_NESTED;
        let val = nla.value();
        result.push(match kind {
            BRIDGE_XSTATS_MCAST => BridgeXstat::Mcast(
                BridgeMcastStats::parse(val)
                    .ok_or(DecodeError::from("invalid bridge mcast stats"))?,
            ),
            BRIDGE_XSTATS_STP => BridgeXstat::Stp(
                BridgeStpXstats::parse(val)
                    .ok_or(DecodeError::from("invalid bridge stp stats"))?,
            ),
            BRIDGE_XSTATS_VLAN => BridgeXstat::Vlan(
                BridgeVlanXstats::parse(val)
                    .ok_or(DecodeError::from("invalid bridge vlan stats"))?,
            ),
            _ => BridgeXstat::Other(kind, val.to_vec()),
        });
    }
    Ok(result)
}

fn parse_bond_xstats(payload: &[u8]) -> Result<Vec<BondXstat>, DecodeError> {
    let mut result = Vec::new();
    for nla in NlasIterator::new(payload) {
        let nla = nla.context("invalid NLA in bond xstats")?;
        let kind = nla.kind() & !NLA_F_NESTED;
        let val = nla.value();
        result.push(match kind {
            BOND_XSTATS_3AD => BondXstat::Threead(Bond3adStats::parse(val)),
            _ => BondXstat::Other(kind, val.to_vec()),
        });
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Bridge xstats types
// ---------------------------------------------------------------------------

/// Parsed bridge xstat value.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum BridgeXstat {
    Mcast(BridgeMcastStats),
    Stp(BridgeStpXstats),
    Vlan(BridgeVlanXstats),
    Other(u16, Vec<u8>),
}

impl Nla for BridgeXstat {
    fn value_len(&self) -> usize {
        match self {
            Self::Mcast(v) => v.buffer_len(),
            Self::Stp(v) => v.buffer_len(),
            Self::Vlan(_) => 40, // raw struct bytes, no NLA wrapper
            Self::Other(_, d) => d.len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Mcast(v) => v.emit(buffer),
            Self::Stp(v) => v.emit(buffer),
            Self::Vlan(v) => v.emit_value(buffer),
            Self::Other(_, d) => buffer.copy_from_slice(d),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Mcast(_) => BRIDGE_XSTATS_MCAST,
            Self::Stp(_) => BRIDGE_XSTATS_STP,
            Self::Vlan(_) => BRIDGE_XSTATS_VLAN,
            Self::Other(k, _) => *k,
        }
    }
}

/// Parsed `struct br_mcast_stats` (240 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct BridgeMcastStats {
    pub igmp_v1queries_rx: u64,
    pub igmp_v1queries_tx: u64,
    pub igmp_v2queries_rx: u64,
    pub igmp_v2queries_tx: u64,
    pub igmp_v3queries_rx: u64,
    pub igmp_v3queries_tx: u64,
    pub igmp_leaves_rx: u64,
    pub igmp_leaves_tx: u64,
    pub igmp_v1reports_rx: u64,
    pub igmp_v1reports_tx: u64,
    pub igmp_v2reports_rx: u64,
    pub igmp_v2reports_tx: u64,
    pub igmp_v3reports_rx: u64,
    pub igmp_v3reports_tx: u64,
    pub igmp_parse_errors: u64,
    pub mld_v1queries_rx: u64,
    pub mld_v1queries_tx: u64,
    pub mld_v2queries_rx: u64,
    pub mld_v2queries_tx: u64,
    pub mld_leaves_rx: u64,
    pub mld_leaves_tx: u64,
    pub mld_v1reports_rx: u64,
    pub mld_v1reports_tx: u64,
    pub mld_v2reports_rx: u64,
    pub mld_v2reports_tx: u64,
    pub mld_parse_errors: u64,
    pub mcast_bytes_rx: u64,
    pub mcast_bytes_tx: u64,
    pub mcast_packets_rx: u64,
    pub mcast_packets_tx: u64,
}

impl BridgeMcastStats {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 240 {
            return None;
        }
        fn le64(d: &[u8]) -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&d[..8]);
            u64::from_ne_bytes(b)
        }
        Some(Self {
            igmp_v1queries_rx: le64(&data[0..8]),
            igmp_v1queries_tx: le64(&data[8..16]),
            igmp_v2queries_rx: le64(&data[16..24]),
            igmp_v2queries_tx: le64(&data[24..32]),
            igmp_v3queries_rx: le64(&data[32..40]),
            igmp_v3queries_tx: le64(&data[40..48]),
            igmp_leaves_rx: le64(&data[48..56]),
            igmp_leaves_tx: le64(&data[56..64]),
            igmp_v1reports_rx: le64(&data[64..72]),
            igmp_v1reports_tx: le64(&data[72..80]),
            igmp_v2reports_rx: le64(&data[80..88]),
            igmp_v2reports_tx: le64(&data[88..96]),
            igmp_v3reports_rx: le64(&data[96..104]),
            igmp_v3reports_tx: le64(&data[104..112]),
            igmp_parse_errors: le64(&data[112..120]),
            mld_v1queries_rx: le64(&data[120..128]),
            mld_v1queries_tx: le64(&data[128..136]),
            mld_v2queries_rx: le64(&data[136..144]),
            mld_v2queries_tx: le64(&data[144..152]),
            mld_leaves_rx: le64(&data[152..160]),
            mld_leaves_tx: le64(&data[160..168]),
            mld_v1reports_rx: le64(&data[168..176]),
            mld_v1reports_tx: le64(&data[176..184]),
            mld_v2reports_rx: le64(&data[184..192]),
            mld_v2reports_tx: le64(&data[192..200]),
            mld_parse_errors: le64(&data[200..208]),
            mcast_bytes_rx: le64(&data[208..216]),
            mcast_bytes_tx: le64(&data[216..224]),
            mcast_packets_rx: le64(&data[224..232]),
            mcast_packets_tx: le64(&data[232..240]),
        })
    }
}

impl Emitable for BridgeMcastStats {
    fn buffer_len(&self) -> usize {
        240
    }

    fn emit(&self, buffer: &mut [u8]) {
        fn emit_u64(buf: &mut [u8], val: u64) {
            buf.copy_from_slice(&val.to_ne_bytes());
        }
        emit_u64(&mut buffer[0..8], self.igmp_v1queries_rx);
        emit_u64(&mut buffer[8..16], self.igmp_v1queries_tx);
        emit_u64(&mut buffer[16..24], self.igmp_v2queries_rx);
        emit_u64(&mut buffer[24..32], self.igmp_v2queries_tx);
        emit_u64(&mut buffer[32..40], self.igmp_v3queries_rx);
        emit_u64(&mut buffer[40..48], self.igmp_v3queries_tx);
        emit_u64(&mut buffer[48..56], self.igmp_leaves_rx);
        emit_u64(&mut buffer[56..64], self.igmp_leaves_tx);
        emit_u64(&mut buffer[64..72], self.igmp_v1reports_rx);
        emit_u64(&mut buffer[72..80], self.igmp_v1reports_tx);
        emit_u64(&mut buffer[80..88], self.igmp_v2reports_rx);
        emit_u64(&mut buffer[88..96], self.igmp_v2reports_tx);
        emit_u64(&mut buffer[96..104], self.igmp_v3reports_rx);
        emit_u64(&mut buffer[104..112], self.igmp_v3reports_tx);
        emit_u64(&mut buffer[112..120], self.igmp_parse_errors);
        emit_u64(&mut buffer[120..128], self.mld_v1queries_rx);
        emit_u64(&mut buffer[128..136], self.mld_v1queries_tx);
        emit_u64(&mut buffer[136..144], self.mld_v2queries_rx);
        emit_u64(&mut buffer[144..152], self.mld_v2queries_tx);
        emit_u64(&mut buffer[152..160], self.mld_leaves_rx);
        emit_u64(&mut buffer[160..168], self.mld_leaves_tx);
        emit_u64(&mut buffer[168..176], self.mld_v1reports_rx);
        emit_u64(&mut buffer[176..184], self.mld_v1reports_tx);
        emit_u64(&mut buffer[184..192], self.mld_v2reports_rx);
        emit_u64(&mut buffer[192..200], self.mld_v2reports_tx);
        emit_u64(&mut buffer[200..208], self.mld_parse_errors);
        emit_u64(&mut buffer[208..216], self.mcast_bytes_rx);
        emit_u64(&mut buffer[216..224], self.mcast_bytes_tx);
        emit_u64(&mut buffer[224..232], self.mcast_packets_rx);
        emit_u64(&mut buffer[232..240], self.mcast_packets_tx);
    }
}

/// Parsed `struct bridge_stp_xstats` (48 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct BridgeStpXstats {
    pub transition_blk: u64,
    pub transition_fwd: u64,
    pub rx_bpdu: u64,
    pub tx_bpdu: u64,
    pub rx_tcn: u64,
    pub tx_tcn: u64,
}

impl BridgeStpXstats {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }
        fn le64(d: &[u8]) -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&d[..8]);
            u64::from_ne_bytes(b)
        }
        Some(Self {
            transition_blk: le64(&data[0..8]),
            transition_fwd: le64(&data[8..16]),
            rx_bpdu: le64(&data[16..24]),
            tx_bpdu: le64(&data[24..32]),
            rx_tcn: le64(&data[32..40]),
            tx_tcn: le64(&data[40..48]),
        })
    }
}

impl Emitable for BridgeStpXstats {
    fn buffer_len(&self) -> usize {
        48
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0..8].copy_from_slice(&self.transition_blk.to_ne_bytes());
        buffer[8..16].copy_from_slice(&self.transition_fwd.to_ne_bytes());
        buffer[16..24].copy_from_slice(&self.rx_bpdu.to_ne_bytes());
        buffer[24..32].copy_from_slice(&self.tx_bpdu.to_ne_bytes());
        buffer[32..40].copy_from_slice(&self.rx_tcn.to_ne_bytes());
        buffer[40..48].copy_from_slice(&self.tx_tcn.to_ne_bytes());
    }
}

/// Parsed `struct bridge_vlan_xstats` (40 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct BridgeVlanXstats {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub vid: u16,
    pub flags: u16,
}

impl Nla for BridgeVlanXstats {
    fn value_len(&self) -> usize {
        40
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0..8].copy_from_slice(&self.rx_bytes.to_ne_bytes());
        buffer[8..16].copy_from_slice(&self.rx_packets.to_ne_bytes());
        buffer[16..24].copy_from_slice(&self.tx_bytes.to_ne_bytes());
        buffer[24..32].copy_from_slice(&self.tx_packets.to_ne_bytes());
        buffer[32..34].copy_from_slice(&self.vid.to_ne_bytes());
        buffer[34..36].copy_from_slice(&self.flags.to_ne_bytes());
        // pad2 = 0 (unused)
    }

    fn kind(&self) -> u16 {
        BRIDGE_XSTATS_VLAN
    }
}

impl BridgeVlanXstats {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        fn le64(d: &[u8]) -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&d[..8]);
            u64::from_ne_bytes(b)
        }
        Some(Self {
            rx_bytes: le64(&data[0..8]),
            rx_packets: le64(&data[8..16]),
            tx_bytes: le64(&data[16..24]),
            tx_packets: le64(&data[24..32]),
            vid: u16::from_ne_bytes(data[32..34].try_into().unwrap()),
            flags: u16::from_ne_bytes(data[34..36].try_into().unwrap()),
        })
    }
}

// ---------------------------------------------------------------------------
// Bond xstats types
// ---------------------------------------------------------------------------

/// Parsed bond xstat value.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum BondXstat {
    Threead(Bond3adStats),
    Other(u16, Vec<u8>),
}

impl Nla for BondXstat {
    fn value_len(&self) -> usize {
        match self {
            Self::Threead(v) => v.buffer_len(),
            Self::Other(_, d) => d.len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Threead(v) => v.emit(buffer),
            Self::Other(_, d) => buffer.copy_from_slice(d),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Threead(_) => BOND_XSTATS_3AD | NLA_F_NESTED,
            Self::Other(k, _) => *k,
        }
    }
}

/// Parsed `BOND_XSTATS_3AD` content.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Bond3adStats {
    pub lacpdu_rx: Option<u64>,
    pub lacpdu_tx: Option<u64>,
    pub lacpdu_unknown_rx: Option<u64>,
    pub lacpdu_illegal_rx: Option<u64>,
    pub marker_rx: Option<u64>,
    pub marker_tx: Option<u64>,
    pub marker_resp_rx: Option<u64>,
    pub marker_resp_tx: Option<u64>,
    pub marker_unknown_rx: Option<u64>,
}

impl Bond3adStats {
    pub fn parse(payload: &[u8]) -> Self {
        fn le64(d: &[u8]) -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&d[..8]);
            u64::from_ne_bytes(b)
        }
        let mut stats = Bond3adStats::default();
        for nla in NlasIterator::new(payload).filter_map(|n| n.ok()) {
            let val = nla.value();
            if val.len() < 8 {
                continue;
            }
            let v = le64(val);
            match nla.kind() & !NLA_F_NESTED {
                1 => stats.lacpdu_rx = Some(v),
                2 => stats.lacpdu_tx = Some(v),
                3 => stats.lacpdu_unknown_rx = Some(v),
                4 => stats.lacpdu_illegal_rx = Some(v),
                5 => stats.marker_rx = Some(v),
                6 => stats.marker_tx = Some(v),
                7 => stats.marker_resp_rx = Some(v),
                8 => stats.marker_resp_tx = Some(v),
                9 => stats.marker_unknown_rx = Some(v),
                _ => {}
            }
        }
        stats
    }

    pub fn buffer_len(&self) -> usize {
        let mut len = 0;
        macro_rules! add {
            ($f:ident, $k:expr) => {
                if self.$f.is_some() {
                    len += 4 + 8; // NLA header + u64
                }
            };
        }
        add!(lacpdu_rx, 1);
        add!(lacpdu_tx, 2);
        add!(lacpdu_unknown_rx, 3);
        add!(lacpdu_illegal_rx, 4);
        add!(marker_rx, 5);
        add!(marker_tx, 6);
        add!(marker_resp_rx, 7);
        add!(marker_resp_tx, 8);
        add!(marker_unknown_rx, 9);
        len
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        let nla_len: u16 = 4 + 8;
        let mut off = 0;
        macro_rules! emit {
            ($f:ident, $k:expr) => {
                if let Some(v) = self.$f {
                    buffer[off..off + 2]
                        .copy_from_slice(&nla_len.to_ne_bytes());
                    buffer[off + 2..off + 4]
                        .copy_from_slice(&($k as u16).to_ne_bytes());
                    buffer[off + 4..off + 12].copy_from_slice(&v.to_ne_bytes());
                    off += 12;
                }
            };
        }
        emit!(lacpdu_rx, 1);
        emit!(lacpdu_tx, 2);
        emit!(lacpdu_unknown_rx, 3);
        emit!(lacpdu_illegal_rx, 4);
        emit!(marker_rx, 5);
        emit!(marker_tx, 6);
        emit!(marker_resp_rx, 7);
        emit!(marker_resp_tx, 8);
        emit!(marker_unknown_rx, 9);
        let _ = off;
    }
}

// ---------------------------------------------------------------------------
// Offload xstats (inside IFLA_STATS_LINK_OFFLOAD_XSTATS)
// ---------------------------------------------------------------------------

/// A fully parsed entry inside `IFLA_STATS_LINK_OFFLOAD_XSTATS`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum OffloadXstat {
    CpuHit(HwStats64),
    HwSInfo(HwSInfo),
    L3Stats(HwStats64),
    Other(u16, Vec<u8>),
}

impl Nla for OffloadXstat {
    fn value_len(&self) -> usize {
        match self {
            Self::CpuHit(v) | Self::L3Stats(v) => v.buffer_len(),
            Self::HwSInfo(v) => v.buffer_len(),
            Self::Other(_, d) => d.len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::CpuHit(v) | Self::L3Stats(v) => v.emit(buffer),
            Self::HwSInfo(v) => v.emit(buffer),
            Self::Other(_, d) => buffer.copy_from_slice(d),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::CpuHit(_) => IFLA_OFFLOAD_XSTATS_CPU_HIT,
            Self::HwSInfo(_) => IFLA_OFFLOAD_XSTATS_HW_S_INFO | NLA_F_NESTED,
            Self::L3Stats(_) => IFLA_OFFLOAD_XSTATS_L3_STATS,
            Self::Other(k, _) => *k,
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
                HwStats64::parse(val)
                    .ok_or(DecodeError::from("invalid cpu hit stats"))?,
            ),
            IFLA_OFFLOAD_XSTATS_HW_S_INFO => {
                OffloadXstat::HwSInfo(HwSInfo::parse(val))
            }
            IFLA_OFFLOAD_XSTATS_L3_STATS => OffloadXstat::L3Stats(
                HwStats64::parse(val)
                    .ok_or(DecodeError::from("invalid l3 stats"))?,
            ),
            _ => OffloadXstat::Other(kind, val.to_vec()),
        });
    }
    Ok(result)
}

/// Parsed `struct rtnl_hw_stats64` (72 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
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

impl HwStats64 {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 72 {
            return None;
        }
        fn le64(d: &[u8]) -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&d[..8]);
            u64::from_ne_bytes(b)
        }
        Some(Self {
            rx_packets: le64(&data[0..8]),
            tx_packets: le64(&data[8..16]),
            rx_bytes: le64(&data[16..24]),
            tx_bytes: le64(&data[24..32]),
            rx_errors: le64(&data[32..40]),
            tx_errors: le64(&data[40..48]),
            rx_dropped: le64(&data[48..56]),
            tx_dropped: le64(&data[56..64]),
            multicast: le64(&data[64..72]),
        })
    }
}

impl Emitable for HwStats64 {
    fn buffer_len(&self) -> usize {
        72
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0..8].copy_from_slice(&self.rx_packets.to_ne_bytes());
        buffer[8..16].copy_from_slice(&self.tx_packets.to_ne_bytes());
        buffer[16..24].copy_from_slice(&self.rx_bytes.to_ne_bytes());
        buffer[24..32].copy_from_slice(&self.tx_bytes.to_ne_bytes());
        buffer[32..40].copy_from_slice(&self.rx_errors.to_ne_bytes());
        buffer[40..48].copy_from_slice(&self.tx_errors.to_ne_bytes());
        buffer[48..56].copy_from_slice(&self.rx_dropped.to_ne_bytes());
        buffer[56..64].copy_from_slice(&self.tx_dropped.to_ne_bytes());
        buffer[64..72].copy_from_slice(&self.multicast.to_ne_bytes());
    }
}

/// Parsed HW stats info nest (`IFLA_OFFLOAD_XSTATS_HW_S_INFO`).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct HwSInfo {
    pub request: Option<u8>,
    pub used: Option<u8>,
}

impl HwSInfo {
    pub fn parse(payload: &[u8]) -> Self {
        let mut info = HwSInfo::default();
        for nla in NlasIterator::new(payload).filter_map(|n| n.ok()) {
            let val = nla.value();
            match nla.kind() & !NLA_F_NESTED {
                1 if !val.is_empty() => info.request = Some(val[0]),
                2 if !val.is_empty() => info.used = Some(val[0]),
                // L3_STATS is nested inside HW_S_INFO; descend to find
                // request/used
                IFLA_OFFLOAD_XSTATS_L3_STATS => {
                    for inner in NlasIterator::new(val).filter_map(|n| n.ok()) {
                        let iv = inner.value();
                        match inner.kind() & !NLA_F_NESTED {
                            1 if !iv.is_empty() => info.request = Some(iv[0]),
                            2 if !iv.is_empty() => info.used = Some(iv[0]),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        info
    }

    pub fn buffer_len(&self) -> usize {
        let mut len = 0;
        if self.request.is_some() {
            len += 4 + 1; // NLA header + u8 (+ padding to 4)
            len += (4 - (len % 4)) % 4;
        }
        if self.used.is_some() {
            len += 4 + 1;
            len += (4 - (len % 4)) % 4;
        }
        len
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        let mut off = 0;
        if let Some(v) = self.request {
            let padded = 4 + 4; // NLA header + 4 bytes (u8 + 3 padding)
            buffer[off..off + 2]
                .copy_from_slice(&(padded as u16).to_ne_bytes());
            buffer[off + 2..off + 4].copy_from_slice(&1u16.to_ne_bytes());
            buffer[off + 4] = v;
            off += padded;
        }
        if let Some(v) = self.used {
            let padded = 4 + 4;
            buffer[off..off + 2]
                .copy_from_slice(&(padded as u16).to_ne_bytes());
            buffer[off + 2..off + 4].copy_from_slice(&2u16.to_ne_bytes());
            buffer[off + 4] = v;
        }
    }
}

// ---------------------------------------------------------------------------
// AF_SPEC stats (inside IFLA_STATS_AF_SPEC)
// ---------------------------------------------------------------------------

/// Parsed content of IFLA_STATS_AF_SPEC.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct AfSpecStats(pub Vec<AfSpecStatEntry>);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AfSpecStatEntry {
    pub af_type: u16,
    pub data: Vec<u8>,
}

impl Nla for AfSpecStatEntry {
    fn value_len(&self) -> usize {
        self.data.len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.data);
    }

    fn kind(&self) -> u16 {
        self.af_type
    }
}

impl Emitable for AfSpecStats {
    fn buffer_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer);
    }
}

impl AfSpecStats {
    pub fn parse(payload: &[u8]) -> Self {
        let entries = NlasIterator::new(payload)
            .filter_map(|nla| nla.ok())
            .map(|nla| AfSpecStatEntry {
                af_type: nla.kind() & !NLA_F_NESTED,
                data: nla.value().to_vec(),
            })
            .collect();
        AfSpecStats(entries)
    }
}
