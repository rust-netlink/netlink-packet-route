// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlasIterator,
    Parseable, NLA_F_NESTED,
};

/// Parsed bridge xstat value.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum BridgeXstat {
    Mcast(BridgeMcastStats),
    Stp(BridgeStpXstats),
    Vlan(BridgeVlanXstats),
    Other(DefaultNla),
}

const BRIDGE_XSTATS_VLAN: u16 = 1;
const BRIDGE_XSTATS_MCAST: u16 = 2;
// const BRIDGE_XSTATS_PAD: u16 = 3;
const BRIDGE_XSTATS_STP: u16 = 4;

pub(crate) fn parse_bridge_xstats(
    payload: &[u8],
) -> Result<Vec<BridgeXstat>, DecodeError> {
    let mut result = Vec::new();
    for nla in NlasIterator::new(payload) {
        let nla = nla.context("invalid NLA in bridge xstats")?;
        let kind = nla.kind() & !NLA_F_NESTED;
        let val = nla.value();
        result.push(match kind {
            BRIDGE_XSTATS_MCAST => BridgeXstat::Mcast(
                BridgeMcastStats::parse(
                    &BridgeMcastStatsBuffer::new_checked(val)
                        .context("invalid bridge mcast stats")?,
                )
                .context("invalid bridge mcast stats")?,
            ),
            BRIDGE_XSTATS_STP => BridgeXstat::Stp(
                BridgeStpXstats::parse(
                    &BridgeStpXstatsBuffer::new_checked(val)
                        .context("invalid bridge stp stats")?,
                )
                .context("invalid bridge stp stats")?,
            ),
            BRIDGE_XSTATS_VLAN => BridgeXstat::Vlan(
                BridgeVlanXstats::parse(
                    &BridgeVlanXstatsBuffer::new_checked(val)
                        .context("invalid bridge vlan stats")?,
                )
                .context("invalid bridge vlan stats")?,
            ),
            _ => BridgeXstat::Other(DefaultNla::parse(&nla)?),
        });
    }
    Ok(result)
}

impl Nla for BridgeXstat {
    fn value_len(&self) -> usize {
        match self {
            Self::Mcast(v) => v.buffer_len(),
            Self::Stp(v) => v.buffer_len(),
            Self::Vlan(v) => v.buffer_len(),
            Self::Other(v) => v.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Mcast(v) => v.emit(buffer),
            Self::Stp(v) => v.emit(buffer),
            Self::Vlan(v) => v.emit(buffer),
            Self::Other(v) => v.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Mcast(_) => BRIDGE_XSTATS_MCAST,
            Self::Stp(_) => BRIDGE_XSTATS_STP,
            Self::Vlan(_) => BRIDGE_XSTATS_VLAN,
            Self::Other(v) => v.kind(),
        }
    }
}

/// Parsed `struct br_mcast_stats` (240 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
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

const BRIDGE_MCAST_STATS_LEN: usize = 240;

buffer!(BridgeMcastStatsBuffer(BRIDGE_MCAST_STATS_LEN) {
    igmp_v1queries_rx: (u64, 0..8),
    igmp_v1queries_tx: (u64, 8..16),
    igmp_v2queries_rx: (u64, 16..24),
    igmp_v2queries_tx: (u64, 24..32),
    igmp_v3queries_rx: (u64, 32..40),
    igmp_v3queries_tx: (u64, 40..48),
    igmp_leaves_rx: (u64, 48..56),
    igmp_leaves_tx: (u64, 56..64),
    igmp_v1reports_rx: (u64, 64..72),
    igmp_v1reports_tx: (u64, 72..80),
    igmp_v2reports_rx: (u64, 80..88),
    igmp_v2reports_tx: (u64, 88..96),
    igmp_v3reports_rx: (u64, 96..104),
    igmp_v3reports_tx: (u64, 104..112),
    igmp_parse_errors: (u64, 112..120),
    mld_v1queries_rx: (u64, 120..128),
    mld_v1queries_tx: (u64, 128..136),
    mld_v2queries_rx: (u64, 136..144),
    mld_v2queries_tx: (u64, 144..152),
    mld_leaves_rx: (u64, 152..160),
    mld_leaves_tx: (u64, 160..168),
    mld_v1reports_rx: (u64, 168..176),
    mld_v1reports_tx: (u64, 176..184),
    mld_v2reports_rx: (u64, 184..192),
    mld_v2reports_tx: (u64, 192..200),
    mld_parse_errors: (u64, 200..208),
    mcast_bytes_rx: (u64, 208..216),
    mcast_bytes_tx: (u64, 216..224),
    mcast_packets_rx: (u64, 224..232),
    mcast_packets_tx: (u64, 232..240),
});

impl<T: AsRef<[u8]>> Parseable<BridgeMcastStatsBuffer<T>> for BridgeMcastStats {
    fn parse(buf: &BridgeMcastStatsBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            igmp_v1queries_rx: buf.igmp_v1queries_rx(),
            igmp_v1queries_tx: buf.igmp_v1queries_tx(),
            igmp_v2queries_rx: buf.igmp_v2queries_rx(),
            igmp_v2queries_tx: buf.igmp_v2queries_tx(),
            igmp_v3queries_rx: buf.igmp_v3queries_rx(),
            igmp_v3queries_tx: buf.igmp_v3queries_tx(),
            igmp_leaves_rx: buf.igmp_leaves_rx(),
            igmp_leaves_tx: buf.igmp_leaves_tx(),
            igmp_v1reports_rx: buf.igmp_v1reports_rx(),
            igmp_v1reports_tx: buf.igmp_v1reports_tx(),
            igmp_v2reports_rx: buf.igmp_v2reports_rx(),
            igmp_v2reports_tx: buf.igmp_v2reports_tx(),
            igmp_v3reports_rx: buf.igmp_v3reports_rx(),
            igmp_v3reports_tx: buf.igmp_v3reports_tx(),
            igmp_parse_errors: buf.igmp_parse_errors(),
            mld_v1queries_rx: buf.mld_v1queries_rx(),
            mld_v1queries_tx: buf.mld_v1queries_tx(),
            mld_v2queries_rx: buf.mld_v2queries_rx(),
            mld_v2queries_tx: buf.mld_v2queries_tx(),
            mld_leaves_rx: buf.mld_leaves_rx(),
            mld_leaves_tx: buf.mld_leaves_tx(),
            mld_v1reports_rx: buf.mld_v1reports_rx(),
            mld_v1reports_tx: buf.mld_v1reports_tx(),
            mld_v2reports_rx: buf.mld_v2reports_rx(),
            mld_v2reports_tx: buf.mld_v2reports_tx(),
            mld_parse_errors: buf.mld_parse_errors(),
            mcast_bytes_rx: buf.mcast_bytes_rx(),
            mcast_bytes_tx: buf.mcast_bytes_tx(),
            mcast_packets_rx: buf.mcast_packets_rx(),
            mcast_packets_tx: buf.mcast_packets_tx(),
        })
    }
}

impl Emitable for BridgeMcastStats {
    fn buffer_len(&self) -> usize {
        BRIDGE_MCAST_STATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buf = BridgeMcastStatsBuffer::new(buffer);
        buf.set_igmp_v1queries_rx(self.igmp_v1queries_rx);
        buf.set_igmp_v1queries_tx(self.igmp_v1queries_tx);
        buf.set_igmp_v2queries_rx(self.igmp_v2queries_rx);
        buf.set_igmp_v2queries_tx(self.igmp_v2queries_tx);
        buf.set_igmp_v3queries_rx(self.igmp_v3queries_rx);
        buf.set_igmp_v3queries_tx(self.igmp_v3queries_tx);
        buf.set_igmp_leaves_rx(self.igmp_leaves_rx);
        buf.set_igmp_leaves_tx(self.igmp_leaves_tx);
        buf.set_igmp_v1reports_rx(self.igmp_v1reports_rx);
        buf.set_igmp_v1reports_tx(self.igmp_v1reports_tx);
        buf.set_igmp_v2reports_rx(self.igmp_v2reports_rx);
        buf.set_igmp_v2reports_tx(self.igmp_v2reports_tx);
        buf.set_igmp_v3reports_rx(self.igmp_v3reports_rx);
        buf.set_igmp_v3reports_tx(self.igmp_v3reports_tx);
        buf.set_igmp_parse_errors(self.igmp_parse_errors);
        buf.set_mld_v1queries_rx(self.mld_v1queries_rx);
        buf.set_mld_v1queries_tx(self.mld_v1queries_tx);
        buf.set_mld_v2queries_rx(self.mld_v2queries_rx);
        buf.set_mld_v2queries_tx(self.mld_v2queries_tx);
        buf.set_mld_leaves_rx(self.mld_leaves_rx);
        buf.set_mld_leaves_tx(self.mld_leaves_tx);
        buf.set_mld_v1reports_rx(self.mld_v1reports_rx);
        buf.set_mld_v1reports_tx(self.mld_v1reports_tx);
        buf.set_mld_v2reports_rx(self.mld_v2reports_rx);
        buf.set_mld_v2reports_tx(self.mld_v2reports_tx);
        buf.set_mld_parse_errors(self.mld_parse_errors);
        buf.set_mcast_bytes_rx(self.mcast_bytes_rx);
        buf.set_mcast_bytes_tx(self.mcast_bytes_tx);
        buf.set_mcast_packets_rx(self.mcast_packets_rx);
        buf.set_mcast_packets_tx(self.mcast_packets_tx);
    }
}

/// Parsed `struct bridge_stp_xstats` (48 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct BridgeStpXstats {
    pub transition_blk: u64,
    pub transition_fwd: u64,
    pub rx_bpdu: u64,
    pub tx_bpdu: u64,
    pub rx_tcn: u64,
    pub tx_tcn: u64,
}

const BRIDGE_STP_XSTATS_LEN: usize = 48;

buffer!(BridgeStpXstatsBuffer(BRIDGE_STP_XSTATS_LEN) {
    transition_blk: (u64, 0..8),
    transition_fwd: (u64, 8..16),
    rx_bpdu: (u64, 16..24),
    tx_bpdu: (u64, 24..32),
    rx_tcn: (u64, 32..40),
    tx_tcn: (u64, 40..48),
});

impl<T: AsRef<[u8]>> Parseable<BridgeStpXstatsBuffer<T>> for BridgeStpXstats {
    fn parse(buf: &BridgeStpXstatsBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            transition_blk: buf.transition_blk(),
            transition_fwd: buf.transition_fwd(),
            rx_bpdu: buf.rx_bpdu(),
            tx_bpdu: buf.tx_bpdu(),
            rx_tcn: buf.rx_tcn(),
            tx_tcn: buf.tx_tcn(),
        })
    }
}

impl Emitable for BridgeStpXstats {
    fn buffer_len(&self) -> usize {
        BRIDGE_STP_XSTATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buf = BridgeStpXstatsBuffer::new(buffer);
        buf.set_transition_blk(self.transition_blk);
        buf.set_transition_fwd(self.transition_fwd);
        buf.set_rx_bpdu(self.rx_bpdu);
        buf.set_tx_bpdu(self.tx_bpdu);
        buf.set_rx_tcn(self.rx_tcn);
        buf.set_tx_tcn(self.tx_tcn);
    }
}

/// Parsed `struct bridge_vlan_xstats` (40 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct BridgeVlanXstats {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub vid: u16,
    pub flags: u16,
}

const BRIDGE_VLAN_XSTATS_LEN: usize = 40;

buffer!(BridgeVlanXstatsBuffer(BRIDGE_VLAN_XSTATS_LEN) {
    rx_bytes: (u64, 0..8),
    rx_packets: (u64, 8..16),
    tx_bytes: (u64, 16..24),
    tx_packets: (u64, 24..32),
    vid: (u16, 32..34),
    flags: (u16, 34..36),
    pad2: (u32, 36..40),
});

impl<T: AsRef<[u8]>> Parseable<BridgeVlanXstatsBuffer<T>> for BridgeVlanXstats {
    fn parse(buf: &BridgeVlanXstatsBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            rx_bytes: buf.rx_bytes(),
            rx_packets: buf.rx_packets(),
            tx_bytes: buf.tx_bytes(),
            tx_packets: buf.tx_packets(),
            vid: buf.vid(),
            flags: buf.flags(),
        })
    }
}

impl Emitable for BridgeVlanXstats {
    fn buffer_len(&self) -> usize {
        BRIDGE_VLAN_XSTATS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buf = BridgeVlanXstatsBuffer::new(buffer);
        buf.set_rx_bytes(self.rx_bytes);
        buf.set_rx_packets(self.rx_packets);
        buf.set_tx_bytes(self.tx_bytes);
        buf.set_tx_packets(self.tx_packets);
        buf.set_vid(self.vid);
        buf.set_flags(self.flags);
        buf.set_pad2(0);
    }
}
