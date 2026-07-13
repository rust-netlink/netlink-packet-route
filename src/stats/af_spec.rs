// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlasIterator,
    Parseable, NLA_F_NESTED,
};

const AF_MPLS: u16 = 28;
const MPLS_STATS_LINK: u16 = 1;

/// Parsed `struct mpls_link_stats` (72 bytes).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct MplsLinkStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_noroute: u64,
}

const MPLS_LINK_STATS_LEN: usize = 72;

buffer!(MplsLinkStatsBuffer(MPLS_LINK_STATS_LEN) {
    rx_packets: (u64, 0..8),
    tx_packets: (u64, 8..16),
    rx_bytes: (u64, 16..24),
    tx_bytes: (u64, 24..32),
    rx_errors: (u64, 32..40),
    tx_errors: (u64, 40..48),
    rx_dropped: (u64, 48..56),
    tx_dropped: (u64, 56..64),
    rx_noroute: (u64, 64..72),
});

impl<T: AsRef<[u8]>> Parseable<MplsLinkStatsBuffer<T>> for MplsLinkStats {
    fn parse(buf: &MplsLinkStatsBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            rx_packets: buf.rx_packets(),
            tx_packets: buf.tx_packets(),
            rx_bytes: buf.rx_bytes(),
            tx_bytes: buf.tx_bytes(),
            rx_errors: buf.rx_errors(),
            tx_errors: buf.tx_errors(),
            rx_dropped: buf.rx_dropped(),
            tx_dropped: buf.tx_dropped(),
            rx_noroute: buf.rx_noroute(),
        })
    }
}

impl Nla for MplsLinkStats {
    fn value_len(&self) -> usize {
        MPLS_LINK_STATS_LEN
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut buf = MplsLinkStatsBuffer::new(buffer);
        buf.set_rx_packets(self.rx_packets);
        buf.set_tx_packets(self.tx_packets);
        buf.set_rx_bytes(self.rx_bytes);
        buf.set_tx_bytes(self.tx_bytes);
        buf.set_rx_errors(self.rx_errors);
        buf.set_tx_errors(self.tx_errors);
        buf.set_rx_dropped(self.rx_dropped);
        buf.set_tx_dropped(self.tx_dropped);
        buf.set_rx_noroute(self.rx_noroute);
    }

    fn kind(&self) -> u16 {
        MPLS_STATS_LINK
    }
}

/// A parsed entry inside `IFLA_STATS_AF_SPEC`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum AfSpecStat {
    Mpls(MplsLinkStats),
    Other(DefaultNla),
}

impl Nla for AfSpecStat {
    fn value_len(&self) -> usize {
        match self {
            Self::Mpls(v) => v.buffer_len(),
            Self::Other(v) => v.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Mpls(v) => v.emit(buffer),
            Self::Other(v) => v.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Mpls(_) => AF_MPLS,
            Self::Other(v) => v.kind(),
        }
    }
}

/// Parsed content of `IFLA_STATS_AF_SPEC`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct AfSpecStats(pub Vec<AfSpecStat>);

impl Emitable for AfSpecStats {
    fn buffer_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer);
    }
}

impl AfSpecStats {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut entries = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla = nla.context("invalid NLA in AF_SPEC stats")?;
            let family = nla.kind() & !NLA_F_NESTED;
            if family == AF_MPLS {
                entries.push(AfSpecStat::Mpls(parse_mpls_stats(nla.value())?));
            } else {
                entries.push(AfSpecStat::Other(DefaultNla::parse(&nla)?));
            }
        }
        Ok(AfSpecStats(entries))
    }
}

fn parse_mpls_stats(payload: &[u8]) -> Result<MplsLinkStats, DecodeError> {
    for nla in NlasIterator::new(payload) {
        let nla = nla.context("invalid NLA in MPLS stats")?;
        let kind = nla.kind() & !NLA_F_NESTED;
        if kind == MPLS_STATS_LINK {
            let val = nla.value();
            return MplsLinkStats::parse(
                &MplsLinkStatsBuffer::new_checked(val)
                    .context("invalid MPLS link stats")?,
            )
            .context("invalid MPLS link stats");
        }
    }
    Ok(MplsLinkStats::default())
}
