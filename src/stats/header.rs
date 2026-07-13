// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, NlaBuffer, NlasIterator, Parseable,
};

use crate::AddressFamily;

const STATS_HEADER_LEN: usize = 12;

buffer!(StatsMessageBuffer(STATS_HEADER_LEN) {
    family: (u8, 0),
    pad1: (u8, 1),
    pad2: (u16, 2..4),
    ifindex: (u32, 4..8),
    filter_mask: (u32, 8..STATS_HEADER_LEN),
    payload: (slice, STATS_HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized> StatsMessageBuffer<&'a T> {
    pub fn attributes(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

// The kernel uses IFLA_STATS_FILTER_BIT(attr) = 1 << (attr - 1)
// (see include/uapi/linux/if_link.h)
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub struct StatsFilterMask: u32 {
        const Link64 =
            1 << (super::attribute::IFLA_STATS_LINK_64 as u32 - 1);
        const LinkXstats =
            1 << (super::attribute::IFLA_STATS_LINK_XSTATS as u32 - 1);
        const LinkXstatsPort =
            1 << (super::attribute::IFLA_STATS_LINK_XSTATS_SLAVE as u32 - 1);
        const LinkOffloadXstats =
            1 << (super::attribute::IFLA_STATS_LINK_OFFLOAD_XSTATS as u32 - 1);
        const AfSpec =
            1 << (super::attribute::IFLA_STATS_AF_SPEC as u32 - 1);
        const _ = !0;
    }
}

impl Default for StatsFilterMask {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct StatsHeader {
    pub family: AddressFamily,
    pub ifindex: u32,
    pub filter_mask: StatsFilterMask,
}

impl Emitable for StatsHeader {
    fn buffer_len(&self) -> usize {
        STATS_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = StatsMessageBuffer::new(buffer);
        packet.set_family(self.family.into());
        packet.set_pad1(0);
        packet.set_pad2(0);
        packet.set_ifindex(self.ifindex);
        packet.set_filter_mask(self.filter_mask.bits());
    }
}

impl<T: AsRef<[u8]>> Parseable<StatsMessageBuffer<T>> for StatsHeader {
    fn parse(buf: &StatsMessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(StatsHeader {
            family: buf.family().into(),
            ifindex: buf.ifindex(),
            filter_mask: StatsFilterMask::from_bits_retain(buf.filter_mask()),
        })
    }
}
