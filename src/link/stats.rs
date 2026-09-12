// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
#[non_exhaustive]
pub struct Stats {
    /// total packets received
    pub rx_packets: u32,
    /// total packets transmitted
    pub tx_packets: u32,
    /// total bytes received
    pub rx_bytes: u32,
    /// total bytes transmitted
    pub tx_bytes: u32,
    /// bad packets received
    pub rx_errors: u32,
    /// packet transmit problems
    pub tx_errors: u32,
    /// no space in linux buffers
    pub rx_dropped: u32,
    /// no space available in linux
    pub tx_dropped: u32,
    /// multicast packets received
    pub multicast: u32,
    pub collisions: u32,

    // detailed rx_errors
    pub rx_length_errors: u32,
    /// receiver ring buff overflow
    pub rx_over_errors: u32,
    /// received packets with crc error
    pub rx_crc_errors: u32,
    /// received frame alignment errors
    pub rx_frame_errors: u32,
    /// recv'r fifo overrun
    pub rx_fifo_errors: u32,
    /// receiver missed packet
    pub rx_missed_errors: u32,

    // detailed tx_errors
    pub tx_aborted_errors: u32,
    pub tx_carrier_errors: u32,
    pub tx_fifo_errors: u32,
    pub tx_heartbeat_errors: u32,
    pub tx_window_errors: u32,

    // for cslip etc
    pub rx_compressed: u32,
    pub tx_compressed: u32,

    /// dropped, no handler found
    pub rx_nohandler: u32,
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
pub struct StatsBuffer {
    rx_packets: u32,
    tx_packets: u32,
    rx_bytes: u32,
    tx_bytes: u32,
    rx_errors: u32,
    tx_errors: u32,
    rx_dropped: u32,
    tx_dropped: u32,
    multicast: u32,
    collisions: u32,
    rx_length_errors: u32,
    rx_over_errors: u32,
    rx_crc_errors: u32,
    rx_frame_errors: u32,
    rx_fifo_errors: u32,
    rx_missed_errors: u32,
    tx_aborted_errors: u32,
    tx_carrier_errors: u32,
    tx_fifo_errors: u32,
    tx_heartbeat_errors: u32,
    tx_window_errors: u32,
    rx_compressed: u32,
    tx_compressed: u32,
    rx_nohandler: u32,
}

impl Stats {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        // The payload length is the size of `struct rtnl_link_stats` of the
        // kernel which sent the message: older kernels send a payload
        // shorter than `StatsBuffer`. Zero fill the missing trailing fields
        // like iproute2 does in `get_rtnl_link_stats_rta()`, instead of
        // failing the whole message decoding.
        let mut buffer = StatsBuffer::new_zeroed();
        let len = payload.len().min(size_of::<StatsBuffer>());
        buffer.as_mut_bytes()[..len].copy_from_slice(&payload[..len]);
        Ok(Self {
            rx_packets: buffer.rx_packets,
            tx_packets: buffer.tx_packets,
            rx_bytes: buffer.rx_bytes,
            tx_bytes: buffer.tx_bytes,
            rx_errors: buffer.rx_errors,
            tx_errors: buffer.tx_errors,
            rx_dropped: buffer.rx_dropped,
            tx_dropped: buffer.tx_dropped,
            multicast: buffer.multicast,
            collisions: buffer.collisions,
            rx_length_errors: buffer.rx_length_errors,
            rx_over_errors: buffer.rx_over_errors,
            rx_crc_errors: buffer.rx_crc_errors,
            rx_frame_errors: buffer.rx_frame_errors,
            rx_fifo_errors: buffer.rx_fifo_errors,
            rx_missed_errors: buffer.rx_missed_errors,
            tx_aborted_errors: buffer.tx_aborted_errors,
            tx_carrier_errors: buffer.tx_carrier_errors,
            tx_fifo_errors: buffer.tx_fifo_errors,
            tx_heartbeat_errors: buffer.tx_heartbeat_errors,
            tx_window_errors: buffer.tx_window_errors,
            rx_compressed: buffer.rx_compressed,
            tx_compressed: buffer.tx_compressed,
            rx_nohandler: buffer.rx_nohandler,
        })
    }
}

impl From<&Stats> for StatsBuffer {
    fn from(value: &Stats) -> Self {
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
            collisions: value.collisions,
            rx_length_errors: value.rx_length_errors,
            rx_over_errors: value.rx_over_errors,
            rx_crc_errors: value.rx_crc_errors,
            rx_frame_errors: value.rx_frame_errors,
            rx_fifo_errors: value.rx_fifo_errors,
            rx_missed_errors: value.rx_missed_errors,
            tx_aborted_errors: value.tx_aborted_errors,
            tx_carrier_errors: value.tx_carrier_errors,
            tx_fifo_errors: value.tx_fifo_errors,
            tx_heartbeat_errors: value.tx_heartbeat_errors,
            tx_window_errors: value.tx_window_errors,
            rx_compressed: value.rx_compressed,
            tx_compressed: value.tx_compressed,
            rx_nohandler: value.rx_nohandler,
        }
    }
}

impl Emitable for Stats {
    fn buffer_len(&self) -> usize {
        size_of::<StatsBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = StatsBuffer::from(self);
        buffer.copy_from_slice(raw.as_bytes());
    }
}
