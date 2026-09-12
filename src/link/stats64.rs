// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned,
};

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
pub struct Stats64Buffer {
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    multicast: u64,
    collisions: u64,
    rx_length_errors: u64,
    rx_over_errors: u64,
    rx_crc_errors: u64,
    rx_frame_errors: u64,
    rx_fifo_errors: u64,
    rx_missed_errors: u64,
    tx_aborted_errors: u64,
    tx_carrier_errors: u64,
    tx_fifo_errors: u64,
    tx_heartbeat_errors: u64,
    tx_window_errors: u64,
    rx_compressed: u64,
    tx_compressed: u64,
    rx_nohandler: u64,
    rx_otherhost_dropped: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
#[non_exhaustive]
pub struct Stats64 {
    /// total packets received
    pub rx_packets: u64,
    /// total packets transmitted
    pub tx_packets: u64,
    /// total bytes received
    pub rx_bytes: u64,
    /// total bytes transmitted
    pub tx_bytes: u64,
    /// bad packets received
    pub rx_errors: u64,
    /// packet transmit problems
    pub tx_errors: u64,
    /// no space in linux buffers
    pub rx_dropped: u64,
    /// no space available in linux
    pub tx_dropped: u64,
    /// multicast packets received
    pub multicast: u64,
    pub collisions: u64,

    // detailed rx_errors
    pub rx_length_errors: u64,
    /// receiver ring buff overflow
    pub rx_over_errors: u64,
    /// received packets with crc error
    pub rx_crc_errors: u64,
    /// received frame alignment errors
    pub rx_frame_errors: u64,
    /// recv'r fifo overrun
    pub rx_fifo_errors: u64,
    /// receiver missed packet
    pub rx_missed_errors: u64,

    // detailed tx_errors
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,

    // for cslip etc
    pub rx_compressed: u64,
    pub tx_compressed: u64,

    /// dropped, no handler found
    pub rx_nohandler: u64,

    pub rx_otherhost_dropped: u64,
}

impl Stats64 {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        // The payload length is the size of `struct rtnl_link_stats64` of
        // the kernel which sent the message: kernels older than 6.9 do not
        // have the `rx_otherhost_dropped` field and send a payload shorter
        // than `Stats64Buffer`. Zero fill the missing trailing fields like
        // iproute2 does in `get_rtnl_link_stats_rta()`, instead of failing
        // the whole message decoding.
        let mut buffer = Stats64Buffer::new_zeroed();
        let len = payload.len().min(size_of::<Stats64Buffer>());
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
            rx_otherhost_dropped: buffer.rx_otherhost_dropped,
        })
    }
}

impl From<&Stats64> for Stats64Buffer {
    fn from(value: &Stats64) -> Self {
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
            rx_otherhost_dropped: value.rx_otherhost_dropped,
        }
    }
}

impl Emitable for Stats64 {
    fn buffer_len(&self) -> usize {
        size_of::<Stats64Buffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = Stats64Buffer::from(self);
        buffer.copy_from_slice(raw.as_bytes());
    }
}
