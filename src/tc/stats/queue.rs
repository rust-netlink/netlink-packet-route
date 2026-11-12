// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Queuing statistics
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcStatsQueue {
    /// queue length
    pub qlen: u32,
    /// backlog size of queue
    pub backlog: u32,
    /// number of dropped packets
    pub drops: u32,
    /// number of requeues
    pub requeues: u32,
    /// number of enqueues over the limit
    pub overlimits: u32,
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
pub(crate) struct TcStatsQueueBuffer {
    qlen: u32,
    backlog: u32,
    drops: u32,
    requeues: u32,
    overlimits: u32,
}

impl TcStatsQueue {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcStatsQueueBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcStatsQueueBuffer>(),
                )
            })?;
        Ok(Self {
            qlen: raw.qlen,
            backlog: raw.backlog,
            drops: raw.drops,
            requeues: raw.requeues,
            overlimits: raw.overlimits,
        })
    }
}

impl From<&TcStatsQueue> for TcStatsQueueBuffer {
    fn from(value: &TcStatsQueue) -> Self {
        Self {
            qlen: value.qlen,
            backlog: value.backlog,
            drops: value.drops,
            requeues: value.requeues,
            overlimits: value.overlimits,
        }
    }
}

impl Emitable for TcStatsQueue {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TcStatsQueueBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
