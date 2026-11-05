// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u64, parse_u64, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_VF_STATS_RX_PACKETS: u16 = 0;
const IFLA_VF_STATS_TX_PACKETS: u16 = 1;
const IFLA_VF_STATS_RX_BYTES: u16 = 2;
const IFLA_VF_STATS_TX_BYTES: u16 = 3;
const IFLA_VF_STATS_BROADCAST: u16 = 4;
const IFLA_VF_STATS_MULTICAST: u16 = 5;
// const IFLA_VF_STATS_PAD: u16 = 6;
const IFLA_VF_STATS_RX_DROPPED: u16 = 7;
const IFLA_VF_STATS_TX_DROPPED: u16 = 8;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum VfStats {
    RxPackets(u64),
    TxPackets(u64),
    RxBytes(u64),
    TxBytes(u64),
    Broadcast(u64),
    Multicast(u64),
    RxDropped(u64),
    TxDropped(u64),
    Other(DefaultNla),
}

impl Nla for VfStats {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::RxPackets(v)
            | Self::TxPackets(v)
            | Self::RxBytes(v)
            | Self::TxBytes(v)
            | Self::Broadcast(v)
            | Self::Multicast(v)
            | Self::RxDropped(v)
            | Self::TxDropped(v) => append_u64(out, *v),
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <VfStats>::kind(self)
    }
}

impl VfStats {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::RxPackets(_) => IFLA_VF_STATS_RX_PACKETS,
            Self::TxPackets(_) => IFLA_VF_STATS_TX_PACKETS,
            Self::RxBytes(_) => IFLA_VF_STATS_RX_BYTES,
            Self::TxBytes(_) => IFLA_VF_STATS_TX_BYTES,
            Self::Broadcast(_) => IFLA_VF_STATS_BROADCAST,
            Self::Multicast(_) => IFLA_VF_STATS_MULTICAST,
            Self::RxDropped(_) => IFLA_VF_STATS_RX_DROPPED,
            Self::TxDropped(_) => IFLA_VF_STATS_TX_DROPPED,
            Self::Other(v) => v.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for VfStats {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VF_STATS_RX_PACKETS => {
                Self::RxPackets(parse_u64(payload).with_context(|| {
                    format!(
                        "invalid IFLA_VF_STATS_RX_PACKETS value {payload:?}"
                    )
                })?)
            }
            IFLA_VF_STATS_TX_PACKETS => {
                Self::TxPackets(parse_u64(payload).with_context(|| {
                    format!(
                        "invalid IFLA_VF_STATS_TX_PACKETS value {payload:?}"
                    )
                })?)
            }
            IFLA_VF_STATS_RX_BYTES => {
                Self::RxBytes(parse_u64(payload).with_context(|| {
                    format!("invalid IFLA_VF_STATS_RX_BYTES value {payload:?}")
                })?)
            }
            IFLA_VF_STATS_TX_BYTES => {
                Self::TxBytes(parse_u64(payload).with_context(|| {
                    format!("invalid IFLA_VF_STATS_TX_BYTES value {payload:?}")
                })?)
            }
            IFLA_VF_STATS_BROADCAST => {
                Self::Broadcast(parse_u64(payload).with_context(|| {
                    format!("invalid IFLA_VF_STATS_BROADCAST value {payload:?}")
                })?)
            }
            IFLA_VF_STATS_MULTICAST => {
                Self::Multicast(parse_u64(payload).with_context(|| {
                    format!("invalid IFLA_VF_STATS_MULTICAST value {payload:?}")
                })?)
            }
            IFLA_VF_STATS_RX_DROPPED => {
                Self::RxDropped(parse_u64(payload).with_context(|| {
                    format!(
                        "invalid IFLA_VF_STATS_RX_DROPPED value {payload:?}"
                    )
                })?)
            }
            IFLA_VF_STATS_TX_DROPPED => {
                Self::TxDropped(parse_u64(payload).with_context(|| {
                    format!(
                        "invalid IFLA_VF_STATS_TX_DROPPED value {payload:?}"
                    )
                })?)
            }
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("failed to parse {kind} as DefaultNla: {payload:?}")
            })?),
        })
    }
}
