// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, Parseable,
};

use crate::buffer_freebsd::FreeBSDBuffer;

// Can offload checksum on RX
const IFCAP_RXCSUM: u32 = 1 << 0;
// Can offload checksum on TX
const IFCAP_TXCSUM: u32 = 1 << 1;
// Can be a network console
const IFCAP_NETCONS: u32 = 1 << 2;
// VLAN-compatible MTU
const IFCAP_VLAN_MTU: u32 = 1 << 3;
// Hardware VLAN tag support
const IFCAP_VLAN_HWTAGGING: u32 = 1 << 4;
// 9000 byte MTU supported
const IFCAP_JUMBO_MTU: u32 = 1 << 5;
// Driver supports polling
const IFCAP_POLLING: u32 = 1 << 6;
// Can do IFCAP_HWCSUM on VLANs
const IFCAP_VLAN_HWCSUM: u32 = 1 << 7;
// Can do TCP Segmentation Offload
const IFCAP_TSO4: u32 = 1 << 8;
// Can do TCP6 Segmentation Offload
const IFCAP_TSO6: u32 = 1 << 9;
// Can do Large Receive Offload
const IFCAP_LRO: u32 = 1 << 10;
// Wake on any unicast frame
const IFCAP_WOL_UCAST: u32 = 1 << 11;
// Wake on any multicast frame
const IFCAP_WOL_MCAST: u32 = 1 << 12;
// Wake on any Magic Packet
const IFCAP_WOL_MAGIC: u32 = 1 << 13;
// Interface can offload TCP
const IFCAP_TOE4: u32 = 1 << 14;
// Interface can offload TCP6
const IFCAP_TOE6: u32 = 1 << 15;
// Interface hw can filter vlan tag
const IFCAP_VLAN_HWFILTER: u32 = 1 << 16;
// Can do SIOCGIFCAPNV/SIOCSIFCAPNV
const IFCAP_NV: u32 = 1 << 17;
// Can do IFCAP_TSO on VLANs
const IFCAP_VLAN_HWTSO: u32 = 1 << 18;
// The runtime link state is dynamic
const IFCAP_LINKSTATE: u32 = 1 << 19;
// Netmap mode supported/enabled
const IFCAP_NETMAP: u32 = 1 << 20;
// Can offload checksum on IPv6 RX
const IFCAP_RXCSUM_IPV6: u32 = 1 << 21;
// Can offload checksum on IPv6 TX
const IFCAP_TXCSUM_IPV6: u32 = 1 << 22;
// Manages counters internally
const IFCAP_HWSTATS: u32 = 1 << 23;
// Hardware supports TX rate limiting
const IFCAP_TXRTLMT: u32 = 1 << 24;
// Hardware rx timestamping
const IFCAP_HWRXTSTMP: u32 = 1 << 25;
// Understands M_EXTPG mbufs
const IFCAP_MEXTPG: u32 = 1 << 26;
// Can do TLS encryption and segmentation for TCP
const IFCAP_TXTLS4: u32 = 1 << 27;
// Can do TLS encryption and segmentation for TCP6
const IFCAP_TXTLS6: u32 = 1 << 28;
// Can do IFCAN_HWCSUM on VXLANs
const IFCAP_VXLAN_HWCSUM: u32 = 1 << 29;
// Can do IFCAP_TSO on VXLANs
const IFCAP_VXLAN_HWTSO: u32 = 1 << 30;
// Can do TLS with rate limiting
const IFCAP_TXTLS_RTLMT: u32 = 1 << 31;

// Can to TLS receive for TCP
const IFCAP2_RXTLS4: u32 = 1 << 0;
// Can to TLS receive for TCP6
const IFCAP2_RXTLS6: u32 = 1 << 1;
// Inline IPSEC offload
const IFCAP2_IPSEC_OFFLOAD: u32 = 1 << 2;

// const IFLAF_ORIG_IFNAME: u16 = 1; // Unused
const IFLAF_ORIG_HWADDR: u16 = 2;
const IFLAF_CAPS: u16 = 3;

const NLA_BITSET_SIZE: u16 = 2;
// const NLA_BITSET_BITS: u16 = 3; // Unused
const NLA_BITSET_VALUE: u16 = 4;
const NLA_BITSET_MASK: u16 = 5;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct IfCaps {
    pub cap_bit_size: u32,
    pub supported_caps: (IfCapFlags, IfCap2Flags),
    pub active_caps: (IfCapFlags, IfCap2Flags),
}

impl Nla for IfCaps {
    fn value_len(&self) -> usize {
        32
    }

    fn kind(&self) -> u16 {
        IFLAF_CAPS
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut buffer = FreeBSDBuffer::new(buffer);
        let (caps1_idx, caps2_idx) = if cfg!(target_endian = "little") {
            (0..4, 4..8)
        } else {
            (4..8, 0..4)
        };

        // Bitset size
        {
            buffer.set_length(8);
            buffer.set_value_type(NLA_BITSET_SIZE);
            buffer.value_mut()[..4]
                .copy_from_slice(&self.cap_bit_size.to_ne_bytes());
            buffer = FreeBSDBuffer::new(&mut buffer.into_inner()[8..]);
        }

        // Supported capabilities
        {
            buffer.set_length(12);
            buffer.set_value_type(NLA_BITSET_MASK);
            buffer.value_mut()[caps1_idx.clone()]
                .copy_from_slice(&self.supported_caps.0.bits().to_ne_bytes());
            buffer.value_mut()[caps2_idx.clone()]
                .copy_from_slice(&self.supported_caps.1.bits().to_ne_bytes());
            buffer = FreeBSDBuffer::new(&mut buffer.into_inner()[12..]);
        }

        // Active capabilities
        {
            buffer.set_length(12);
            buffer.set_value_type(NLA_BITSET_VALUE);
            buffer.value_mut()[caps1_idx]
                .copy_from_slice(&self.active_caps.0.bits().to_ne_bytes());
            buffer.value_mut()[caps2_idx]
                .copy_from_slice(&self.active_caps.1.bits().to_ne_bytes());
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FreeBsdLinkAttribute {
    // OrigIfName(String), // Unused
    OrigHwAddr([u8; 6]),
    IfCaps(IfCaps),
    Other(DefaultNla),
}

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IfCapFlags : u32 {
        const RxCsum = IFCAP_RXCSUM;
        const TxCsum = IFCAP_TXCSUM;
        const Netcons = IFCAP_NETCONS;
        const VlanMtu = IFCAP_VLAN_MTU;
        const VlanHwtagging = IFCAP_VLAN_HWTAGGING;
        const JumboMtu = IFCAP_JUMBO_MTU;
        const Polling = IFCAP_POLLING;
        const VlanHwCsum = IFCAP_VLAN_HWCSUM;
        const Tso4 = IFCAP_TSO4;
        const Tso6 = IFCAP_TSO6;
        const Lro = IFCAP_LRO;
        const WolUcast = IFCAP_WOL_UCAST;
        const WolMcast = IFCAP_WOL_MCAST;
        const WolMagic = IFCAP_WOL_MAGIC;
        const Toe4 = IFCAP_TOE4;
        const Toe6 = IFCAP_TOE6;
        const VlanHwFilter = IFCAP_VLAN_HWFILTER;
        const Nv = IFCAP_NV;
        const VlanHwTso = IFCAP_VLAN_HWTSO;
        const Linkstate = IFCAP_LINKSTATE;
        const Netmap = IFCAP_NETMAP;
        const RxCsumIpv6 = IFCAP_RXCSUM_IPV6;
        const TxCsumIpv6 = IFCAP_TXCSUM_IPV6;
        const Hwstats = IFCAP_HWSTATS;
        const TxRtlmt = IFCAP_TXRTLMT;
        const HwRxTstmp = IFCAP_HWRXTSTMP;
        const Mextpg = IFCAP_MEXTPG;
        const TxTls4 = IFCAP_TXTLS4;
        const TxTls6 = IFCAP_TXTLS6;
        const VxlanHwCsum = IFCAP_VXLAN_HWCSUM;
        const VxlanHwTso = IFCAP_VXLAN_HWTSO;
        const TxTlsRtlmt = IFCAP_TXTLS_RTLMT;
        const _ = !0;
    }
}

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IfCap2Flags : u32 {
        const RxTls4 = IFCAP2_RXTLS4;
        const RxTls6 = IFCAP2_RXTLS6;
        const IpsecOffload = IFCAP2_IPSEC_OFFLOAD;
        const _ = !0;
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<FreeBSDBuffer<&'buffer T>>
    for FreeBsdLinkAttribute
{
    fn parse(buf: &FreeBSDBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        if buf.inner().len() < buf.length() as usize {
            return Err(DecodeError::from(
                "Buffer length is smaller than indicated length",
            ));
        }

        match buf.value_type() {
            IFLAF_ORIG_HWADDR => {
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&buf.value()[..6]);
                Ok(FreeBsdLinkAttribute::OrigHwAddr(addr))
            }
            IFLAF_CAPS => {
                // Nested bitset attribute
                let mut bitset_size = None;
                let mut supported_caps = None;
                let mut active_caps = None;
                let mut nested_buf = FreeBSDBuffer::new(buf.value());
                while !nested_buf.inner().is_empty() {
                    match nested_buf.value_type() {
                        NLA_BITSET_SIZE => {
                            if nested_buf.length() != 8 {
                                return Err(DecodeError::from(
                                    "Invalid length for IFLA_CAPS bitset size",
                                ));
                            }

                            bitset_size = Some(
                                parse_u32(&nested_buf.value()[..4]).context(
                                    "failed to parse IFLA_CAPS bitset size",
                                )?,
                            );

                            nested_buf =
                                FreeBSDBuffer::new(&nested_buf.inner()[8..]);
                        }
                        v if v == NLA_BITSET_VALUE || v == NLA_BITSET_MASK => {
                            // in `sys/netlink/route/iface.c`, `dump_iface_caps`
                            let (caps_name, caps) = if v == NLA_BITSET_VALUE {
                                ("active", &mut active_caps)
                            } else {
                                ("supported", &mut supported_caps)
                            };

                            let (cap1_idx, cap2_idx) =
                                if cfg!(target_endian = "little") {
                                    (0..4, 4..8)
                                } else {
                                    (4..8, 0..4)
                                };

                            if nested_buf.length() != 12 {
                                return Err(DecodeError::from(format!(
                                    "Invalid length for IFLA_CAPS {} \
                                     capabilities",
                                    caps_name
                                )));
                            }

                            let err = format!(
                                "failed to parse IFLA_CAPS {} capabilities",
                                caps_name
                            );
                            let if_cap_flags = IfCapFlags::from_bits(
                                parse_u32(&nested_buf.value()[cap1_idx])
                                    .context(err.as_str())?,
                            )
                            .ok_or_else(|| DecodeError::from(err.as_str()))?;
                            let if_cap2_flags = IfCap2Flags::from_bits(
                                parse_u32(&nested_buf.value()[cap2_idx])
                                    .context(err.as_str())?,
                            )
                            .ok_or_else(|| DecodeError::from(err.as_str()))?;
                            *caps = Some((if_cap_flags, if_cap2_flags));

                            nested_buf =
                                FreeBSDBuffer::new(&nested_buf.inner()[12..]);
                        }
                        _ => {
                            return Err(DecodeError::from(
                                "Unknown IFLA_CAPS attribute type",
                            ));
                        }
                    }
                }

                Ok(FreeBsdLinkAttribute::IfCaps(IfCaps {
                    cap_bit_size: bitset_size.ok_or_else(|| {
                        DecodeError::from("Missing IFLA_CAPS bitset size")
                    })?,
                    supported_caps: supported_caps.ok_or_else(|| {
                        DecodeError::from(
                            "Missing IFLA_CAPS supported capabilities",
                        )
                    })?,
                    active_caps: active_caps.ok_or_else(|| {
                        DecodeError::from(
                            "Missing IFLA_CAPS active capabilities",
                        )
                    })?,
                }))
            }
            t => Ok(FreeBsdLinkAttribute::Other(DefaultNla::new(
                t,
                buf.value().to_vec(),
            ))),
        }
    }
}

impl Nla for FreeBsdLinkAttribute {
    fn kind(&self) -> u16 {
        match self {
            FreeBsdLinkAttribute::OrigHwAddr(_) => IFLAF_ORIG_HWADDR,
            FreeBsdLinkAttribute::IfCaps(caps) => caps.kind(),
            FreeBsdLinkAttribute::Other(nla) => nla.kind(),
        }
    }

    fn value_len(&self) -> usize {
        match self {
            FreeBsdLinkAttribute::OrigHwAddr(_) => 6,
            FreeBsdLinkAttribute::IfCaps(caps) => caps.value_len(),
            FreeBsdLinkAttribute::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            FreeBsdLinkAttribute::OrigHwAddr(addr) => {
                buffer.copy_from_slice(addr);
            }
            FreeBsdLinkAttribute::IfCaps(caps) => {
                caps.emit_value(buffer);
            }
            FreeBsdLinkAttribute::Other(nla) => nla.emit_value(buffer),
        }
    }
}
