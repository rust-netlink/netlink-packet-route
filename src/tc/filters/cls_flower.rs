// SPDX-License-Identifier: MIT
#![deny(clippy::all, clippy::pedantic)]

/// flower filter
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, NativeEndian};
use netlink_packet_utils::nla::{NlasIterator, NLA_F_NESTED};
use netlink_packet_utils::parsers::{
    parse_u16, parse_u16_be, parse_u32_be, parse_u8,
};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32,
    traits::Parseable,
    DecodeError, Emitable,
};

use crate::net::arp;
use crate::net::mpls;
use crate::net::{ethernet, icmpv4, icmpv6};
use crate::tc::filters::flower;
use crate::tc::filters::flower::encap;
use crate::tc::flower::encap::OptionsList;
use crate::tc::{TcAction, TcFlowerOptionFlags, TcHandle};
use crate::{EncKeyId, IpProtocol};

pub(crate) const TCA_FLOWER_CLASSID: u16 = 1;
pub(crate) const TCA_FLOWER_INDEV: u16 = 2;
pub(crate) const TCA_FLOWER_ACT: u16 = 3;
pub(crate) const TCA_FLOWER_KEY_ETH_DST: u16 = 4;
pub(crate) const TCA_FLOWER_KEY_ETH_DST_MASK: u16 = 5;
pub(crate) const TCA_FLOWER_KEY_ETH_SRC: u16 = 6;
pub(crate) const TCA_FLOWER_KEY_ETH_SRC_MASK: u16 = 7;
pub(crate) const TCA_FLOWER_KEY_ETH_TYPE: u16 = 8;
pub(crate) const TCA_FLOWER_KEY_IP_PROTO: u16 = 9;
pub(crate) const TCA_FLOWER_KEY_IPV4_SRC: u16 = 10;
pub(crate) const TCA_FLOWER_KEY_IPV4_SRC_MASK: u16 = 11;
pub(crate) const TCA_FLOWER_KEY_IPV4_DST: u16 = 12;
pub(crate) const TCA_FLOWER_KEY_IPV4_DST_MASK: u16 = 13;
pub(crate) const TCA_FLOWER_KEY_IPV6_SRC: u16 = 14;
pub(crate) const TCA_FLOWER_KEY_IPV6_SRC_MASK: u16 = 15;
pub(crate) const TCA_FLOWER_KEY_IPV6_DST: u16 = 16;
pub(crate) const TCA_FLOWER_KEY_IPV6_DST_MASK: u16 = 17;
pub(crate) const TCA_FLOWER_KEY_TCP_SRC: u16 = 18;
pub(crate) const TCA_FLOWER_KEY_TCP_DST: u16 = 19;
pub(crate) const TCA_FLOWER_KEY_UDP_SRC: u16 = 20;
pub(crate) const TCA_FLOWER_KEY_UDP_DST: u16 = 21;
pub(crate) const TCA_FLOWER_FLAGS: u16 = 22;
pub(crate) const TCA_FLOWER_KEY_VLAN_ID: u16 = 23;
pub(crate) const TCA_FLOWER_KEY_VLAN_PRIO: u16 = 24;
pub(crate) const TCA_FLOWER_KEY_VLAN_ETH_TYPE: u16 = 25;
pub(crate) const TCA_FLOWER_KEY_ENC_KEY_ID: u16 = 26;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV4_SRC: u16 = 27;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK: u16 = 28;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV4_DST: u16 = 29;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV4_DST_MASK: u16 = 30;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV6_SRC: u16 = 31;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK: u16 = 32;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV6_DST: u16 = 33;
pub(crate) const TCA_FLOWER_KEY_ENC_IPV6_DST_MASK: u16 = 34;
pub(crate) const TCA_FLOWER_KEY_TCP_SRC_MASK: u16 = 35;
pub(crate) const TCA_FLOWER_KEY_TCP_DST_MASK: u16 = 36;
pub(crate) const TCA_FLOWER_KEY_UDP_SRC_MASK: u16 = 37;
pub(crate) const TCA_FLOWER_KEY_UDP_DST_MASK: u16 = 38;
pub(crate) const TCA_FLOWER_KEY_SCTP_SRC_MASK: u16 = 39;
pub(crate) const TCA_FLOWER_KEY_SCTP_DST_MASK: u16 = 40;
pub(crate) const TCA_FLOWER_KEY_SCTP_SRC: u16 = 41;
pub(crate) const TCA_FLOWER_KEY_SCTP_DST: u16 = 42;
pub(crate) const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT: u16 = 43;
pub(crate) const TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK: u16 = 44;
pub(crate) const TCA_FLOWER_KEY_ENC_UDP_DST_PORT: u16 = 45;
pub(crate) const TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK: u16 = 46;
pub(crate) const TCA_FLOWER_KEY_FLAGS: u16 = 47;
pub(crate) const TCA_FLOWER_KEY_FLAGS_MASK: u16 = 48;
pub(crate) const TCA_FLOWER_KEY_ICMPV4_CODE: u16 = 49;
pub(crate) const TCA_FLOWER_KEY_ICMPV4_CODE_MASK: u16 = 50;
pub(crate) const TCA_FLOWER_KEY_ICMPV4_TYPE: u16 = 51;
pub(crate) const TCA_FLOWER_KEY_ICMPV4_TYPE_MASK: u16 = 52;
pub(crate) const TCA_FLOWER_KEY_ICMPV6_CODE: u16 = 53;
pub(crate) const TCA_FLOWER_KEY_ICMPV6_CODE_MASK: u16 = 54;
pub(crate) const TCA_FLOWER_KEY_ICMPV6_TYPE: u16 = 55;
pub(crate) const TCA_FLOWER_KEY_ICMPV6_TYPE_MASK: u16 = 56;
pub(crate) const TCA_FLOWER_KEY_ARP_SIP: u16 = 57;
pub(crate) const TCA_FLOWER_KEY_ARP_SIP_MASK: u16 = 58;
pub(crate) const TCA_FLOWER_KEY_ARP_TIP: u16 = 59;
pub(crate) const TCA_FLOWER_KEY_ARP_TIP_MASK: u16 = 60;
pub(crate) const TCA_FLOWER_KEY_ARP_OP: u16 = 61;
pub(crate) const TCA_FLOWER_KEY_ARP_OP_MASK: u16 = 62;
pub(crate) const TCA_FLOWER_KEY_ARP_SHA: u16 = 63;
pub(crate) const TCA_FLOWER_KEY_ARP_SHA_MASK: u16 = 64;
pub(crate) const TCA_FLOWER_KEY_ARP_THA: u16 = 65;
pub(crate) const TCA_FLOWER_KEY_ARP_THA_MASK: u16 = 66;
pub(crate) const TCA_FLOWER_KEY_MPLS_TTL: u16 = 67;
pub(crate) const TCA_FLOWER_KEY_MPLS_BOS: u16 = 68;
pub(crate) const TCA_FLOWER_KEY_MPLS_TC: u16 = 69;
pub(crate) const TCA_FLOWER_KEY_MPLS_LABEL: u16 = 70;
pub(crate) const TCA_FLOWER_KEY_TCP_FLAGS: u16 = 71;
pub(crate) const TCA_FLOWER_KEY_TCP_FLAGS_MASK: u16 = 72;
pub(crate) const TCA_FLOWER_KEY_IP_TOS: u16 = 73;
pub(crate) const TCA_FLOWER_KEY_IP_TOS_MASK: u16 = 74;
pub(crate) const TCA_FLOWER_KEY_IP_TTL: u16 = 75;
pub(crate) const TCA_FLOWER_KEY_IP_TTL_MASK: u16 = 76;
pub(crate) const TCA_FLOWER_KEY_CVLAN_ID: u16 = 77;
pub(crate) const TCA_FLOWER_KEY_CVLAN_PRIO: u16 = 78;
pub(crate) const TCA_FLOWER_KEY_CVLAN_ETH_TYPE: u16 = 79;
pub(crate) const TCA_FLOWER_KEY_ENC_IP_TOS: u16 = 80;
pub(crate) const TCA_FLOWER_KEY_ENC_IP_TOS_MASK: u16 = 81;
pub(crate) const TCA_FLOWER_KEY_ENC_IP_TTL: u16 = 82;
pub(crate) const TCA_FLOWER_KEY_ENC_IP_TTL_MASK: u16 = 83;
pub(crate) const TCA_FLOWER_KEY_ENC_OPTS: u16 = 84;
pub(crate) const TCA_FLOWER_KEY_ENC_OPTS_MASK: u16 = 85;
pub(crate) const TCA_FLOWER_IN_HW_COUNT: u16 = 86;
pub(crate) const TCA_FLOWER_KEY_PORT_SRC_MIN: u16 = 87;
pub(crate) const TCA_FLOWER_KEY_PORT_SRC_MAX: u16 = 88;
pub(crate) const TCA_FLOWER_KEY_PORT_DST_MIN: u16 = 89;
pub(crate) const TCA_FLOWER_KEY_PORT_DST_MAX: u16 = 90;
pub(crate) const TCA_FLOWER_KEY_CT_STATE: u16 = 91;
pub(crate) const TCA_FLOWER_KEY_CT_STATE_MASK: u16 = 92;
pub(crate) const TCA_FLOWER_KEY_CT_ZONE: u16 = 93;
pub(crate) const TCA_FLOWER_KEY_CT_ZONE_MASK: u16 = 94;
pub(crate) const TCA_FLOWER_KEY_CT_MARK: u16 = 95;
pub(crate) const TCA_FLOWER_KEY_CT_MARK_MASK: u16 = 96;
pub(crate) const TCA_FLOWER_KEY_CT_LABELS: u16 = 97;
pub(crate) const TCA_FLOWER_KEY_CT_LABELS_MASK: u16 = 98;
pub(crate) const TCA_FLOWER_KEY_MPLS_OPTS: u16 = 99;
pub(crate) const TCA_FLOWER_KEY_HASH: u16 = 100;
pub(crate) const TCA_FLOWER_KEY_HASH_MASK: u16 = 101;
pub(crate) const TCA_FLOWER_KEY_NUM_OF_VLANS: u16 = 102;
pub(crate) const TCA_FLOWER_KEY_PPPOE_SID: u16 = 103;
pub(crate) const TCA_FLOWER_KEY_PPP_PROTO: u16 = 104;
pub(crate) const TCA_FLOWER_KEY_L2TPV3_SID: u16 = 105;
pub(crate) const TCA_FLOWER_L2_MISS: u16 = 106;
pub(crate) const TCA_FLOWER_KEY_CFM: u16 = 107;
pub(crate) const TCA_FLOWER_KEY_SPI: u16 = 108;
pub(crate) const TCA_FLOWER_KEY_SPI_MASK: u16 = 109;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcFilterFlower {}

impl TcFilterFlower {
    pub const KIND: &'static str = "flower";
}

/// I can't figure out a better type than just `u8` for `CfmOpCode`.
/// The only reserved values and meanings I was able to find were in
/// [rfc7319][1], and that only specifies that values 64-95 are expressly
/// _unassigned_.
/// The only other useful source I was able to find was [an IEEE slideshow][2]
/// Which asserts that about 18 PDU types are defined, but does not list them.
/// The official spec of interest would be [IEEE 802.1ag][3], but the spec
/// is currently behind a paywall.
///
/// TODO: discuss if it is better to leave this as a u8, or to make an enum
/// with a single type of `Other(u8)`.
/// I assume simply `u8` is the best choice because it will be an API break
/// either way if we ever find some better answers.
///
/// [0]: https://datatracker.ietf.org/doc/html/rfc7319
/// [1]: https://www.ieee802.org/1/files/public/docs2021/60802-finn-intro-to-CFM-0721-v01.pdf
/// [2]: https://www.ieee802.org/1/pages/802.1ag.html
pub type CfmOpCode = u8;

bitflags! {
    // TcpFlags _ARE_ exactly 8 bits.
    // Why flower uses a 16-bit field is a mystery, but we deal with it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TcpFlags : u8 {
        const Cwr = 1 << 0;
        const Ece = 1 << 1;
        const Urg = 1 << 2;
        const Ack = 1 << 3;
        const Psh = 1 << 4;
        const Rst = 1 << 5;
        const Syn = 1 << 6;
        const Fin = 1 << 7;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcFilterFlowerOption {
    ClassId(TcHandle),
    Indev(Vec<u8>), /* TODO: try to establish some bounds on this. Vec<u8>
                     * is kinda crazy. */
    Action(Vec<TcAction>),
    KeyEthDst(ethernet::Mac),
    KeyEthDstMask(ethernet::MacMask),
    KeyEthSrc(ethernet::Mac),
    KeyEthSrcMask(ethernet::MacMask),
    KeyEthType(ethernet::Ethertype),
    KeyIpProto(IpProtocol),
    KeyIpv4Src(Ipv4Addr),
    KeyIpv4SrcMask(Ipv4Addr),
    KeyIpv4Dst(Ipv4Addr),
    KeyIpv4DstMask(Ipv4Addr),
    KeyIpv6Src(Ipv6Addr),
    KeyIpv6SrcMask(Ipv6Addr),
    KeyIpv6Dst(Ipv6Addr),
    KeyIpv6DstMask(Ipv6Addr),
    KeyTcpSrc(u16),
    KeyTcpDst(u16),
    KeyUdpSrc(u16),
    KeyUdpDst(u16),
    Flags(TcFlowerOptionFlags),
    Other(DefaultNla),
    KeyVlanId(ethernet::VlanId),
    KeyVlanPrio(ethernet::VlanPrio),
    KeyVlanEthType(ethernet::Ethertype),
    KeyEncKeyId(EncKeyId),
    KeyEncIpv4Src(Ipv4Addr),
    KeyEncIpv4SrcMask(Ipv4Addr),
    KeyEncIpv4Dst(Ipv4Addr),
    KeyEncIpv4DstMask(Ipv4Addr),
    KeyEncIpv6Src(Ipv6Addr),
    KeyEncIpv6SrcMask(Ipv6Addr),
    KeyEncIpv6Dst(Ipv6Addr),
    KeyEncIpv6DstMask(Ipv6Addr),
    KeyTcpSrcMask(u16),
    KeyTcpDstMask(u16),
    KeyUdpSrcMask(u16),
    KeyUdpDstMask(u16),
    KeySctpSrcMask(u16),
    KeySctpDstMask(u16),
    KeySctpSrc(u16),
    KeySctpDst(u16),
    KeyEncUdpSrcPort(u16),
    KeyEncUdpSrcPortMask(u16),
    KeyEncUdpDstPort(u16),
    KeyEncUdpDstPortMask(u16),
    KeyFlags(flower::Flags),
    KeyFlagsMask(flower::Flags),
    KeyIcmpv4Code(icmpv4::Code),
    KeyIcmpv4CodeMask(u8),
    KeyIcmpv4Type(icmpv4::Type),
    KeyIcmpv4TypeMask(u8),
    KeyIcmpv6Code(icmpv6::Code),
    KeyIcmpv6CodeMask(u8),
    KeyIcmpv6Type(icmpv6::Type),
    KeyIcmpv6TypeMask(u8),
    KeyArpSip(Ipv4Addr),
    KeyArpSipMask(Ipv4Addr),
    KeyArpTip(Ipv4Addr),
    KeyArpTipMask(Ipv4Addr),
    KeyArpOp(arp::Operation),
    KeyArpOpMask(u8),
    KeyArpSha(ethernet::Mac),
    KeyArpShaMask(ethernet::Mac),
    KeyArpTha(ethernet::Mac),
    KeyArpThaMask(ethernet::Mac),
    KeyMplsTtl(u8),
    KeyMplsBos(mpls::BottomOfStack),
    KeyMplsTc(u8),
    KeyMplsLabel(mpls::Label),
    KeyTcpFlags(TcpFlags),
    KeyTcpFlagsMask(u8),
    KeyIpTos(u8),
    KeyIpTosMask(u8),
    KeyIpTtl(u8),
    KeyIpTtlMask(u8),
    KeyCvlanId(ethernet::VlanId),
    KeyCvlanPrio(ethernet::VlanPrio),
    KeyCvlanEthType(ethernet::Ethertype),
    KeyEncIpTos(u8),
    KeyEncIpTosMask(u8),
    KeyEncIpTtl(u8),
    KeyEncIpTtlMask(u8),
    KeyEncOpts(encap::OptionsList),
    KeyEncOptsMask(encap::OptionsList),
    KeyPortSrcMin(u16),
    KeyPortSrcMax(u16),
    KeyPortDstMin(u16),
    KeyPortDstMax(u16),
    KeyCtState(ConnectionTrackingFlags),
    KeyCtStateMask(ConnectionTrackingFlags),
    KeyCtZone(u16),
    KeyCtZoneMask(u16),
    KeyCtMark(u32),
    KeyCtMarkMask(u32),
    KeyCtLabels(u128),
    KeyCtLabelsMask(u128),
    KeyMplsOpts(flower::mpls::Options),
    KeyHash(u32),
    KeyHashMask(u32),
    KeyNumOfVlans(u8),
    KeyPppoeSid(u16),
    KeyPppProto(u16),
    KeyL2tpv3Sid(u32),
    L2Miss(L2Miss),
    KeyCfm(Vec<CfmAttribute>),
    KeySpi(u32),
    KeySpiMask(u32),
    InHwCount(u32),
}

impl Nla for TcFilterFlowerOption {
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn value_len(&self) -> usize {
        match self {
            Self::ClassId(_) => 4,
            Self::Indev(b) => b.len(),
            Self::Action(acts) => acts.as_slice().buffer_len(),
            Self::KeyEthDst(k) => k.as_ref().as_slice().len(),
            Self::KeyEthDstMask(k) => k.as_ref().as_slice().len(),
            Self::KeyEthSrc(k) => k.as_ref().as_slice().len(),
            Self::KeyEthSrcMask(k) => k.as_ref().as_slice().len(),
            Self::KeyEthType(_) => 2,
            Self::KeyIpProto(_) => 1,
            Self::KeyIpv4Src(_) => 4,
            Self::KeyIpv4SrcMask(_) => 4,
            Self::KeyIpv4Dst(_) => 4,
            Self::KeyIpv4DstMask(_) => 4,
            Self::KeyIpv6Src(_) => 16,
            Self::KeyIpv6SrcMask(_) => 16,
            Self::KeyIpv6Dst(_) => 16,
            Self::KeyIpv6DstMask(_) => 16,
            Self::KeyTcpSrc(_) => 2,
            Self::KeyTcpDst(_) => 2,
            Self::KeyUdpSrc(_) => 2,
            Self::KeyUdpDst(_) => 2,
            Self::Flags(_) => 4,
            Self::KeyVlanId(_) => 2,
            Self::KeyVlanPrio(_) => 1,
            Self::KeyVlanEthType(_) => 2,
            Self::KeyEncKeyId(_) => 4,
            Self::KeyEncIpv4Src(_) => 4,
            Self::KeyEncIpv4SrcMask(_) => 4,
            Self::KeyEncIpv4Dst(_) => 4,
            Self::KeyEncIpv4DstMask(_) => 4,
            Self::KeyEncIpv6Src(_) => 16,
            Self::KeyEncIpv6SrcMask(_) => 16,
            Self::KeyEncIpv6Dst(_) => 16,
            Self::KeyEncIpv6DstMask(_) => 16,
            Self::KeyTcpSrcMask(_) => 2,
            Self::KeyTcpDstMask(_) => 2,
            Self::KeyUdpSrcMask(_) => 2,
            Self::KeyUdpDstMask(_) => 2,
            Self::KeySctpSrcMask(_) => 2,
            Self::KeySctpDstMask(_) => 2,
            Self::KeySctpSrc(_) => 2,
            Self::KeySctpDst(_) => 2,
            Self::KeyEncUdpSrcPort(_) => 2,
            Self::KeyEncUdpSrcPortMask(_) => 2,
            Self::KeyEncUdpDstPort(_) => 2,
            Self::KeyEncUdpDstPortMask(_) => 2,
            Self::KeyFlags(_) => 4,
            Self::KeyFlagsMask(_) => 4,
            Self::KeyIcmpv4Code(_) => 1,
            Self::KeyIcmpv4CodeMask(_) => 1,
            Self::KeyIcmpv4Type(_) => 1,
            Self::KeyIcmpv4TypeMask(_) => 1,
            Self::KeyIcmpv6Code(_) => 1,
            Self::KeyIcmpv6CodeMask(_) => 1,
            Self::KeyIcmpv6Type(_) => 1,
            Self::KeyIcmpv6TypeMask(_) => 1,
            Self::KeyArpSip(_) => 4,
            Self::KeyArpSipMask(_) => 4,
            Self::KeyArpTip(_) => 4,
            Self::KeyArpTipMask(_) => 4,
            Self::KeyArpOp(_) => 1,
            Self::KeyArpOpMask(_) => 1,
            Self::KeyArpSha(_) => 6,
            Self::KeyArpShaMask(_) => 6,
            Self::KeyArpTha(_) => 6,
            Self::KeyArpThaMask(_) => 6,
            Self::KeyMplsTtl(_) => 1,
            Self::KeyMplsBos(_) => 1,
            Self::KeyMplsTc(_) => 1,
            Self::KeyMplsLabel(_) => 4,
            Self::KeyTcpFlags(_) => 2,
            Self::KeyTcpFlagsMask(_) => 2,
            Self::KeyIpTos(_) => 1,
            Self::KeyIpTosMask(_) => 1,
            Self::KeyIpTtl(_) => 1,
            Self::KeyIpTtlMask(_) => 1,
            Self::KeyCvlanId(_) => 2,
            Self::KeyCvlanPrio(_) => 1,
            Self::KeyCvlanEthType(_) => 2,
            Self::KeyEncIpTos(_) => 1,
            Self::KeyEncIpTosMask(_) => 1,
            Self::KeyEncIpTtl(_) => 1,
            Self::KeyEncIpTtlMask(_) => 1,
            Self::KeyEncOpts(opts) => opts.value_len(),
            Self::KeyEncOptsMask(opts) => opts.value_len(),
            Self::InHwCount(_) => 4,
            Self::KeyPortSrcMin(_) => 2,
            Self::KeyPortSrcMax(_) => 2,
            Self::KeyPortDstMin(_) => 2,
            Self::KeyPortDstMax(_) => 2,
            Self::KeyCtState(_) => 2,
            Self::KeyCtStateMask(_) => 2,
            Self::KeyCtZone(_) => 2,
            Self::KeyCtZoneMask(_) => 2,
            Self::KeyCtMark(_) => 4,
            Self::KeyCtMarkMask(_) => 4,
            Self::KeyCtLabels(_) => 16,
            Self::KeyCtLabelsMask(_) => 16,
            Self::KeyMplsOpts(opts) => opts.value_len(),
            Self::KeyHash(_) => 4,
            Self::KeyHashMask(_) => 4,
            Self::KeyNumOfVlans(_) => 1,
            Self::KeyPppoeSid(_) => 2,
            Self::KeyPppProto(_) => 2,
            Self::KeyL2tpv3Sid(_) => 4,
            Self::L2Miss(_) => 1,
            Self::KeyCfm(cfm) => cfm.as_slice().buffer_len(),
            Self::KeySpi(_) => 4,
            Self::KeySpiMask(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn kind(&self) -> u16 {
        match self {
            Self::ClassId(_) => TCA_FLOWER_CLASSID,
            Self::Indev(_) => TCA_FLOWER_INDEV,
            Self::Action(_) => TCA_FLOWER_ACT,
            Self::KeyEthDst(_) => TCA_FLOWER_KEY_ETH_DST,
            Self::KeyEthDstMask(_) => TCA_FLOWER_KEY_ETH_DST_MASK,
            Self::KeyEthSrc(_) => TCA_FLOWER_KEY_ETH_SRC,
            Self::KeyEthSrcMask(_) => TCA_FLOWER_KEY_ETH_SRC_MASK,
            Self::KeyEthType(_) => TCA_FLOWER_KEY_ETH_TYPE,
            Self::KeyIpProto(_) => TCA_FLOWER_KEY_IP_PROTO,
            Self::KeyIpv4Src(_) => TCA_FLOWER_KEY_IPV4_SRC,
            Self::KeyIpv4SrcMask(_) => TCA_FLOWER_KEY_IPV4_SRC_MASK,
            Self::KeyIpv4Dst(_) => TCA_FLOWER_KEY_IPV4_DST,
            Self::KeyIpv4DstMask(_) => TCA_FLOWER_KEY_IPV4_DST_MASK,
            Self::KeyIpv6Src(_) => TCA_FLOWER_KEY_IPV6_SRC,
            Self::KeyIpv6SrcMask(_) => TCA_FLOWER_KEY_IPV6_SRC_MASK,
            Self::KeyIpv6Dst(_) => TCA_FLOWER_KEY_IPV6_DST,
            Self::KeyIpv6DstMask(_) => TCA_FLOWER_KEY_IPV6_DST_MASK,
            Self::KeyTcpSrc(_) => TCA_FLOWER_KEY_TCP_SRC,
            Self::KeyTcpDst(_) => TCA_FLOWER_KEY_TCP_DST,
            Self::KeyUdpSrc(_) => TCA_FLOWER_KEY_UDP_SRC,
            Self::KeyUdpDst(_) => TCA_FLOWER_KEY_UDP_DST,
            Self::Flags(_) => TCA_FLOWER_FLAGS,
            Self::KeyVlanId(_) => TCA_FLOWER_KEY_VLAN_ID,
            Self::KeyVlanPrio(_) => TCA_FLOWER_KEY_VLAN_PRIO,
            Self::KeyVlanEthType(_) => TCA_FLOWER_KEY_VLAN_ETH_TYPE,
            Self::KeyEncKeyId(_) => TCA_FLOWER_KEY_ENC_KEY_ID,
            Self::KeyEncIpv4Src(_) => TCA_FLOWER_KEY_ENC_IPV4_SRC,
            Self::KeyEncIpv4SrcMask(_) => TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
            Self::KeyEncIpv4Dst(_) => TCA_FLOWER_KEY_ENC_IPV4_DST,
            Self::KeyEncIpv4DstMask(_) => TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
            Self::KeyEncIpv6Src(_) => TCA_FLOWER_KEY_ENC_IPV6_SRC,
            Self::KeyEncIpv6SrcMask(_) => TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,
            Self::KeyEncIpv6Dst(_) => TCA_FLOWER_KEY_ENC_IPV6_DST,
            Self::KeyEncIpv6DstMask(_) => TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,
            Self::KeyTcpSrcMask(_) => TCA_FLOWER_KEY_TCP_SRC_MASK,
            Self::KeyTcpDstMask(_) => TCA_FLOWER_KEY_TCP_DST_MASK,
            Self::KeyUdpSrcMask(_) => TCA_FLOWER_KEY_UDP_SRC_MASK,
            Self::KeyUdpDstMask(_) => TCA_FLOWER_KEY_UDP_DST_MASK,
            Self::KeySctpSrcMask(_) => TCA_FLOWER_KEY_SCTP_SRC_MASK,
            Self::KeySctpDstMask(_) => TCA_FLOWER_KEY_SCTP_DST_MASK,
            Self::KeySctpSrc(_) => TCA_FLOWER_KEY_SCTP_SRC,
            Self::KeySctpDst(_) => TCA_FLOWER_KEY_SCTP_DST,
            Self::KeyEncUdpSrcPort(_) => TCA_FLOWER_KEY_ENC_UDP_SRC_PORT,
            Self::KeyEncUdpSrcPortMask(_) => {
                TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK
            }
            Self::KeyEncUdpDstPort(_) => TCA_FLOWER_KEY_ENC_UDP_DST_PORT,
            Self::KeyEncUdpDstPortMask(_) => {
                TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK
            }
            Self::KeyFlags(_) => TCA_FLOWER_KEY_FLAGS,
            Self::KeyFlagsMask(_) => TCA_FLOWER_KEY_FLAGS_MASK,
            Self::KeyIcmpv4Code(_) => TCA_FLOWER_KEY_ICMPV4_CODE,
            Self::KeyIcmpv4CodeMask(_) => TCA_FLOWER_KEY_ICMPV4_CODE_MASK,
            Self::KeyIcmpv4Type(_) => TCA_FLOWER_KEY_ICMPV4_TYPE,
            Self::KeyIcmpv4TypeMask(_) => TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,
            Self::KeyIcmpv6Code(_) => TCA_FLOWER_KEY_ICMPV6_CODE,
            Self::KeyIcmpv6CodeMask(_) => TCA_FLOWER_KEY_ICMPV6_CODE_MASK,
            Self::KeyIcmpv6Type(_) => TCA_FLOWER_KEY_ICMPV6_TYPE,
            Self::KeyIcmpv6TypeMask(_) => TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,
            Self::KeyArpSip(_) => TCA_FLOWER_KEY_ARP_SIP,
            Self::KeyArpSipMask(_) => TCA_FLOWER_KEY_ARP_SIP_MASK,
            Self::KeyArpTip(_) => TCA_FLOWER_KEY_ARP_TIP,
            Self::KeyArpTipMask(_) => TCA_FLOWER_KEY_ARP_TIP_MASK,
            Self::KeyArpOp(_) => TCA_FLOWER_KEY_ARP_OP,
            Self::KeyArpOpMask(_) => TCA_FLOWER_KEY_ARP_OP_MASK,
            Self::KeyArpSha(_) => TCA_FLOWER_KEY_ARP_SHA,
            Self::KeyArpShaMask(_) => TCA_FLOWER_KEY_ARP_SHA_MASK,
            Self::KeyArpTha(_) => TCA_FLOWER_KEY_ARP_THA,
            Self::KeyArpThaMask(_) => TCA_FLOWER_KEY_ARP_THA_MASK,
            Self::KeyMplsTtl(_) => TCA_FLOWER_KEY_MPLS_TTL,
            Self::KeyMplsBos(_) => TCA_FLOWER_KEY_MPLS_BOS,
            Self::KeyMplsTc(_) => TCA_FLOWER_KEY_MPLS_TC,
            Self::KeyMplsLabel(_) => TCA_FLOWER_KEY_MPLS_LABEL,
            Self::KeyTcpFlags(_) => TCA_FLOWER_KEY_TCP_FLAGS,
            Self::KeyTcpFlagsMask(_) => TCA_FLOWER_KEY_TCP_FLAGS_MASK,
            Self::KeyIpTos(_) => TCA_FLOWER_KEY_IP_TOS,
            Self::KeyIpTtl(_) => TCA_FLOWER_KEY_IP_TTL,
            Self::KeyIpTosMask(_) => TCA_FLOWER_KEY_IP_TOS_MASK,
            Self::KeyIpTtlMask(_) => TCA_FLOWER_KEY_IP_TTL_MASK,
            Self::KeyCvlanId(_) => TCA_FLOWER_KEY_CVLAN_ID,
            Self::KeyCvlanPrio(_) => TCA_FLOWER_KEY_CVLAN_PRIO,
            Self::KeyCvlanEthType(_) => TCA_FLOWER_KEY_CVLAN_ETH_TYPE,
            Self::KeyEncIpTos(_) => TCA_FLOWER_KEY_ENC_IP_TOS,
            Self::KeyEncIpTosMask(_) => TCA_FLOWER_KEY_ENC_IP_TOS_MASK,
            Self::KeyEncIpTtl(_) => TCA_FLOWER_KEY_ENC_IP_TTL,
            Self::KeyEncIpTtlMask(_) => TCA_FLOWER_KEY_ENC_IP_TTL_MASK,
            // NOTE: iproute2 is just not consistent with the use of the NLAF_NESTED flag
            // for encap options.
            Self::KeyEncOpts(OptionsList(opts)) => {
                TCA_FLOWER_KEY_ENC_OPTS
                    | match opts {
                        encap::Options::Geneve(_) => 0,
                        encap::Options::Vxlan(_) => NLA_F_NESTED,
                        encap::Options::Erspan(_) => 0,
                        encap::Options::Gtp(_) => 0,
                        encap::Options::Other(_) => 0,
                    }
            }
            Self::KeyEncOptsMask(OptionsList(opts)) => {
                TCA_FLOWER_KEY_ENC_OPTS_MASK
                    | match opts {
                        encap::Options::Geneve(_) => 0,
                        encap::Options::Vxlan(_) => NLA_F_NESTED,
                        encap::Options::Erspan(_) => 0,
                        encap::Options::Gtp(_) => 0,
                        encap::Options::Other(_) => 0,
                    }
            }
            Self::InHwCount(_) => TCA_FLOWER_IN_HW_COUNT,
            Self::KeyPortSrcMin(_) => TCA_FLOWER_KEY_PORT_SRC_MIN,
            Self::KeyPortSrcMax(_) => TCA_FLOWER_KEY_PORT_SRC_MAX,
            Self::KeyPortDstMin(_) => TCA_FLOWER_KEY_PORT_DST_MIN,
            Self::KeyPortDstMax(_) => TCA_FLOWER_KEY_PORT_DST_MAX,
            Self::KeyCtState(_) => TCA_FLOWER_KEY_CT_STATE,
            Self::KeyCtStateMask(_) => TCA_FLOWER_KEY_CT_STATE_MASK,
            Self::KeyCtZone(_) => TCA_FLOWER_KEY_CT_ZONE,
            Self::KeyCtZoneMask(_) => TCA_FLOWER_KEY_CT_ZONE_MASK,
            Self::KeyCtMark(_) => TCA_FLOWER_KEY_CT_MARK,
            Self::KeyCtMarkMask(_) => TCA_FLOWER_KEY_CT_MARK_MASK,
            Self::KeyCtLabels(_) => TCA_FLOWER_KEY_CT_LABELS,
            Self::KeyCtLabelsMask(_) => TCA_FLOWER_KEY_CT_LABELS_MASK,
            Self::KeyMplsOpts(_) => TCA_FLOWER_KEY_MPLS_OPTS | NLA_F_NESTED,
            Self::KeyHash(_) => TCA_FLOWER_KEY_HASH,
            Self::KeyHashMask(_) => TCA_FLOWER_KEY_HASH_MASK,
            Self::KeyNumOfVlans(_) => TCA_FLOWER_KEY_NUM_OF_VLANS,
            Self::KeyPppoeSid(_) => TCA_FLOWER_KEY_PPPOE_SID,
            Self::KeyPppProto(_) => TCA_FLOWER_KEY_PPP_PROTO,
            Self::KeyL2tpv3Sid(_) => TCA_FLOWER_KEY_L2TPV3_SID,
            Self::L2Miss(_) => TCA_FLOWER_L2_MISS,
            Self::KeyCfm(_) => TCA_FLOWER_KEY_CFM | NLA_F_NESTED,
            Self::KeySpi(_) => TCA_FLOWER_KEY_SPI,
            Self::KeySpiMask(_) => TCA_FLOWER_KEY_SPI_MASK,
            Self::Other(attr) => attr.kind(),
        }
    }

    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Indev(b) => buffer.copy_from_slice(b.as_slice()),
            Self::ClassId(i) => NativeEndian::write_u32(buffer, (*i).into()),
            Self::Action(acts) => {
                acts.as_slice().emit(buffer);
            }
            Self::KeyEthDst(k) => buffer.copy_from_slice(k.as_ref().as_slice()),
            Self::KeyEthDstMask(k) => {
                buffer.copy_from_slice(k.as_ref().as_slice());
            }
            Self::KeyEthSrc(k) => buffer.copy_from_slice(k.as_ref().as_slice()),
            Self::KeyEthSrcMask(k) => {
                buffer.copy_from_slice(k.as_ref().as_slice());
            }
            Self::KeyEthType(eth_type) => {
                buffer.copy_from_slice(eth_type.as_be_bytes().as_slice());
            }
            Self::KeyIpProto(proto) => {
                // TODO: find a way to make clippy happy with this.
                // I think this is safe but that should be explained.
                #[allow(
                    clippy::cast_sign_loss,
                    clippy::cast_possible_truncation
                )]
                buffer.copy_from_slice(&[i32::from(*proto) as u8]);
            }
            Self::KeyIpv4Src(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyIpv4SrcMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyIpv4Dst(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyIpv4DstMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyIpv6Src(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyIpv6SrcMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyIpv6Dst(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyIpv6DstMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyTcpSrc(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyTcpDst(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyUdpSrc(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyUdpDst(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::Flags(f) => NativeEndian::write_u32(buffer, f.bits()),
            Self::KeyVlanId(vlan_id) => buffer.copy_from_slice(
                u16::to_ne_bytes(*vlan_id.as_ref()).as_slice(),
            ),
            Self::KeyVlanPrio(vlan_prio) => buffer
                .copy_from_slice(vlan_prio.as_ref().to_be_bytes().as_slice()),
            Self::KeyVlanEthType(eth_type) => {
                buffer.copy_from_slice(eth_type.as_be_bytes().as_slice());
            }
            Self::KeyEncKeyId(enc_key_id) => buffer
                .copy_from_slice(enc_key_id.as_ref().to_be_bytes().as_slice()),
            Self::KeyEncIpv4Src(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyEncIpv4SrcMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyEncIpv4Dst(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyEncIpv4DstMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyEncIpv6Src(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyEncIpv6SrcMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyEncIpv6Dst(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyEncIpv6DstMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyTcpSrcMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyTcpDstMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyUdpSrcMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyUdpDstMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeySctpSrcMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeySctpDstMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeySctpSrc(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeySctpDst(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyEncUdpSrcPort(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyEncUdpSrcPortMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyEncUdpDstPort(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyEncUdpDstPortMask(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyFlags(flags) => {
                buffer.copy_from_slice(flags.bits().to_be_bytes().as_slice());
            }
            Self::KeyFlagsMask(flags) => {
                buffer.copy_from_slice(flags.bits().to_be_bytes().as_slice());
            }
            Self::KeyIcmpv4Code(code) => {
                buffer.copy_from_slice(code.as_ref().to_be_bytes().as_slice());
            }
            Self::KeyIcmpv4CodeMask(code_mask) => {
                buffer.copy_from_slice(code_mask.to_be_bytes().as_slice());
            }
            Self::KeyIcmpv4Type(typ) => {
                buffer.copy_from_slice(typ.as_ref().to_be_bytes().as_slice());
            }
            Self::KeyIcmpv4TypeMask(type_mask) => {
                buffer.copy_from_slice(type_mask.to_be_bytes().as_slice());
            }
            Self::KeyIcmpv6Code(code) => {
                buffer.copy_from_slice(code.to_be_bytes().as_slice());
            }
            Self::KeyIcmpv6CodeMask(code_mask) => {
                buffer.copy_from_slice(code_mask.to_be_bytes().as_slice());
            }
            Self::KeyIcmpv6Type(typ) => {
                buffer.copy_from_slice(typ.as_ref().to_be_bytes().as_slice());
            }
            Self::KeyIcmpv6TypeMask(type_mask) => {
                buffer.copy_from_slice(type_mask.to_be_bytes().as_slice());
            }
            Self::KeyArpSip(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyArpSipMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyArpTip(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyArpTipMask(ip) => buffer.copy_from_slice(&ip.octets()),
            Self::KeyArpOp(op) => {
                buffer.copy_from_slice(op.as_ref().to_be_bytes().as_slice());
            }
            Self::KeyArpOpMask(op_mask) => {
                buffer.copy_from_slice(op_mask.to_be_bytes().as_slice());
            }
            Self::KeyArpSha(k) => buffer.copy_from_slice(k.as_ref().as_slice()),
            Self::KeyArpShaMask(k) => {
                buffer.copy_from_slice(k.as_ref().as_slice());
            }
            Self::KeyArpTha(k) => buffer.copy_from_slice(k.as_ref().as_slice()),
            Self::KeyArpThaMask(k) => {
                buffer.copy_from_slice(k.as_ref().as_slice());
            }
            Self::KeyMplsTtl(ttl) => {
                buffer.copy_from_slice(ttl.to_be_bytes().as_slice());
            }
            Self::KeyMplsBos(bos) => {
                buffer.copy_from_slice(u8::from(*bos).to_ne_bytes().as_slice());
            }
            Self::KeyMplsTc(tc) => {
                buffer.copy_from_slice(tc.to_be_bytes().as_slice());
            }
            Self::KeyMplsLabel(label) => {
                // TODO: I don't know why the yaml says this should be big
                // endian but nothing works unless it's native
                // endian.  Bug report?
                buffer.copy_from_slice(
                    u32::from(*label).to_ne_bytes().as_slice(),
                );
            }
            Self::KeyTcpFlags(flags) => buffer.copy_from_slice(
                #[allow(clippy::cast_lossless)]
                (flags.bits() as u16).to_be_bytes().as_slice(),
            ),
            Self::KeyTcpFlagsMask(flags) => {
                buffer.copy_from_slice(
                    u16::from(*flags).to_be_bytes().as_slice(),
                );
            }
            Self::KeyIpTos(tos) => {
                buffer.copy_from_slice(tos.to_be_bytes().as_slice());
            }
            Self::KeyIpTosMask(tos) => {
                buffer.copy_from_slice(tos.to_be_bytes().as_slice());
            }
            Self::KeyIpTtl(ttl) => {
                buffer.copy_from_slice(ttl.to_be_bytes().as_slice());
            }
            Self::KeyIpTtlMask(ttl) => {
                buffer.copy_from_slice(ttl.to_be_bytes().as_slice());
            }
            Self::KeyCvlanId(vlan_id) => buffer.copy_from_slice(
                u16::to_ne_bytes(*vlan_id.as_ref()).as_slice(),
            ),
            Self::KeyCvlanPrio(vlan_prio) => buffer
                .copy_from_slice(vlan_prio.as_ref().to_be_bytes().as_slice()),
            Self::KeyCvlanEthType(eth_type) => {
                buffer.copy_from_slice(eth_type.as_be_bytes().as_slice());
            }
            Self::KeyEncIpTos(tos) => {
                buffer.copy_from_slice(tos.to_be_bytes().as_slice());
            }
            Self::KeyEncIpTosMask(tos) => {
                buffer.copy_from_slice(tos.to_be_bytes().as_slice());
            }
            Self::KeyEncIpTtl(ttl) => {
                buffer.copy_from_slice(ttl.to_be_bytes().as_slice());
            }
            Self::KeyEncIpTtlMask(ttl) => {
                buffer.copy_from_slice(ttl.to_be_bytes().as_slice());
            }
            Self::KeyEncOpts(opts) => opts.emit_value(buffer),
            Self::KeyEncOptsMask(opts) => opts.emit_value(buffer),
            Self::InHwCount(count) => {
                NativeEndian::write_u32(buffer, *count);
            }
            Self::KeyPortSrcMin(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyPortSrcMax(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyPortDstMin(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyPortDstMax(port) => {
                buffer.copy_from_slice(port.to_be_bytes().as_slice());
            }
            Self::KeyCtState(state) => {
                buffer.copy_from_slice(state.bits().to_ne_bytes().as_slice());
            }
            Self::KeyCtStateMask(mask) => {
                buffer.copy_from_slice(mask.bits().to_ne_bytes().as_slice());
            }
            Self::KeyCtZone(zone) => {
                buffer.copy_from_slice(zone.to_ne_bytes().as_slice());
            }
            Self::KeyCtZoneMask(mask) => {
                buffer.copy_from_slice(mask.to_ne_bytes().as_slice());
            }
            Self::KeyCtMark(mark) => {
                buffer.copy_from_slice(mark.to_ne_bytes().as_slice());
            }
            Self::KeyCtMarkMask(mask) => {
                buffer.copy_from_slice(mask.to_ne_bytes().as_slice());
            }
            Self::KeyCtLabels(labels) => {
                buffer.copy_from_slice(labels.to_be_bytes().as_slice());
            }
            Self::KeyCtLabelsMask(labels) => {
                buffer.copy_from_slice(labels.to_be_bytes().as_slice());
            }
            Self::KeyMplsOpts(opts) => opts.emit_value(buffer),
            Self::KeyHash(hash) => {
                buffer.copy_from_slice(hash.to_ne_bytes().as_slice());
            }
            Self::KeyHashMask(mask) => {
                buffer.copy_from_slice(mask.to_ne_bytes().as_slice());
            }
            Self::KeyNumOfVlans(num) => {
                buffer.copy_from_slice(num.to_be_bytes().as_slice());
            }
            Self::KeyPppoeSid(sid) => {
                buffer.copy_from_slice(sid.to_be_bytes().as_slice());
            }
            Self::KeyPppProto(proto) => {
                buffer.copy_from_slice(proto.to_be_bytes().as_slice());
            }
            Self::KeyL2tpv3Sid(sid) => {
                buffer.copy_from_slice(sid.to_be_bytes().as_slice());
            }
            Self::L2Miss(l2_miss) => buffer.copy_from_slice(
                u8::from(l2_miss.clone()).to_be_bytes().as_slice(),
            ),
            Self::KeyCfm(cfm) => cfm.as_slice().emit(buffer),
            Self::KeySpi(spi) => {
                buffer.copy_from_slice(spi.to_be_bytes().as_slice());
            }
            Self::KeySpiMask(mask) => {
                buffer.copy_from_slice(mask.to_be_bytes().as_slice());
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TcFilterFlowerOption
{
    #[allow(clippy::too_many_lines)]
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_FLOWER_CLASSID => Self::ClassId(TcHandle::from(
                parse_u32(payload)
                    .context("failed to parse TCA_FLOWER_CLASSID")?,
            )),
            TCA_FLOWER_INDEV => Self::Indev(payload.to_vec()),
            TCA_FLOWER_ACT => {
                match NlasIterator::new(payload)
                    .map(|act| match act {
                        Ok(nla) => TcAction::parse(&nla),
                        Err(e) => Err(e),
                    })
                    .collect::<Result<Vec<TcAction>, DecodeError>>()
                {
                    Ok(acts) => Self::Action(acts),
                    Err(e) => return Err(e),
                }
            }
            TCA_FLOWER_KEY_ETH_DST => Self::KeyEthDst(parse_mac(payload)?),
            TCA_FLOWER_KEY_ETH_DST_MASK => {
                Self::KeyEthDstMask(parse_mac(payload)?)
            }
            TCA_FLOWER_KEY_ETH_SRC => Self::KeyEthSrc(parse_mac(payload)?),
            TCA_FLOWER_KEY_ETH_SRC_MASK => {
                Self::KeyEthSrcMask(parse_mac(payload)?)
            }
            TCA_FLOWER_KEY_ETH_TYPE => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid eth type length"));
                }
                let eth_type = BigEndian::read_u16(payload);
                Self::KeyEthType(ethernet::Ethertype::from(eth_type))
            }
            TCA_FLOWER_KEY_IP_PROTO => {
                #[allow(clippy::cast_lossless)]
                let proto = IpProtocol::from(parse_u8(payload)? as i32);
                Self::KeyIpProto(proto)
            }
            TCA_FLOWER_KEY_IPV4_SRC => {
                if payload.len() != 4 {
                    return Err(DecodeError::from("invalid ipv4 src length"));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyIpv4Src(ip)
            }
            TCA_FLOWER_KEY_IPV4_SRC_MASK => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid ipv4 src mask length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyIpv4SrcMask(ip)
            }
            TCA_FLOWER_KEY_IPV4_DST => {
                if payload.len() != 4 {
                    return Err(DecodeError::from("invalid ipv4 dst length"));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyIpv4Dst(ip)
            }
            TCA_FLOWER_KEY_IPV4_DST_MASK => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid ipv4 dst mask length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyIpv4DstMask(ip)
            }
            TCA_FLOWER_KEY_IPV6_SRC => {
                if payload.len() != 16 {
                    return Err(DecodeError::from("invalid ipv6 src length"));
                }
                let payload2: [u8; 16] =
                    payload.try_into().context("invalid ipv6 src length")?;
                Self::KeyIpv6Src(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_IPV6_SRC_MASK => {
                if payload.len() != 16 {
                    return Err(DecodeError::from(
                        "invalid ipv6 src mask length",
                    ));
                }
                let payload2: [u8; 16] = payload
                    .try_into()
                    .context("invalid ipv6 src mask length")?;
                Self::KeyIpv6SrcMask(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_IPV6_DST => {
                if payload.len() != 16 {
                    return Err(DecodeError::from("invalid ipv6 dst length"));
                }
                let payload2: [u8; 16] =
                    payload.try_into().context("invalid ipv6 dst length")?;
                Self::KeyIpv6Dst(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_IPV6_DST_MASK => {
                if payload.len() != 16 {
                    return Err(DecodeError::from(
                        "invalid ipv6 dst mask length",
                    ));
                }
                let payload2: [u8; 16] = payload
                    .try_into()
                    .context("invalid ipv6 dst mask length")?;
                Self::KeyIpv6DstMask(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_TCP_SRC => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid tcp src length"));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyTcpSrc(port)
            }
            TCA_FLOWER_KEY_TCP_DST => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid tcp dst length"));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyTcpDst(port)
            }
            TCA_FLOWER_KEY_UDP_SRC => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid udp src length"));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyUdpSrc(port)
            }
            TCA_FLOWER_KEY_UDP_DST => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid udp dst length"));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyUdpDst(port)
            }
            TCA_FLOWER_FLAGS => {
                if payload.len() != 4 {
                    return Err(DecodeError::from("invalid flags length"));
                }
                let flags = NativeEndian::read_u32(payload);
                Self::Flags(
                    TcFlowerOptionFlags::from_bits(flags)
                        .unwrap_or_else(TcFlowerOptionFlags::empty),
                )
            }
            TCA_FLOWER_KEY_VLAN_ID => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid vlan id length"));
                }
                let id = NativeEndian::read_u16(payload);
                Self::KeyVlanId(
                    ethernet::VlanId::new(id)
                        .context("failed to parse vlan id")?,
                )
            }
            TCA_FLOWER_KEY_VLAN_PRIO => {
                if payload.len() != 1 {
                    return Err(DecodeError::from("invalid vlan prio length"));
                }
                let prio = payload[0];
                Self::KeyVlanPrio(
                    ethernet::VlanPrio::new(prio)
                        .context("failed to parse vlan prio")?,
                )
            }
            TCA_FLOWER_KEY_VLAN_ETH_TYPE => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid vlan eth type length",
                    ));
                }
                let eth_type = BigEndian::read_u16(payload);
                Self::KeyVlanEthType(ethernet::Ethertype::from(eth_type))
            }
            TCA_FLOWER_KEY_ENC_KEY_ID => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid encap key id length",
                    ));
                }
                let id = BigEndian::read_u32(payload);
                Self::KeyEncKeyId(EncKeyId::new_unchecked(id))
            }
            TCA_FLOWER_KEY_ENC_IPV4_SRC => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid encap ipv4 src length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyEncIpv4Src(ip)
            }
            TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid encap ipv4 src mask length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyEncIpv4SrcMask(ip)
            }
            TCA_FLOWER_KEY_ENC_IPV4_DST => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid encap ipv4 dst length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyEncIpv4Dst(ip)
            }
            TCA_FLOWER_KEY_ENC_IPV4_DST_MASK => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid encap ipv4 dst mask length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyEncIpv4DstMask(ip)
            }
            TCA_FLOWER_KEY_ENC_IPV6_SRC => {
                if payload.len() != 16 {
                    return Err(DecodeError::from(
                        "invalid encap ipv6 src length",
                    ));
                }
                let payload2: [u8; 16] = payload
                    .try_into()
                    .context("invalid encap ipv6 src length")?;
                Self::KeyEncIpv6Src(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK => {
                if payload.len() != 16 {
                    return Err(DecodeError::from(
                        "invalid encap ipv6 src mask length",
                    ));
                }
                let payload2: [u8; 16] = payload
                    .try_into()
                    .context("invalid encap ipv6 src mask length")?;
                Self::KeyEncIpv6SrcMask(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_ENC_IPV6_DST => {
                if payload.len() != 16 {
                    return Err(DecodeError::from(
                        "invalid encap ipv6 dst length",
                    ));
                }
                let payload2: [u8; 16] = payload
                    .try_into()
                    .context("invalid encap ipv6 dst length")?;
                Self::KeyEncIpv6Dst(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_ENC_IPV6_DST_MASK => {
                if payload.len() != 16 {
                    return Err(DecodeError::from(
                        "invalid encap ipv6 dst mask length",
                    ));
                }
                let payload2: [u8; 16] = payload
                    .try_into()
                    .context("invalid encap ipv6 dst mask length")?;
                Self::KeyEncIpv6DstMask(Ipv6Addr::from(payload2))
            }
            TCA_FLOWER_KEY_TCP_SRC_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid tcp src mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyTcpSrcMask(port)
            }
            TCA_FLOWER_KEY_TCP_DST_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid tcp dst mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyTcpDstMask(port)
            }
            TCA_FLOWER_KEY_UDP_SRC_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid udp src mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyUdpSrcMask(port)
            }
            TCA_FLOWER_KEY_UDP_DST_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid udp dst mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyUdpDstMask(port)
            }
            TCA_FLOWER_KEY_SCTP_SRC_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid sctp src mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeySctpSrcMask(port)
            }
            TCA_FLOWER_KEY_SCTP_DST_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid sctp dst mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeySctpDstMask(port)
            }
            TCA_FLOWER_KEY_SCTP_SRC => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid sctp src length"));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeySctpSrc(port)
            }
            TCA_FLOWER_KEY_SCTP_DST => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid sctp dst length"));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeySctpDst(port)
            }
            TCA_FLOWER_KEY_ENC_UDP_SRC_PORT => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid encap udp src port length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyEncUdpSrcPort(port)
            }
            TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid encap udp src port mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyEncUdpSrcPortMask(port)
            }
            TCA_FLOWER_KEY_ENC_UDP_DST_PORT => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid encap udp dst port length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyEncUdpDstPort(port)
            }
            TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid encap udp dst port mask length",
                    ));
                }
                let port = BigEndian::read_u16(payload);
                Self::KeyEncUdpDstPortMask(port)
            }
            TCA_FLOWER_KEY_FLAGS => Self::KeyFlags(
                flower::Flags::from_bits_retain(parse_u32_be(payload)?),
            ),
            TCA_FLOWER_KEY_FLAGS_MASK => Self::KeyFlagsMask(
                flower::Flags::from_bits_retain(parse_u32_be(payload)?),
            ),
            TCA_FLOWER_KEY_ICMPV4_CODE => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv4 code length",
                    ));
                }
                // TODO: it makes no sense to use Other here unconditionally.
                // I need to restructure ICMPv4 parsing if the code is to have a
                // meaning more specific than a number after
                // deserialization. That would require at least
                // two passes through the parser which is just not
                // how it works (and likely not how it should work).
                Self::KeyIcmpv4Code(icmpv4::Code::Other(payload[0]))
            }
            TCA_FLOWER_KEY_ICMPV4_CODE_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv4 code mask length",
                    ));
                }
                Self::KeyIcmpv4CodeMask(payload[0])
            }
            TCA_FLOWER_KEY_ICMPV4_TYPE => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv4 type length",
                    ));
                }
                Self::KeyIcmpv4Type(icmpv4::Type::from(payload[0]))
            }
            TCA_FLOWER_KEY_ICMPV4_TYPE_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv4 type mask length",
                    ));
                }
                Self::KeyIcmpv4TypeMask(payload[0])
            }
            TCA_FLOWER_KEY_ICMPV6_CODE => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv6 code length",
                    ));
                }
                Self::KeyIcmpv6Code(payload[0])
            }
            TCA_FLOWER_KEY_ICMPV6_CODE_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv6 code mask length",
                    ));
                }
                Self::KeyIcmpv6CodeMask(payload[0])
            }
            TCA_FLOWER_KEY_ICMPV6_TYPE => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv6 type length",
                    ));
                }
                Self::KeyIcmpv6Type(icmpv6::Type::from(payload[0]))
            }
            TCA_FLOWER_KEY_ICMPV6_TYPE_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid icmpv6 type mask length",
                    ));
                }
                Self::KeyIcmpv6TypeMask(payload[0])
            }
            TCA_FLOWER_KEY_ARP_SIP => {
                if payload.len() != 4 {
                    return Err(DecodeError::from("invalid arp sip length"));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyArpSip(ip)
            }
            TCA_FLOWER_KEY_ARP_SIP_MASK => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid arp sip mask length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyArpSipMask(ip)
            }
            TCA_FLOWER_KEY_ARP_TIP => {
                if payload.len() != 4 {
                    return Err(DecodeError::from("invalid arp tip length"));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyArpTip(ip)
            }
            TCA_FLOWER_KEY_ARP_TIP_MASK => {
                if payload.len() != 4 {
                    return Err(DecodeError::from(
                        "invalid arp tip mask length",
                    ));
                }
                let ip = Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                Self::KeyArpTipMask(ip)
            }
            TCA_FLOWER_KEY_ARP_OP => {
                if payload.len() != 1 {
                    return Err(DecodeError::from("invalid arp op length"));
                }
                Self::KeyArpOp(arp::Operation::from(payload[0]))
            }
            TCA_FLOWER_KEY_ARP_OP_MASK => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid arp op mask length",
                    ));
                }
                Self::KeyArpOpMask(payload[0])
            }
            TCA_FLOWER_KEY_ARP_SHA => {
                if payload.len() != 6 {
                    return Err(DecodeError::from("invalid arp sha length"));
                }
                match parse_mac(payload) {
                    Ok(mac) => Self::KeyArpSha(mac),
                    Err(e) => return Err(e),
                }
            }
            TCA_FLOWER_KEY_ARP_SHA_MASK => {
                if payload.len() != 6 {
                    return Err(DecodeError::from(
                        "invalid arp sha mask length",
                    ));
                }
                match parse_mac(payload) {
                    Ok(mac) => Self::KeyArpShaMask(mac),
                    Err(e) => return Err(e),
                }
            }
            TCA_FLOWER_KEY_ARP_THA => {
                if payload.len() != 6 {
                    return Err(DecodeError::from("invalid arp tha length"));
                }
                match parse_mac(payload) {
                    Ok(mac) => Self::KeyArpTha(mac),
                    Err(e) => return Err(e),
                }
            }
            TCA_FLOWER_KEY_ARP_THA_MASK => {
                if payload.len() != 6 {
                    return Err(DecodeError::from(
                        "invalid arp tha mask length",
                    ));
                }
                match parse_mac(payload) {
                    Ok(mac) => Self::KeyArpThaMask(mac),
                    Err(e) => return Err(e),
                }
            }
            TCA_FLOWER_KEY_MPLS_TTL => Self::KeyMplsTtl(parse_u8(payload)?),
            TCA_FLOWER_KEY_MPLS_BOS => {
                Self::KeyMplsBos(mpls::BottomOfStack::from(parse_u8(payload)?))
            }
            TCA_FLOWER_KEY_MPLS_TC => Self::KeyMplsTc(parse_u8(payload)?),
            TCA_FLOWER_KEY_MPLS_LABEL => {
                Self::KeyMplsLabel(mpls::Label::try_from(parse_u32(payload)?)?)
            }
            TCA_FLOWER_KEY_TCP_FLAGS => {
                let flags = parse_u16_be(payload)?;
                if flags > 0xff {
                    return Err(DecodeError::from("invalid tcp flags value"));
                }
                Self::KeyTcpFlags(TcpFlags::from_bits_retain(
                    (flags & 0xff) as u8,
                ))
            }
            TCA_FLOWER_KEY_TCP_FLAGS_MASK => {
                let flags = parse_u16_be(payload)?;
                if flags > 0xff {
                    return Err(DecodeError::from(
                        "invalid tcp flags mask value",
                    ));
                }
                Self::KeyTcpFlagsMask((flags & 0xff) as u8)
            }
            TCA_FLOWER_KEY_IP_TOS => {
                if payload.len() != 1 {
                    return Err(DecodeError::from("invalid ip tos length"));
                }
                Self::KeyIpTos(payload[0])
            }
            TCA_FLOWER_KEY_IP_TOS_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid ip tos mask length",
                    ));
                }
                Self::KeyIpTosMask(payload[0])
            }
            TCA_FLOWER_KEY_IP_TTL => {
                if payload.len() != 1 {
                    return Err(DecodeError::from("invalid ip ttl length"));
                }
                Self::KeyIpTtl(payload[0])
            }
            TCA_FLOWER_KEY_IP_TTL_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid ip ttl mask length",
                    ));
                }
                Self::KeyIpTtlMask(payload[0])
            }
            TCA_FLOWER_KEY_CVLAN_ID => {
                if payload.len() != 2 {
                    return Err(DecodeError::from("invalid cvlan id length"));
                }
                let id = NativeEndian::read_u16(payload);
                Self::KeyCvlanId(
                    ethernet::VlanId::new(id)
                        .context("failed to parse cvlan id")?,
                )
            }
            TCA_FLOWER_KEY_CVLAN_PRIO => {
                if payload.len() != 1 {
                    return Err(DecodeError::from("invalid cvlan prio length"));
                }
                let prio = payload[0];
                Self::KeyCvlanPrio(
                    ethernet::VlanPrio::new(prio)
                        .context("failed to parse cvlan prio")?,
                )
            }
            TCA_FLOWER_KEY_CVLAN_ETH_TYPE => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "invalid cvlan eth type length",
                    ));
                }
                let eth_type = BigEndian::read_u16(payload);
                Self::KeyCvlanEthType(ethernet::Ethertype::from(eth_type))
            }
            TCA_FLOWER_KEY_ENC_IP_TOS => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid encap ip tos length",
                    ));
                }
                Self::KeyEncIpTos(payload[0])
            }
            TCA_FLOWER_KEY_ENC_IP_TOS_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid encap ip tos mask length",
                    ));
                }
                Self::KeyEncIpTosMask(payload[0])
            }
            TCA_FLOWER_KEY_ENC_IP_TTL => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid encap ip ttl length",
                    ));
                }
                Self::KeyEncIpTtl(payload[0])
            }
            TCA_FLOWER_KEY_ENC_IP_TTL_MASK => {
                if payload.len() != 1 {
                    return Err(DecodeError::from(
                        "invalid encap ip ttl mask length",
                    ));
                }
                Self::KeyEncIpTtlMask(payload[0])
            }
            TCA_FLOWER_KEY_ENC_OPTS => {
                Self::KeyEncOpts(encap::OptionsList::parse(buf)?)
            }
            TCA_FLOWER_KEY_ENC_OPTS_MASK => {
                Self::KeyEncOptsMask(encap::OptionsList::parse(buf)?)
            }
            TCA_FLOWER_IN_HW_COUNT => Self::InHwCount(
                parse_u32(payload)
                    .context("failed to parse TCA_FLOWER_IN_HW_COUNT")?,
            ),
            TCA_FLOWER_KEY_PORT_SRC_MIN => Self::KeyPortSrcMin(
                parse_u16(payload)
                    .context("failed to parse key port source min")?,
            ),
            TCA_FLOWER_KEY_PORT_SRC_MAX => Self::KeyPortSrcMax(
                parse_u16(payload)
                    .context("failed to parse key port source max")?,
            ),
            TCA_FLOWER_KEY_PORT_DST_MIN => Self::KeyPortDstMin(
                parse_u16(payload)
                    .context("failed to parse key port source max")?,
            ),
            TCA_FLOWER_KEY_PORT_DST_MAX => Self::KeyPortDstMax(
                parse_u16(payload)
                    .context("failed to parse key port source max")?,
            ),
            TCA_FLOWER_KEY_CT_STATE => {
                let state = ConnectionTrackingFlags::from_bits(
                    NativeEndian::read_u16(payload),
                )
                .ok_or_else(|| {
                    DecodeError::from("invalid connection tracking state")
                })?;
                Self::KeyCtState(state)
            }
            TCA_FLOWER_KEY_CT_STATE_MASK => {
                let mask = ConnectionTrackingFlags::from_bits(
                    NativeEndian::read_u16(payload),
                )
                .ok_or_else(|| {
                    DecodeError::from("invalid connection tracking state mask")
                })?;
                Self::KeyCtStateMask(mask)
            }
            TCA_FLOWER_KEY_CT_ZONE => Self::KeyCtZone(parse_u16(payload)?),
            TCA_FLOWER_KEY_CT_ZONE_MASK => Self::KeyCtZone(parse_u16(payload)?),
            TCA_FLOWER_KEY_CT_MARK => Self::KeyCtMark(parse_u32(payload)?),
            TCA_FLOWER_KEY_CT_MARK_MASK => Self::KeyCtMark(parse_u32(payload)?),
            TCA_FLOWER_KEY_CT_LABELS => {
                Self::KeyCtLabels(parse_u128_be(payload)?)
            }
            TCA_FLOWER_KEY_CT_LABELS_MASK => {
                Self::KeyCtLabels(parse_u128_be(payload)?)
            }
            TCA_FLOWER_KEY_MPLS_OPTS => {
                Self::KeyMplsOpts(flower::mpls::Options::parse(buf)?)
            }
            TCA_FLOWER_KEY_HASH => Self::KeyHash(parse_u32(payload)?),
            TCA_FLOWER_KEY_HASH_MASK => Self::KeyHash(parse_u32(payload)?),
            TCA_FLOWER_KEY_NUM_OF_VLANS => {
                Self::KeyNumOfVlans(parse_u8(payload)?)
            }
            TCA_FLOWER_KEY_PPPOE_SID => {
                Self::KeyPppoeSid(parse_u16_be(payload)?)
            }
            TCA_FLOWER_KEY_PPP_PROTO => {
                Self::KeyPppProto(parse_u16_be(payload)?)
            }
            TCA_FLOWER_KEY_L2TPV3_SID => {
                Self::KeyL2tpv3Sid(parse_u32_be(payload)?)
            }
            TCA_FLOWER_L2_MISS => {
                if payload.len() != 1 {
                    Err(DecodeError::from("invalid l2 miss length"))?;
                }
                let l2_miss = match payload[0] {
                    0 => L2Miss::NoMiss,
                    1 => L2Miss::Miss,
                    other => L2Miss::Other(other),
                };
                Self::L2Miss(l2_miss)
            }
            TCA_FLOWER_KEY_CFM => {
                let cfms = buf.value();
                Self::KeyCfm(
                    NlasIterator::new(cfms)
                        .map(|cfm| CfmAttribute::parse(&cfm?))
                        .collect::<Result<Vec<CfmAttribute>, _>>()?,
                )
            }
            TCA_FLOWER_KEY_SPI => Self::KeySpi(parse_u32_be(buf.value())?),
            TCA_FLOWER_KEY_SPI_MASK => {
                Self::KeySpiMask(parse_u32_be(buf.value())?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse flower nla")?,
            ),
        })
    }
}

fn parse_mac(slice: &[u8]) -> Result<ethernet::Mac, DecodeError> {
    let mut mac = [0; 6];
    if slice.len() != mac.len() {
        return Err(DecodeError::from("invalid MAC address length"));
    }
    mac.copy_from_slice(slice);
    Ok(mac.into())
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ConnectionTrackingFlags: u16 {
        const New = 1 << 0;
        const Established = 1 << 1;
        const Related = 1 << 2;
        const Tracked = 1 << 3;
        const Invalid = 1 << 4;
        const Reply = 1 << 5;
        const _ = !0;
    }
}

fn parse_u128_be(slice: &[u8]) -> Result<u128, DecodeError> {
    if slice.len() != 16 {
        return Err(DecodeError::from("invalid u128 length"));
    }
    Ok(BigEndian::read_u128(slice))
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u8)]
pub enum L2Miss {
    NoMiss = 0,
    Miss = 1,
    Other(u8),
}

impl From<u8> for L2Miss {
    fn from(value: u8) -> Self {
        match value {
            0 => L2Miss::NoMiss,
            1 => L2Miss::Miss,
            value => L2Miss::Other(value),
        }
    }
}

impl From<L2Miss> for u8 {
    fn from(value: L2Miss) -> Self {
        match value {
            L2Miss::NoMiss => 0,
            L2Miss::Miss => 1,
            L2Miss::Other(value) => value,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct MaintenanceDomainLevel(u8);

impl MaintenanceDomainLevel {
    /// # Errors
    /// Returns an error if the value is greater than 7
    /// (the maximum allowed value in the CFM spec).
    pub fn new(value: u8) -> Result<Self, DecodeError> {
        if value > 7 {
            Err(DecodeError::from("invalid maintenance domain level"))
        } else {
            Ok(Self(value))
        }
    }
}

impl From<MaintenanceDomainLevel> for u8 {
    fn from(value: MaintenanceDomainLevel) -> Self {
        value.0
    }
}

impl TryFrom<u8> for MaintenanceDomainLevel {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum CfmAttribute {
    MaintenanceDomainLevel(MaintenanceDomainLevel),
    OpCode(CfmOpCode),
    Other(DefaultNla),
}

const TCA_FLOWER_KEY_CFM_MD_LEVEL: u16 = 1;
const TCA_FLOWER_KEY_CFM_OPCODE: u16 = 2;

impl Nla for CfmAttribute {
    fn value_len(&self) -> usize {
        match self {
            CfmAttribute::MaintenanceDomainLevel(_)
            | CfmAttribute::OpCode(_) => 1,
            CfmAttribute::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            CfmAttribute::MaintenanceDomainLevel(_) => {
                TCA_FLOWER_KEY_CFM_MD_LEVEL
            }
            CfmAttribute::OpCode(_) => TCA_FLOWER_KEY_CFM_OPCODE,
            CfmAttribute::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            CfmAttribute::MaintenanceDomainLevel(level) => {
                buffer[0] = level.0;
            }
            CfmAttribute::OpCode(op_code) => {
                buffer[0] = *op_code;
            }
            CfmAttribute::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for CfmAttribute {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_CFM_MD_LEVEL => {
                CfmAttribute::MaintenanceDomainLevel(
                    MaintenanceDomainLevel::new(parse_u8(payload)?)
                        .context("failed to parse maintenance domain level")?,
                )
            }
            TCA_FLOWER_KEY_CFM_OPCODE => {
                CfmAttribute::OpCode(parse_u8(payload)?)
            }
            _ => CfmAttribute::Other(
                DefaultNla::parse(buf).context("failed to parse cfm nla")?,
            ),
        })
    }
}
