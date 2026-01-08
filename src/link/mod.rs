// SPDX-License-Identifier: MIT

mod af_spec;
mod attribute;
mod buffer_tool;
mod down_reason;
mod event;
pub(crate) mod ext_mask;
#[cfg(target_os = "freebsd")]
mod freebsd;
mod header;
mod link_flag;
mod link_info;
mod link_layer_type;
mod link_mode;
mod link_state;
mod map;
mod message;
mod phys_id;
mod prop_list;
mod proto_info;
pub(crate) mod sriov;
mod stats;
mod stats64;
mod vlan_protocol;
mod xdp;

mod tests;

#[cfg(not(target_os = "freebsd"))]
pub use self::link_info::{
    BondAdInfo, BondAdSelect, BondAllPortActive, BondArpAllTargets,
    BondArpValidate, BondFailOverMac, BondLacpRate, BondMode, BondPortState,
    BondPrimaryReselect, BondXmitHashPolicy, BridgeBooleanOptionFlags,
    BridgeBooleanOptions, BridgeId, BridgeIdBuffer, BridgeMulticastRouterType,
    BridgePortState, BridgeQuerierState, BridgeStpState, GeneveDf,
    GreEncapFlags, GreEncapType, GreIOFlags, HsrProtocol, InfoBond,
    InfoBondPort, InfoBridge, InfoBridgePort, InfoGeneve, InfoGre, InfoGre6,
    InfoGtp, InfoHsr, InfoIpTunnel, InfoIpVlan, InfoIpVtap, InfoIpoib,
    InfoMacSec, InfoMacVlan, InfoMacVtap, InfoNetkit, InfoPortData,
    InfoPortKind, InfoTun, InfoVeth, InfoVrf, InfoVrfPort, InfoVti, InfoVxlan,
    InfoXfrm, Ip6TunnelFlags, IpVlanFlags, IpVlanMode, IpVtapFlags, IpVtapMode,
    IpoibMode, LinkXstats, MacSecCipherId, MacSecOffload, MacSecValidate,
    MacVlanFlags, MacVlanMacAddressMode, MacVlanMode, MacVtapFlags,
    MacVtapMacAddressMode, MacVtapMode, MiiStatus, NetkitMode, NetkitPolicy,
    NetkitScrub, TunnelEncapFlags, TunnelEncapType,
};
pub use self::{
    af_spec::{
        AfSpecBridge, AfSpecInet, AfSpecInet6, AfSpecUnspec, BridgeFlag,
        BridgeMode, BridgeVlanInfo, BridgeVlanInfoFlags, BridgeVlanTunnelInfo,
        Icmp6Stats, Icmp6StatsBuffer, In6AddrGenMode, Inet6CacheInfo,
        Inet6CacheInfoBuffer, Inet6DevConf, Inet6DevConfBuffer,
        Inet6IfaceFlags, Inet6Stats, Inet6StatsBuffer, InetDevConf,
    },
    attribute::LinkAttribute,
    down_reason::LinkProtocolDownReason,
    event::LinkEvent,
    ext_mask::LinkExtentMask,
    header::{LinkHeader, LinkMessageBuffer},
    link_flag::LinkFlags,
    link_info::{
        InfoData, InfoKind, InfoVlan, LinkInfo, VlanFlags, VlanQosMapping,
    },
    link_layer_type::LinkLayerType,
    link_mode::LinkMode,
    link_state::State,
    map::{Map, MapBuffer},
    message::LinkMessage,
    phys_id::LinkPhysId,
    prop_list::Prop,
    proto_info::{LinkProtoInfoBridge, LinkProtoInfoInet6},
    sriov::{
        LinkVfInfo, LinkVfPort, VfInfo, VfInfoBroadcast, VfInfoBroadcastBuffer,
        VfInfoGuid, VfInfoGuidBuffer, VfInfoLinkState, VfInfoLinkStateBuffer,
        VfInfoMac, VfInfoMacBuffer, VfInfoRate, VfInfoRateBuffer,
        VfInfoRssQueryEn, VfInfoRssQueryEnBuffer, VfInfoSpoofCheck,
        VfInfoSpoofCheckBuffer, VfInfoTrust, VfInfoTrustBuffer, VfInfoTxRate,
        VfInfoTxRateBuffer, VfInfoVlan, VfInfoVlanBuffer, VfLinkState, VfPort,
        VfStats, VfVlan, VfVlanInfo,
    },
    stats::{Stats, StatsBuffer},
    stats64::{Stats64, Stats64Buffer},
    vlan_protocol::VlanProtocol,
    xdp::{LinkXdp, XdpAttached},
};
