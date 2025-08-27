// SPDX-License-Identifier: MIT

mod af_spec;
mod attribute;
mod buffer_tool;
mod down_reason;
mod event;
pub(crate) mod ext_mask;
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
mod wireless;
mod xdp;

mod tests;

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
        BondAdInfo, BondArpAllTargets, BondArpValidate, BondFailOverMac,
        BondMode, BondPortState, BondPrimaryReselect, BondXmitHashPolicy,
        BridgeId, BridgeIdBuffer, BridgePortMulticastRouter, BridgePortState,
        BridgeQuerierState, GeneveDf, HsrProtocol, InfoBond, InfoBondPort,
        InfoBridge, InfoBridgePort, InfoData, InfoGeneve, InfoGreTap,
        InfoGreTap6, InfoGreTun, InfoGreTun6, InfoGtp, InfoHsr, InfoIpVlan,
        InfoIpVtap, InfoIpoib, InfoKind, InfoMacSec, InfoMacVlan, InfoMacVtap,
        InfoPortData, InfoPortKind, InfoSitTun, InfoTun, InfoVeth, InfoVlan,
        InfoVrf, InfoVrfPort, InfoVti, InfoVxlan, InfoXfrm, IpVlanFlags,
        IpVlanMode, IpVtapFlags, IpVtapMode, LinkInfo, LinkXstats,
        MacSecCipherId, MacSecOffload, MacSecValidate, MacVlanMode,
        MacVtapMode, MiiStatus, VlanQosMapping,
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
    wireless::LinkWirelessEvent,
    xdp::{LinkXdp, XdpAttached},
};
