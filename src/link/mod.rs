// SPDX-License-Identifier: MIT

#[cfg(feature = "link-af-spec")]
mod af_spec;
mod attribute;
mod buffer_tool;
mod devlink_port;
mod down_reason;
mod dpll_pin;
mod event;
pub(crate) mod ext_mask;
mod header;
mod link_flag;
#[cfg(feature = "link-info")]
mod link_info;
mod link_layer_type;
mod link_mode;
mod link_state;
mod map;
mod message;
mod phys_id;
mod prop_list;
mod proto_info;
#[cfg(feature = "link-sriov")]
pub(crate) mod sriov;
mod stats;
mod stats64;
mod vlan_protocol;
mod wireless;
mod xdp;

#[cfg(test)]
mod tests;

#[cfg(feature = "link-af-spec")]
pub use self::af_spec::{
    AfSpecBridge, AfSpecInet, AfSpecInet6, AfSpecMctp, AfSpecUnspec,
    BridgeFlag, BridgeMode, BridgeVlanInfo, BridgeVlanInfoFlags,
    BridgeVlanTunnelInfo, Icmp6Stats, In6AddrGenMode, Inet6CacheInfo,
    Inet6DevConf, Inet6IfaceFlags, Inet6Stats, InetDevConf, MctpPhysBinding,
};
#[cfg(feature = "link-af-spec")]
pub(crate) use self::af_spec::{
    Icmp6StatsBuffer, Inet6DevConfBuffer, Inet6StatsBuffer,
};
#[cfg(feature = "link-info")]
pub use self::link_info::{
    AmtMode, BondAdInfo, BondAdSelect, BondAllPortActive, BondArpAllTargets,
    BondArpValidate, BondFailOverMac, BondLacpRate, BondMode, BondPortState,
    BondPrimaryReselect, BondXmitHashPolicy, BridgeBooleanOptionFlags,
    BridgeBooleanOptions, BridgeId, BridgeMulticastRouterType, BridgePortState,
    BridgeQuerierState, BridgeStpMode, BridgeStpState, CanBerrCounter,
    CanBitTiming, CanBitTimingConst, CanClock, CanCtrlMode, CanCtrlModeExt,
    CanCtrlModeFlags, CanTdc, ChurnState, ErSpanDir, GeneveDf, GreEncapFlags,
    GreEncapType, GreIOFlags, GtpRole, HsrProtocol, InfoAmt, InfoBareUdp,
    InfoBatAdv, InfoBond, InfoBondPort, InfoBridge, InfoBridgePort, InfoCan,
    InfoData, InfoDsa, InfoGeneve, InfoGre, InfoGre6, InfoGtp, InfoHsr,
    InfoIpTunnel, InfoIpVlan, InfoIpVtap, InfoIpoib, InfoKind, InfoMacSec,
    InfoMacVlan, InfoMacVtap, InfoNetkit, InfoPortData, InfoPortKind,
    InfoRmNet, InfoRmNetFlags, InfoTeamPort, InfoTun, InfoVeth, InfoVlan,
    InfoVrf, InfoVrfPort, InfoVti, InfoVxcan, InfoVxlan, InfoWireguard,
    InfoWwan, InfoXfrm, Ip6TunnelFlags, IpVlanFlags, IpVlanMode, IpVtapFlags,
    IpVtapMode, IpoibMode, LacpState, LinkInfo, LinkXstats, MacSecCipherId,
    MacSecOffload, MacSecValidate, MacVlanFlags, MacVlanMacAddressMode,
    MacVlanMode, MacVtapFlags, MacVtapMacAddressMode, MacVtapMode, MiiStatus,
    NetkitMode, NetkitPolicy, NetkitScrub, RmNetFlags, TunnelEncapFlags,
    TunnelEncapType, VlanFlags, VlanQosMapping, VxlanDf,
};
#[cfg(feature = "link-sriov")]
pub use self::sriov::{
    LinkVfInfo, LinkVfPort, VfInfo, VfInfoBroadcast, VfInfoGuid,
    VfInfoLinkState, VfInfoMac, VfInfoRate, VfInfoRssQueryEn, VfInfoSpoofCheck,
    VfInfoTrust, VfInfoTxRate, VfInfoVlan, VfLinkState, VfPort, VfStats,
    VfVlan, VfVlanInfo,
};
pub use self::{
    attribute::LinkAttribute,
    devlink_port::DevlinkPort,
    down_reason::LinkProtocolDownReason,
    dpll_pin::DpllPin,
    event::LinkEvent,
    ext_mask::LinkExtentMask,
    header::LinkHeader,
    link_flag::LinkFlags,
    link_layer_type::LinkLayerType,
    link_mode::LinkMode,
    link_state::State,
    map::Map,
    message::LinkMessage,
    phys_id::LinkPhysId,
    prop_list::Prop,
    proto_info::{LinkProtoInfoBridge, LinkProtoInfoInet6},
    stats::Stats,
    stats64::Stats64,
    vlan_protocol::VlanProtocol,
    wireless::WirelessEvent,
    xdp::{LinkXdp, XdpAttached},
};
pub(crate) use self::{stats::StatsBuffer, stats64::Stats64Buffer};
