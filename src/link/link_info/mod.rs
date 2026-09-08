// SPDX-License-Identifier: MIT

#[cfg(not(target_os = "freebsd"))]
mod amt;
#[cfg(not(target_os = "freebsd"))]
mod bareudp;
#[cfg(not(target_os = "freebsd"))]
mod batadv;
#[cfg(not(target_os = "freebsd"))]
mod bond;
#[cfg(not(target_os = "freebsd"))]
mod bond_port;
#[cfg(not(target_os = "freebsd"))]
mod bridge;
#[cfg(not(target_os = "freebsd"))]
mod bridge_boolopt;
#[cfg(not(target_os = "freebsd"))]
mod bridge_port;
#[cfg(not(target_os = "freebsd"))]
mod can;
#[cfg(not(target_os = "freebsd"))]
mod dsa;
#[cfg(not(target_os = "freebsd"))]
mod geneve;
#[cfg(not(target_os = "freebsd"))]
mod gre;
#[cfg(not(target_os = "freebsd"))]
mod gtp;
#[cfg(not(target_os = "freebsd"))]
mod hsr;
mod info_data;
#[cfg(not(target_os = "freebsd"))]
mod info_port;
mod infos;
#[cfg(not(target_os = "freebsd"))]
mod ipoib;
#[cfg(not(target_os = "freebsd"))]
mod iptunnel;
#[cfg(not(target_os = "freebsd"))]
mod ipvlan;
#[cfg(not(target_os = "freebsd"))]
mod mac_vlan;
#[cfg(not(target_os = "freebsd"))]
mod macsec;
#[cfg(not(target_os = "freebsd"))]
mod netkit;
#[cfg(not(target_os = "freebsd"))]
mod rmnet;
#[cfg(not(target_os = "freebsd"))]
mod team_port;
#[cfg(not(target_os = "freebsd"))]
mod tun;
#[cfg(not(target_os = "freebsd"))]
mod veth;
mod vlan;
#[cfg(not(target_os = "freebsd"))]
mod vrf;
#[cfg(not(target_os = "freebsd"))]
mod vti;
#[cfg(not(target_os = "freebsd"))]
mod vxcan;
#[cfg(not(target_os = "freebsd"))]
mod vxlan;
#[cfg(not(target_os = "freebsd"))]
mod wireguard;
#[cfg(not(target_os = "freebsd"))]
mod wwan;
#[cfg(not(target_os = "freebsd"))]
mod xfrm;
#[cfg(not(target_os = "freebsd"))]
mod xstats;

pub(crate) use self::infos::VecLinkInfo;
#[cfg(not(target_os = "freebsd"))]
pub use self::{
    amt::{AmtMode, InfoAmt},
    bareudp::InfoBareUdp,
    batadv::InfoBatAdv,
    bond::{
        BondAdInfo, BondAdSelect, BondAllPortActive, BondArpAllTargets,
        BondArpValidate, BondFailOverMac, BondLacpRate, BondMode,
        BondPrimaryReselect, BondXmitHashPolicy, InfoBond,
    },
    bond_port::{
        BondPortState, ChurnState, InfoBondPort, LacpState, MiiStatus,
    },
    bridge::{
        BridgeId, BridgeIdBuffer, BridgeMulticastRouterType,
        BridgeQuerierState, BridgeStpMode, BridgeStpState, InfoBridge,
    },
    bridge_boolopt::{BridgeBooleanOptionFlags, BridgeBooleanOptions},
    bridge_port::{BridgePortState, InfoBridgePort},
    can::{
        CanBerrCounter, CanBitTiming, CanBitTimingConst, CanClock, CanCtrlMode,
        CanCtrlModeFlags, CanTdc, InfoCan,
    },
    dsa::InfoDsa,
    geneve::{GeneveDf, InfoGeneve},
    gre::{
        ErSpanDir, GreEncapFlags, GreEncapType, GreIOFlags, InfoGre, InfoGre6,
    },
    gtp::{GtpRole, InfoGtp},
    hsr::{HsrProtocol, InfoHsr},
    info_port::{InfoPortData, InfoPortKind, InfoVrfPort},
    ipoib::{InfoIpoib, IpoibMode},
    iptunnel::{
        InfoIpTunnel, Ip6TunnelFlags, TunnelEncapFlags, TunnelEncapType,
    },
    ipvlan::{
        InfoIpVlan, InfoIpVtap, IpVlanFlags, IpVlanMode, IpVtapFlags,
        IpVtapMode,
    },
    mac_vlan::{
        InfoMacVlan, InfoMacVtap, MacVlanFlags, MacVlanMacAddressMode,
        MacVlanMode, MacVtapFlags, MacVtapMacAddressMode, MacVtapMode,
    },
    macsec::{InfoMacSec, MacSecCipherId, MacSecOffload, MacSecValidate},
    netkit::{InfoNetkit, NetkitMode, NetkitPolicy, NetkitScrub},
    rmnet::{InfoRmNet, InfoRmNetFlags, RmNetFlags},
    team_port::InfoTeamPort,
    tun::InfoTun,
    veth::InfoVeth,
    vrf::InfoVrf,
    vti::InfoVti,
    vxcan::InfoVxcan,
    vxlan::{InfoVxlan, VxlanDf},
    wireguard::InfoWireguard,
    wwan::InfoWwan,
    xfrm::InfoXfrm,
    xstats::LinkXstats,
};
pub use self::{
    info_data::InfoData,
    infos::{InfoKind, LinkInfo},
    vlan::{InfoVlan, VlanFlags, VlanQosMapping},
};
