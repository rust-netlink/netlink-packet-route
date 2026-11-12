// SPDX-License-Identifier: MIT

mod amt;
mod bareudp;
mod batadv;
mod bond;
mod bond_port;
mod bridge;
mod bridge_boolopt;
mod bridge_port;
mod can;
mod dsa;
mod geneve;
mod gre;
mod gtp;
mod hsr;
mod info_data;
mod info_port;
mod infos;
mod ipoib;
mod iptunnel;
mod ipvlan;
mod mac_vlan;
mod macsec;
mod netkit;
mod ovpn;
mod ppp;
mod rmnet;
mod team_port;
mod tun;
mod veth;
mod vlan;
mod vrf;
mod vti;
mod vxcan;
mod vxlan;
mod wireguard;
mod wwan;
mod xfrm;
mod xstats;

pub(crate) use self::infos::VecLinkInfo;
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
        BridgeGroupFwdMask, BridgeId, BridgeMulticastIgmpVersion,
        BridgeMulticastMldVersion, BridgeMulticastRouterType,
        BridgeQuerierState, BridgeStpMode, BridgeStpState, InfoBridge,
    },
    bridge_boolopt::{BridgeBooleanOptionFlags, BridgeBooleanOptions},
    bridge_port::InfoBridgePort,
    can::{
        CanBerrCounter, CanBitTiming, CanBitTimingConst, CanClock, CanCtrlMode,
        CanCtrlModeExt, CanCtrlModeFlags, CanState, CanTdc, InfoCan,
    },
    dsa::InfoDsa,
    geneve::{GeneveDf, InfoGeneve},
    gre::{
        ErSpanDir, GreEncapFlags, GreEncapType, GreIOFlags, InfoGre, InfoGre6,
    },
    gtp::{GtpRole, InfoGtp},
    hsr::{HsrProtocol, HsrVersion, InfoHsr},
    info_data::InfoData,
    info_port::{InfoPortData, InfoPortKind, InfoVrfPort},
    infos::{InfoKind, LinkInfo},
    ipoib::{InfoIpoib, IpoibMode},
    iptunnel::{
        InfoIpTunnel, Ip6TunnelFlags, SitFlags, TunnelEncapFlags,
        TunnelEncapType,
    },
    ipvlan::{
        InfoIpVlan, InfoIpVtap, IpVlanFlags, IpVlanMode, IpVtapFlags,
        IpVtapMode,
    },
    mac_vlan::{
        InfoMacVlan, InfoMacVtap, MacVlanBcCutoff, MacVlanFlags,
        MacVlanMacAddressMode, MacVlanMode, MacVtapFlags,
        MacVtapMacAddressMode, MacVtapMode,
    },
    macsec::{InfoMacSec, MacSecCipherId, MacSecOffload, MacSecValidate},
    netkit::{InfoNetkit, NetkitMode, NetkitPolicy, NetkitScrub},
    ovpn::{InfoOvpn, OvpnMode},
    ppp::InfoPpp,
    rmnet::{InfoRmNet, InfoRmNetFlags, RmNetFlags},
    team_port::InfoTeamPort,
    tun::InfoTun,
    veth::InfoVeth,
    vlan::{InfoVlan, VlanFlags, VlanQosMapping},
    vrf::InfoVrf,
    vti::InfoVti,
    vxcan::InfoVxcan,
    vxlan::{InfoVxlan, VxlanDf, VxlanLabelPolicy},
    wireguard::InfoWireguard,
    wwan::InfoWwan,
    xfrm::InfoXfrm,
    xstats::LinkXstats,
};
