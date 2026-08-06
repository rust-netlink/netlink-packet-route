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
mod tun;
mod veth;
mod vlan;
mod vrf;
mod vti;
mod vxcan;
mod vxlan;
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
        BridgeId, BridgeIdBuffer, BridgeMulticastRouterType,
        BridgeQuerierState, BridgeStpState, InfoBridge,
    },
    bridge_boolopt::{BridgeBooleanOptionFlags, BridgeBooleanOptions},
    bridge_port::{BridgePortState, InfoBridgePort},
    can::{
        CanBerrCounter, CanBitTiming, CanBitTimingConst, CanClock, CanCtrlMode,
        CanCtrlModeFlags, CanTdc, InfoCan,
    },
    dsa::InfoDsa,
    geneve::{GeneveDf, InfoGeneve},
    gre::{GreEncapFlags, GreEncapType, GreIOFlags, InfoGre, InfoGre6},
    gtp::{GtpRole, InfoGtp},
    hsr::{HsrProtocol, InfoHsr},
    info_data::InfoData,
    info_port::{InfoPortData, InfoPortKind, InfoVrfPort},
    infos::{InfoKind, LinkInfo},
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
    tun::InfoTun,
    veth::InfoVeth,
    vlan::{InfoVlan, VlanFlags, VlanQosMapping},
    vrf::InfoVrf,
    vti::InfoVti,
    vxcan::InfoVxcan,
    vxlan::{InfoVxlan, VxlanDf},
    wwan::InfoWwan,
    xfrm::InfoXfrm,
    xstats::LinkXstats,
};
