// SPDX-License-Identifier: MIT

mod bond;
mod bond_port;
mod bridge;
mod bridge_port;
mod geneve;
mod gre;
mod gtp;
mod hsr;
mod info_data;
mod info_port;
mod infos;
mod ipoib;
mod ipvlan;
mod mac_vlan;
mod macsec;
mod sit;
mod tun;
mod veth;
mod vlan;
mod vrf;
mod vti;
mod vxlan;
mod xfrm;
mod xstats;

pub(crate) use self::infos::VecLinkInfo;
pub use self::{
    bond::{
        BondAdInfo, BondArpAllTargets, BondArpValidate, BondFailOverMac,
        BondMode, BondPrimaryReselect, BondXmitHashPolicy, InfoBond,
    },
    bond_port::{BondPortState, InfoBondPort, MiiStatus},
    bridge::{BridgeId, BridgeIdBuffer, BridgeQuerierState, InfoBridge},
    bridge_port::{BridgePortMulticastRouter, BridgePortState, InfoBridgePort},
    geneve::{GeneveDf, InfoGeneve},
    gre::{GreEncapFlags, GreEncapType, GreIOFlags, InfoGre, InfoGre6},
    gtp::InfoGtp,
    hsr::{HsrProtocol, InfoHsr},
    info_data::InfoData,
    info_port::{InfoPortData, InfoPortKind, InfoVrfPort},
    infos::{InfoKind, LinkInfo},
    ipoib::InfoIpoib,
    ipvlan::{
        InfoIpVlan, InfoIpVtap, IpVlanFlags, IpVlanMode, IpVtapFlags,
        IpVtapMode,
    },
    mac_vlan::{InfoMacVlan, InfoMacVtap, MacVlanMode, MacVtapMode},
    macsec::{InfoMacSec, MacSecCipherId, MacSecOffload, MacSecValidate},
    sit::InfoSitTun,
    tun::InfoTun,
    veth::InfoVeth,
    vlan::{InfoVlan, VlanQosMapping},
    vrf::InfoVrf,
    vti::InfoVti,
    vxlan::InfoVxlan,
    xfrm::InfoXfrm,
    xstats::LinkXstats,
};
