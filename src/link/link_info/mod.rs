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

pub use self::bond::{
    BondAdInfo, BondArpAllTargets, BondArpValidate, BondFailOverMac, BondMode,
    BondPrimaryReselect, BondXmitHashPolicy, InfoBond,
};
pub use self::bond_port::{BondPortState, InfoBondPort, MiiStatus};
pub use self::bridge::{
    BridgeId, BridgeIdBuffer, BridgeQuerierState, InfoBridge,
};
pub use self::bridge_port::{
    BridgePortMulticastRouter, BridgePortState, InfoBridgePort,
};
pub use self::geneve::{GeneveDf, InfoGeneve};
pub use self::gre::{
    GreEncapFlags, GreEncapType, GreIOFlags, InfoGreTap, InfoGreTap6,
    InfoGreTun, InfoGreTun6,
};
pub use self::gtp::InfoGtp;
pub use self::hsr::{HsrProtocol, InfoHsr};
pub use self::info_data::InfoData;
pub use self::info_port::{InfoPortData, InfoPortKind, InfoVrfPort};
pub use self::infos::{InfoKind, LinkInfo};
pub use self::ipoib::InfoIpoib;
pub use self::ipvlan::{
    InfoIpVlan, InfoIpVtap, IpVlanFlags, IpVlanMode, IpVtapFlags, IpVtapMode,
};
pub use self::mac_vlan::{InfoMacVlan, InfoMacVtap, MacVlanMode, MacVtapMode};
pub use self::macsec::{
    InfoMacSec, MacSecCipherId, MacSecOffload, MacSecValidate,
};
pub use self::sit::InfoSitTun;
pub use self::tun::InfoTun;
pub use self::veth::InfoVeth;
pub use self::vlan::{InfoVlan, VlanQosMapping};
pub use self::vrf::InfoVrf;
pub use self::vti::InfoVti;
pub use self::vxlan::InfoVxlan;
pub use self::xfrm::InfoXfrm;
pub use self::xstats::LinkXstats;

pub(crate) use self::infos::VecLinkInfo;
