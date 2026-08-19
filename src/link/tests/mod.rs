// SPDX-License-Identifier: MIT

#[cfg(feature = "link-af-spec")]
mod afspec;
#[cfg(feature = "link-info")]
mod amt;
#[cfg(feature = "link-info")]
mod bareudp;
#[cfg(feature = "link-info")]
mod batadv;
#[cfg(feature = "link-info")]
mod bond;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod bridge;
#[cfg(feature = "link-info")]
mod can;
mod dpll_pin;
#[cfg(feature = "link-info")]
mod geneve;
#[cfg(feature = "link-info")]
mod gre;
#[cfg(feature = "link-info")]
mod gtp;
#[cfg(feature = "link-info")]
mod hsr;
#[cfg(feature = "link-af-spec")]
mod inet;
#[cfg(feature = "link-info")]
mod ipoib;
#[cfg(feature = "link-info")]
mod iptunnel;
#[cfg(feature = "link-info")]
mod ipvlan;
#[cfg(feature = "link-info")]
mod ipvtap;
#[cfg(feature = "link-af-spec")]
mod loopback;
#[cfg(feature = "link-info")]
mod macsec;
#[cfg(feature = "link-info")]
mod macvlan;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod macvtap;
mod message;
#[cfg(all(feature = "link-af-spec", feature = "link-sriov"))]
mod netdevsim;
#[cfg(feature = "link-info")]
mod netkit;
#[cfg(feature = "link-info")]
mod pfcp;
mod prop_list;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod rmnet;
#[cfg(feature = "link-sriov")]
mod sriov;
#[cfg(feature = "link-af-spec")]
mod statistics;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod vcan;
#[cfg(feature = "link-info")]
mod veth;
#[cfg(feature = "link-info")]
mod vlan;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod vrf;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod vti;
#[cfg(feature = "link-info")]
mod vxcan;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod vxlan;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod wireguard;
mod wireless;
#[cfg(all(feature = "link-af-spec", feature = "link-info"))]
mod wwan;
mod xdp;
#[cfg(feature = "link-info")]
mod xfrm;
