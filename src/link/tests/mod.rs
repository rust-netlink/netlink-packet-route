// SPDX-License-Identifier: MIT
//
// Test modules are gated by content, not blanket-disabled per OS:
//  - tests exercising Linux-only types/messages are gated to Linux;
//  - OS-neutral tests (including message, dpll_pin, inet, sriov and xdp) run
//    everywhere;
//  - mixed modules gate individual tests/imports, and FreeBSD-specific tests
//    live in `freebsd.rs`.

#[cfg(target_os = "linux")]
mod afspec;
#[cfg(target_os = "linux")]
mod amt;
#[cfg(target_os = "linux")]
mod bareudp;
#[cfg(target_os = "linux")]
mod batadv;
#[cfg(target_os = "linux")]
mod bond;
#[cfg(target_os = "linux")]
mod bridge;
#[cfg(target_os = "linux")]
mod can;
mod dpll_pin;
#[cfg(all(test, target_os = "freebsd"))]
mod freebsd;
#[cfg(target_os = "linux")]
mod geneve;
#[cfg(target_os = "linux")]
mod gre;
#[cfg(target_os = "linux")]
mod gtp;
#[cfg(target_os = "linux")]
mod hsr;
mod inet;
#[cfg(target_os = "linux")]
mod ipoib;
#[cfg(target_os = "linux")]
mod iptunnel;
#[cfg(target_os = "linux")]
mod ipvlan;
#[cfg(target_os = "linux")]
mod ipvtap;
#[cfg(target_os = "linux")]
mod loopback;
#[cfg(target_os = "linux")]
mod macsec;
#[cfg(target_os = "linux")]
mod macvlan;
#[cfg(target_os = "linux")]
mod macvtap;
#[cfg(test)]
mod message;
#[cfg(target_os = "linux")]
mod netdevsim;
#[cfg(target_os = "linux")]
mod netkit;
#[cfg(target_os = "linux")]
mod pfcp;
mod prop_list;
#[cfg(target_os = "linux")]
mod rmnet;
#[cfg(test)]
mod sriov;
#[cfg(target_os = "linux")]
mod statistics;
#[cfg(target_os = "linux")]
mod vcan;
#[cfg(target_os = "linux")]
mod veth;
#[cfg(target_os = "linux")]
mod vlan;
#[cfg(target_os = "linux")]
mod vrf;
#[cfg(target_os = "linux")]
mod vti;
#[cfg(target_os = "linux")]
mod vxcan;
#[cfg(target_os = "linux")]
mod vxlan;
#[cfg(target_os = "linux")]
mod wireguard;
#[cfg(target_os = "linux")]
mod wireless;
#[cfg(target_os = "linux")]
mod wwan;
#[cfg(test)]
mod xdp;
#[cfg(target_os = "linux")]
mod xfrm;
