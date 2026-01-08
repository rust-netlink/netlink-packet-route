// SPDX-License-Identifier: MIT

#[cfg(all(test, not(target_os = "freebsd")))]
mod afspec;
#[cfg(all(test, not(target_os = "freebsd")))]
mod bond;
#[cfg(all(test, not(target_os = "freebsd")))]
mod bridge;
#[cfg(test)]
mod freebsd;
#[cfg(all(test, not(target_os = "freebsd")))]
mod geneve;
#[cfg(all(test, not(target_os = "freebsd")))]
mod gre;
#[cfg(all(test, not(target_os = "freebsd")))]
mod hsr;
#[cfg(all(test, not(target_os = "freebsd")))]
mod ipoib;
#[cfg(all(test, not(target_os = "freebsd")))]
mod iptunnel;
#[cfg(all(test, not(target_os = "freebsd")))]
mod ipvlan;
#[cfg(all(test, not(target_os = "freebsd")))]
mod ipvtap;
#[cfg(all(test, not(target_os = "freebsd")))]
mod loopback;
#[cfg(all(test, not(target_os = "freebsd")))]
mod macsec;
#[cfg(all(test, not(target_os = "freebsd")))]
mod macvlan;
#[cfg(all(test, not(target_os = "freebsd")))]
mod macvtap;
#[cfg(test)]
mod message;
#[cfg(all(test, not(target_os = "freebsd")))]
mod netkit;
#[cfg(test)]
mod prop_list;
#[cfg(test)]
mod sriov;
#[cfg(all(test, not(target_os = "freebsd")))]
mod statistics;
#[cfg(all(test, not(target_os = "freebsd")))]
mod veth;
#[cfg(all(test, not(target_os = "freebsd")))]
mod vlan;
#[cfg(all(test, not(target_os = "freebsd")))]
mod vrf;
#[cfg(all(test, not(target_os = "freebsd")))]
mod vxlan;
#[cfg(all(test, not(target_os = "freebsd")))]
mod xdp;
#[cfg(all(test, not(target_os = "freebsd")))]
mod xfrm;
