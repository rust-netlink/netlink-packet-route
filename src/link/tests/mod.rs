// SPDX-License-Identifier: MIT

#[cfg(all(test, not(target_os = "freebsd")))]
mod afspec;
#[cfg(test)]
mod bond;
#[cfg(all(test, not(target_os = "freebsd")))]
mod bridge;
#[cfg(test)]
mod geneve;
#[cfg(test)]
mod gre;
#[cfg(test)]
mod hsr;
#[cfg(test)]
mod ipoib;
#[cfg(test)]
mod iptunnel;
#[cfg(test)]
mod ipvlan;
#[cfg(test)]
mod ipvtap;
#[cfg(test)]
mod loopback;
#[cfg(test)]
mod macsec;
#[cfg(test)]
mod macvlan;
#[cfg(all(test, not(target_os = "freebsd")))]
mod macvtap;
#[cfg(test)]
mod message;
#[cfg(test)]
mod netkit;
#[cfg(test)]
mod prop_list;
#[cfg(test)]
mod sriov;
#[cfg(all(test, not(target_os = "freebsd")))]
mod statistics;
#[cfg(test)]
mod veth;
#[cfg(test)]
mod vlan;
#[cfg(test)]
mod vrf;
#[cfg(all(test, not(target_os = "freebsd")))]
mod vxlan;
#[cfg(test)]
mod xdp;
#[cfg(test)]
mod xfrm;
