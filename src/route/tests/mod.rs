// SPDX-License-Identifier: MIT

#[cfg(test)]
mod cache_info;
#[cfg(test)]
mod expires;
#[cfg(test)]
mod ip6_tunnel;
#[cfg(test)]
mod loopback;
#[cfg(all(test, not(target_os = "freebsd")))]
mod mpls;
#[cfg(test)]
mod multipath;
#[cfg(test)]
mod realm;
#[cfg(test)]
mod route_flags;
#[cfg(test)]
mod seg6;
#[cfg(test)]
mod uid;
#[cfg(test)]
mod via;
