// SPDX-License-Identifier: MIT

#[cfg(target_os = "linux")]
mod cache_info;
#[cfg(target_os = "linux")]
mod expires;
#[cfg(all(test, target_os = "freebsd"))]
mod freebsd;
#[cfg(test)]
mod ip6_tunnel;
#[cfg(test)]
mod loopback;
#[cfg(test)]
mod metrics;
#[cfg(target_os = "linux")]
mod mpls;
#[cfg(test)]
mod multipath;
#[cfg(test)]
mod realm;
#[cfg(test)]
mod route_flags;
#[cfg(target_os = "linux")]
mod seg6;
#[cfg(test)]
mod uid;
#[cfg(target_os = "linux")]
mod via;
