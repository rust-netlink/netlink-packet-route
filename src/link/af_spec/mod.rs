// SPDX-License-Identifier: MIT

mod bridge;
mod in6_addr_gen_mode;
mod inet;
mod inet6;
mod inet6_cache;
mod inet6_devconf;
mod inet6_icmp;
mod inet6_iface_flag;
mod inet6_stats;
mod mctp;
mod unspec;

#[cfg(test)]
pub(crate) use self::inet::InetDevConfBuffer;
pub use self::{
    bridge::{
        AfSpecBridge, BridgeFlag, BridgeMode, BridgeVlanInfo,
        BridgeVlanInfoFlags, BridgeVlanTunnelInfo,
    },
    in6_addr_gen_mode::In6AddrGenMode,
    inet::{AfSpecInet, InetDevConf},
    inet6::AfSpecInet6,
    inet6_cache::Inet6CacheInfo,
    inet6_devconf::Inet6DevConf,
    inet6_icmp::Icmp6Stats,
    inet6_iface_flag::Inet6IfaceFlags,
    inet6_stats::Inet6Stats,
    mctp::{AfSpecMctp, MctpPhysBinding},
    unspec::AfSpecUnspec,
};
pub(crate) use self::{
    inet6_devconf::Inet6DevConfBuffer, inet6_icmp::Icmp6StatsBuffer,
    inet6_stats::Inet6StatsBuffer,
};
