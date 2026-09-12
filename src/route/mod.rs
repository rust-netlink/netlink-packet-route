// SPDX-License-Identifier: MIT

mod address;
mod attribute;
mod cache_info;
mod flags;
mod header;
mod ioam6;
mod lwtunnel;
mod message;
pub(crate) mod metrics;
mod mfc_stats;
mod mpls;
mod next_hops;
mod preference;
mod realm;
mod rpl;
mod seg6;
mod seg6local;
mod tunnel_opts;
mod via;

#[cfg(test)]
mod tests;

pub use flags::RouteFlags;

pub use self::{
    address::RouteAddress,
    attribute::RouteAttribute,
    cache_info::{RouteCacheInfo, RouteCacheInfoBuffer},
    header::{
        RouteHeader, RouteMessageBuffer, RouteProtocol, RouteScope, RouteType,
    },
    ioam6::{Ioam6Mode, Ioam6TraceHdr, RouteIoam6Tunnel},
    lwtunnel::{
        RouteIp6Tunnel, RouteIp6TunnelFlags, RouteIpTunnel, RouteIpTunnelFlags,
        RouteLwEnCapType, RouteLwTunnelEncap, RouteXfrmTunnel,
    },
    message::RouteMessage,
    metrics::RouteMetric,
    mfc_stats::{RouteMfcStats, RouteMfcStatsBuffer},
    mpls::{MplsLabel, RouteMplsIpTunnel, RouteMplsTtlPropagation},
    next_hops::{RouteNextHop, RouteNextHopBuffer, RouteNextHopFlags},
    preference::RoutePreference,
    realm::RouteRealm,
    rpl::{RouteRplIpTunnel, RplSrh},
    seg6::{RouteSeg6IpTunnel, Seg6Header, Seg6Mode},
    seg6local::{RouteSeg6LocalTunnel, Seg6LocalAction, Seg6LocalSrh},
    tunnel_opts::{RouteErspanOpt, RouteGeneveOpt, RouteLwTunnelOpt},
    via::{RouteVia, RouteViaBuffer},
};
