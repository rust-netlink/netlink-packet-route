// SPDX-License-Identifier: MIT
use super::RouteLwEnCapType;
use netlink_packet_utils::{nla::NlaError, DecodeError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("Invalid {kind} value")]
    InvalidValue {
        kind: &'static str,
        #[source]
        error: DecodeError,
    },

    #[error("cannot parse route attributes in next-hop")]
    ParseNextHopAttributes(#[source] DecodeError),

    #[error("Invalid RTA_ENCAP for kind: {kind}")]
    InvalidRtaEncap {
        kind: RouteLwEnCapType,
        error: NlaError,
    },

    #[error("invalid MPLS_IPTUNNEL_DST value")]
    InvalidMplsIpTunnelTtl(#[source] DecodeError),

    #[error("Invalid {kind} value")]
    InvalidRouteMetric {
        kind: &'static str,
        #[source]
        error: DecodeError,
    },

    #[error("Invalid array length. Expected={expected}, got={got}")]
    ParseMplsLabel { expected: usize, got: usize },

    #[error("Expected single u8 for route protocol")]
    ParseRouteProtocol,

    #[error("Invalid rule port range data, expecting {expected} u8 array, but got {got}")]
    InvalidRulePortRange { expected: usize, got: usize },

    #[error(transparent)]
    ParseNla(#[from] NlaError),

    #[error(transparent)]
    Other(#[from] DecodeError),
}
