// SPDX-License-Identifier: MIT

const IPV6_SRCRT_TYPE_0: u8 = 0;
const IPV6_SRCRT_TYPE_2: u8 = 2;
const IPV6_SRCRT_TYPE_3: u8 = 3;
const IPV6_SRCRT_TYPE_4: u8 = 4;

/// IPv6 routing header type, the `routing_type` field of the Segment Routing
/// and RPL headers.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Ipv6RoutingType {
    /// Deprecated type 0 routing header.
    #[default]
    Type0,
    /// Type 2 routing header.
    Type2,
    /// RPL source routing header, `IPV6_SRCRT_TYPE_3`.
    Rpl,
    /// Segment Routing header, `IPV6_SRCRT_TYPE_4`.
    SegmentRouting,
    Other(u8),
}

impl From<u8> for Ipv6RoutingType {
    fn from(d: u8) -> Self {
        match d {
            IPV6_SRCRT_TYPE_0 => Self::Type0,
            IPV6_SRCRT_TYPE_2 => Self::Type2,
            IPV6_SRCRT_TYPE_3 => Self::Rpl,
            IPV6_SRCRT_TYPE_4 => Self::SegmentRouting,
            _ => Self::Other(d),
        }
    }
}

impl From<Ipv6RoutingType> for u8 {
    fn from(v: Ipv6RoutingType) -> u8 {
        match v {
            Ipv6RoutingType::Type0 => IPV6_SRCRT_TYPE_0,
            Ipv6RoutingType::Type2 => IPV6_SRCRT_TYPE_2,
            Ipv6RoutingType::Rpl => IPV6_SRCRT_TYPE_3,
            Ipv6RoutingType::SegmentRouting => IPV6_SRCRT_TYPE_4,
            Ipv6RoutingType::Other(d) => d,
        }
    }
}

impl std::fmt::Display for Ipv6RoutingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Type0 => f.write_str("0"),
            Self::Type2 => f.write_str("2"),
            Self::Rpl => f.write_str("3"),
            Self::SegmentRouting => f.write_str("4"),
            Self::Other(d) => write!(f, "{d}"),
        }
    }
}
