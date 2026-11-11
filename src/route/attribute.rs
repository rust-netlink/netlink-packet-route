// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u16_be, append_u32, append_u32_be, append_u64,
    parse_u16, parse_u16_be, parse_u32, parse_u32_be, parse_u64, parse_u8,
    DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, ParseableParametrized, NLA_F_NESTED,
};

use super::{
    super::AddressFamily, mpls::VecMplsLabel,
    next_hops::parse_multipath_next_hops, MplsLabel, RouteAddress,
    RouteCacheInfo, RouteIp6Tunnel, RouteIpTunnel, RouteLwEnCapType,
    RouteLwTunnelEncap, RouteMetric, RouteMfcStats, RouteMplsTtlPropagation,
    RouteNextHop, RoutePreference, RouteRealm, RouteType, RouteVia,
};
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_METRICS: u16 = 8;
const RTA_MULTIPATH: u16 = 9;
// const RTA_PROTOINFO: u16 = 10; // linux kernel said `no longer used`
const RTA_FLOW: u16 = 11;
const RTA_CACHEINFO: u16 = 12;
// const RTA_SESSION: u16 = 13; // linux kernel said `no longer used`
// const RTA_MP_ALGO: u16 = 14; // linux kernel said `no longer used`
const RTA_TABLE: u16 = 15;
const RTA_MARK: u16 = 16;
const RTA_MFC_STATS: u16 = 17;
const RTA_VIA: u16 = 18;
const RTA_NEWDST: u16 = 19;
const RTA_PREF: u16 = 20;
pub(crate) const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const RTA_EXPIRES: u16 = 23;
const RTA_UID: u16 = 25;
const RTA_TTL_PROPAGATE: u16 = 26;
const RTA_IP_PROTO: u16 = 27;
const RTA_SPORT: u16 = 28;
const RTA_DPORT: u16 = 29;
const RTA_NH_ID: u16 = 30;
const RTA_FLOWLABEL: u16 = 31;

/// Netlink attributes for `RTM_NEWROUTE`, `RTM_DELROUTE`,
/// `RTM_GETROUTE` netlink messages.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteAttribute {
    Metrics(Vec<RouteMetric>),
    MfcStats(RouteMfcStats),
    MultiPath(Vec<RouteNextHop>),
    CacheInfo(RouteCacheInfo),
    Destination(RouteAddress),
    Source(RouteAddress),
    Gateway(RouteAddress),
    PrefSource(RouteAddress),
    Via(RouteVia),
    /// Only for MPLS for destination label(u32) to forward the packet with
    NewDestination(Vec<MplsLabel>),
    /// The `as ADDRESS` address of `ip route get`, the address is packed as
    /// a raw address instead of MPLS labels
    NewDestinationAddress(RouteAddress),
    Preference(RoutePreference),
    EncapType(RouteLwEnCapType),
    Encap(Vec<RouteLwTunnelEncap>),
    // The RTA_EXPIRES holds different data type in kernel 6.5.8.
    // For non-multipath route, it is u32 and only used for modifying routes.
    // For multipath route, it is u64 for querying only.
    /// This is only for non-multicast route
    Expires(u32),
    /// This is only for multicast route
    MulticastExpires(u64),
    Uid(u32),
    TtlPropagate(RouteMplsTtlPropagation),
    Iif(u32),
    Oif(u32),
    Priority(u32),
    /// IPv4 Realm
    Realm(RouteRealm),
    Table(u32),
    Mark(u32),
    IpProto(u8),
    Sport(u16),
    Dport(u16),
    Flowlabel(u32),
    NhId(u32),
    Other(DefaultNla),
}

impl Nla for RouteAttribute {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Destination(addr)
            | Self::PrefSource(addr)
            | Self::Source(addr)
            | Self::Gateway(addr) => addr.emit(out)?,
            Self::Via(v) => v.emit(out)?,
            Self::NewDestination(v) => {
                for label in v {
                    label.emit(out)?;
                }
            }
            Self::NewDestinationAddress(v) => v.emit(out)?,

            Self::Encap(nlas) => (nlas).emit(out)?,
            Self::TtlPropagate(v) => out.push(u8::from(*v)),
            Self::Preference(p) => out.push((*p).into()),
            Self::CacheInfo(cache_info) => cache_info.emit(out)?,
            Self::MfcStats(stats) => stats.emit(out)?,
            Self::Metrics(metrics) => (metrics).emit(out)?,
            Self::MultiPath(next_hops) => {
                for nh in next_hops {
                    nh.emit(out)?;
                }
            }
            Self::EncapType(v) => v.emit(out)?,
            Self::Uid(value)
            | Self::Expires(value)
            | Self::Iif(value)
            | Self::Oif(value)
            | Self::Priority(value)
            | Self::Table(value)
            | Self::Mark(value) => append_u32(out, *value),
            Self::Realm(v) => v.emit(out)?,
            Self::MulticastExpires(value) => append_u64(out, *value),
            Self::IpProto(value) => out.push(*value),
            Self::Sport(value) | Self::Dport(value) => {
                append_u16_be(out, *value)
            }
            // RTA_FLOWLABEL is a NLA_BE32 attribute while RTA_NH_ID is a
            // host endian one.
            Self::Flowlabel(value) => append_u32_be(out, *value),
            Self::NhId(value) => append_u32(out, *value),
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Destination(_) => RTA_DST,
            Self::Source(_) => RTA_SRC,
            Self::Iif(_) => RTA_IIF,
            Self::Oif(_) => RTA_OIF,
            Self::Gateway(_) => RTA_GATEWAY,
            Self::Priority(_) => RTA_PRIORITY,
            Self::PrefSource(_) => RTA_PREFSRC,
            Self::Metrics(_) => RTA_METRICS,
            Self::MultiPath(_) => RTA_MULTIPATH,
            Self::Realm(_) => RTA_FLOW,
            Self::CacheInfo(_) => RTA_CACHEINFO,
            Self::Table(_) => RTA_TABLE,
            Self::Mark(_) => RTA_MARK,
            Self::MfcStats(_) => RTA_MFC_STATS,
            Self::Via(_) => RTA_VIA,
            Self::NewDestination(_) => RTA_NEWDST,
            Self::NewDestinationAddress(_) => RTA_NEWDST,
            Self::Preference(_) => RTA_PREF,
            Self::EncapType(_) => RTA_ENCAP_TYPE,
            Self::Encap(encap) => {
                // The kernel validates these encapsulation types with
                // `nla_parse_nested()` which rejects a missing
                // `NLA_F_NESTED` flag, `iproute2` always sets the flag on
                // `RTA_ENCAP`.
                if encap.iter().any(|e| {
                    matches!(
                        e,
                        RouteLwTunnelEncap::Seg6(_)
                            | RouteLwTunnelEncap::Xfrm(_)
                            | RouteLwTunnelEncap::Rpl(_)
                            | RouteLwTunnelEncap::Ioam6(_)
                            | RouteLwTunnelEncap::Ip(RouteIpTunnel::Opts(_))
                            | RouteLwTunnelEncap::Ip6(RouteIp6Tunnel::Opts(_))
                    )
                }) {
                    RTA_ENCAP | NLA_F_NESTED
                } else {
                    RTA_ENCAP
                }
            }
            Self::Expires(_) => RTA_EXPIRES,
            Self::MulticastExpires(_) => RTA_EXPIRES,
            Self::Uid(_) => RTA_UID,
            Self::TtlPropagate(_) => RTA_TTL_PROPAGATE,
            Self::IpProto(_) => RTA_IP_PROTO,
            Self::Sport(_) => RTA_SPORT,
            Self::Dport(_) => RTA_DPORT,
            Self::Flowlabel(_) => RTA_FLOWLABEL,
            Self::NhId(_) => RTA_NH_ID,
            Self::Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a>
    ParseableParametrized<
        NlaBuffer<'a>,
        (AddressFamily, RouteType, RouteLwEnCapType),
    > for RouteAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<'a>,
        (address_family, route_type, encap_type): (
            AddressFamily,
            RouteType,
            RouteLwEnCapType,
        ),
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            RTA_DST => {
                Self::Destination(RouteAddress::parse(address_family, payload)?)
            }
            RTA_SRC => {
                Self::Source(RouteAddress::parse(address_family, payload)?)
            }
            RTA_GATEWAY => {
                Self::Gateway(RouteAddress::parse(address_family, payload)?)
            }
            RTA_PREFSRC => {
                Self::PrefSource(RouteAddress::parse(address_family, payload)?)
            }
            RTA_VIA => {
                Self::Via(RouteVia::parse(payload).with_context(|| {
                    format!("Invalid RTA_VIA value {payload:?}")
                })?)
            }
            RTA_NEWDST => {
                // `RTA_NEWDST` holds a MPLS label stack for MPLS routes and
                // a plain address for `ip route get ADDR as ADDR`. The
                // `Mpls` address family only exists on the Linux and Fuchsia
                // targets.
                #[cfg(any(target_os = "linux", target_os = "fuchsia"))]
                let mpls = address_family == AddressFamily::Mpls;
                #[cfg(not(any(target_os = "linux", target_os = "fuchsia")))]
                let mpls = false;
                if mpls {
                    Self::NewDestination(
                        VecMplsLabel::parse(payload)
                            .with_context(|| {
                                format!("Invalid RTA_NEWDST value {payload:?}")
                            })?
                            .0,
                    )
                } else {
                    Self::NewDestinationAddress(RouteAddress::parse(
                        address_family,
                        payload,
                    )?)
                }
            }

            RTA_PREF => Self::Preference(parse_u8(payload)?.into()),
            RTA_ENCAP => Self::Encap(
                Vec::<RouteLwTunnelEncap>::parse_with_param(buf, encap_type)
                    .with_context(|| {
                        format!("Invalid RTA_ENCAP for kind: {encap_type}")
                    })?,
            ),
            RTA_EXPIRES => {
                if route_type == RouteType::Multicast {
                    Self::MulticastExpires(parse_u64(payload).with_context(
                        || {
                            format!(
                                "invalid RTA_EXPIRES (multicast) value \
                                 {payload:?}"
                            )
                        },
                    )?)
                } else {
                    Self::Expires(parse_u32(payload).with_context(|| {
                        format!("invalid RTA_EXPIRES value {payload:?}")
                    })?)
                }
            }
            RTA_UID => Self::Uid(parse_u32(payload).with_context(|| {
                format!("invalid RTA_UID value {payload:?}")
            })?),
            RTA_TTL_PROPAGATE => Self::TtlPropagate(
                RouteMplsTtlPropagation::from(parse_u8(payload).with_context(
                    || format!("invalid RTA_TTL_PROPAGATE {payload:?}"),
                )?),
            ),
            RTA_ENCAP_TYPE => Self::EncapType(RouteLwEnCapType::from(
                parse_u16(payload).context("invalid RTA_ENCAP_TYPE value")?,
            )),
            RTA_IIF => {
                Self::Iif(parse_u32(payload).context("invalid RTA_IIF value")?)
            }
            RTA_OIF => {
                Self::Oif(parse_u32(payload).context("invalid RTA_OIF value")?)
            }
            RTA_PRIORITY => Self::Priority(
                parse_u32(payload).context("invalid RTA_PRIORITY value")?,
            ),
            RTA_FLOW => Self::Realm(
                RouteRealm::parse(payload).context("invalid RTA_FLOW value")?,
            ),
            RTA_TABLE => Self::Table(
                parse_u32(payload).context("invalid RTA_TABLE value")?,
            ),
            RTA_MARK => Self::Mark(
                parse_u32(payload).context("invalid RTA_MARK value")?,
            ),

            RTA_CACHEINFO => Self::CacheInfo(
                RouteCacheInfo::parse(payload)
                    .context("invalid RTA_CACHEINFO value")?,
            ),
            RTA_MFC_STATS => Self::MfcStats(
                RouteMfcStats::parse(payload)
                    .context("invalid RTA_MFC_STATS value")?,
            ),
            RTA_METRICS => Self::Metrics(
                Vec::<RouteMetric>::parse(buf)
                    .context("invalid RTA_METRICS value")?,
            ),
            RTA_MULTIPATH => Self::MultiPath(
                parse_multipath_next_hops(
                    payload,
                    (address_family, route_type, encap_type),
                )
                .context("invalid RTA_MULTIPATH value")?,
            ),
            RTA_IP_PROTO => Self::IpProto(
                parse_u8(payload).context("invalid RTA_IP_PROTO value")?,
            ),
            RTA_SPORT => Self::Sport(
                parse_u16_be(payload).context("invalid RTA_SPORT value")?,
            ),
            RTA_DPORT => Self::Dport(
                parse_u16_be(payload).context("invalid RTA_DPORT value")?,
            ),
            RTA_FLOWLABEL => Self::Flowlabel(
                parse_u32_be(payload).context("invalid RTA_FLOWLABEL value")?,
            ),
            RTA_NH_ID => Self::NhId(
                parse_u32(payload).context("invalid RTA_NH_ID value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

pub(crate) struct VecRouteAttribute(pub(crate) Vec<RouteAttribute>);

impl ParseableParametrized<[u8], (AddressFamily, RouteType)>
    for VecRouteAttribute
{
    fn parse_with_param(
        buf: &[u8],
        (address_family, route_type): (AddressFamily, RouteType),
    ) -> Result<Self, DecodeError> {
        let mut encap_type = RouteLwEnCapType::None;
        // The RTA_ENCAP_TYPE is provided __after__ RTA_ENCAP, we should find
        // RTA_ENCAP_TYPE first.
        let nlas = NlasIterator::new(buf)?.collect::<Vec<_>>();
        for nla in &nlas {
            if nla.kind() == RTA_ENCAP_TYPE {
                if let Ok(RouteAttribute::EncapType(v)) =
                    RouteAttribute::parse_with_param(
                        nla,
                        (address_family, route_type, encap_type),
                    )
                {
                    encap_type = v;
                    break;
                }
            }
        }
        let mut attributes = vec![];
        for nla in &nlas {
            attributes.push(RouteAttribute::parse_with_param(
                nla,
                (address_family, route_type, encap_type),
            )?);
        }
        Ok(Self(attributes))
    }
}

impl ParseableParametrized<[u8], (AddressFamily, RouteType, RouteLwEnCapType)>
    for VecRouteAttribute
{
    fn parse_with_param(
        buf: &[u8],
        (address_family, route_type, encap_type): (
            AddressFamily,
            RouteType,
            RouteLwEnCapType,
        ),
    ) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in NlasIterator::new(buf)? {
            nlas.push(RouteAttribute::parse_with_param(
                &nla_buf,
                (address_family, route_type, encap_type),
            )?);
        }
        Ok(Self(nlas))
    }
}
