// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_string, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, ParseableParametrized,
};

use super::*;

const DUMMY: &str = "dummy";
const IFB: &str = "ifb";
const NLMON: &str = "nlmon";
const VETH: &str = "veth";
const BOND: &str = "bond";
const IPVLAN: &str = "ipvlan";
const IPVTAP: &str = "ipvtap";
const MACVLAN: &str = "macvlan";
const MACVTAP: &str = "macvtap";
const GRETAP: &str = "gretap";
const IP6GRETAP: &str = "ip6gretap";
const IPIP: &str = "ipip";
const IP6TNL: &str = "ip6tnl";
const SIT: &str = "sit";
const IP6GRE: &str = "ip6gre";
const VTI: &str = "vti";
const VRF: &str = "vrf";
const GTP: &str = "gtp";
const IPOIB: &str = "ipoib";
const XFRM: &str = "xfrm";
const MACSEC: &str = "macsec";
const HSR: &str = "hsr";
const GENEVE: &str = "geneve";
const NETKIT: &str = "netkit";

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoKind {
    Dummy,
    Ifb,
    Bridge,
    Tun,
    Nlmon,
    Vlan,
    Veth,
    Vxlan,
    Bond,
    IpVlan,
    IpVtap,
    MacVlan,
    MacVtap,
    GreTap,
    GreTap6,
    IpIp,
    Ip6Tnl,
    SitTun,
    GreTun,
    GreTun6,
    Vti,
    Vrf,
    Gtp,
    Ipoib,
    Wireguard,
    Xfrm,
    MacSec,
    Hsr,
    Geneve,
    Netkit,
    Other(String),
}

impl std::fmt::Display for InfoKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Dummy => DUMMY,
                Self::Ifb => IFB,
                Self::Bridge => BRIDGE,
                Self::Tun => TUN,
                Self::Nlmon => NLMON,
                Self::Vlan => VLAN,
                Self::Veth => VETH,
                Self::Vxlan => VXLAN,
                Self::Bond => BOND,
                Self::IpVlan => IPVLAN,
                Self::IpVtap => IPVTAP,
                Self::MacVlan => MACVLAN,
                Self::MacVtap => MACVTAP,
                Self::GreTap => GRETAP,
                Self::GreTap6 => IP6GRETAP,
                Self::IpIp => IPIP,
                Self::Ip6Tnl => IP6TNL,
                Self::SitTun => SIT,
                Self::GreTun => GRE,
                Self::GreTun6 => IP6GRE,
                Self::Vti => VTI,
                Self::Vrf => VRF,
                Self::Gtp => GTP,
                Self::Ipoib => IPOIB,
                Self::Wireguard => WIREGUARD,
                Self::Xfrm => XFRM,
                Self::MacSec => MACSEC,
                Self::Hsr => HSR,
                Self::Geneve => GENEVE,
                Self::Netkit => NETKIT,
                Self::Other(s) => s.as_str(),
            }
        )
    }
}

impl Nla for InfoKind {
    fn value_len(&self) -> usize {
        let len = match self {
            Self::Dummy => DUMMY.len(),
            Self::Ifb => IFB.len(),
            Self::Bridge => BRIDGE.len(),
            Self::Tun => TUN.len(),
            Self::Nlmon => NLMON.len(),
            Self::Vlan => VLAN.len(),
            Self::Veth => VETH.len(),
            Self::Vxlan => VXLAN.len(),
            Self::Bond => BOND.len(),
            Self::IpVlan => IPVLAN.len(),
            Self::IpVtap => IPVTAP.len(),
            Self::MacVlan => MACVLAN.len(),
            Self::MacVtap => MACVTAP.len(),
            Self::GreTap => GRETAP.len(),
            Self::GreTap6 => IP6GRETAP.len(),
            Self::IpIp => IPIP.len(),
            Self::Ip6Tnl => IP6TNL.len(),
            Self::SitTun => SIT.len(),
            Self::GreTun => GRE.len(),
            Self::GreTun6 => IP6GRE.len(),
            Self::Vti => VTI.len(),
            Self::Vrf => VRF.len(),
            Self::Gtp => GTP.len(),
            Self::Ipoib => IPOIB.len(),
            Self::Wireguard => WIREGUARD.len(),
            Self::Xfrm => XFRM.len(),
            Self::MacSec => MACSEC.len(),
            Self::Hsr => HSR.len(),
            Self::Geneve => GENEVE.len(),
            Self::Netkit => NETKIT.len(),
            Self::Other(s) => s.len(),
        };
        len + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let kind = self.to_string();
        let s = kind.as_str();
        buffer[..s.len()].copy_from_slice(s.to_string().as_bytes());
        buffer[s.len()] = 0;
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_KIND
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoKind {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<InfoKind, DecodeError> {
        if buf.kind() != IFLA_INFO_KIND {
            return Err(format!(
                "failed to parse IFLA_INFO_KIND: NLA type is {}",
                buf.kind()
            )
            .into());
        }
        let s = parse_string(buf.value())
            .context("invalid IFLA_INFO_KIND value")?;
        Ok(match s.as_str() {
            DUMMY => Self::Dummy,
            IFB => Self::Ifb,
            BRIDGE => Self::Bridge,
            TUN => Self::Tun,
            NLMON => Self::Nlmon,
            VLAN => Self::Vlan,
            VETH => Self::Veth,
            VXLAN => Self::Vxlan,
            BOND => Self::Bond,
            IPVLAN => Self::IpVlan,
            IPVTAP => Self::IpVtap,
            MACVLAN => Self::MacVlan,
            MACVTAP => Self::MacVtap,
            GRETAP => Self::GreTap,
            IP6GRETAP => Self::GreTap6,
            IPIP => Self::IpIp,
            IP6TNL => Self::Ip6Tnl,
            SIT => Self::SitTun,
            GRE => Self::GreTun,
            IP6GRE => Self::GreTun6,
            VTI => Self::Vti,
            VRF => Self::Vrf,
            GTP => Self::Gtp,
            IPOIB => Self::Ipoib,
            WIREGUARD => Self::Wireguard,
            MACSEC => Self::MacSec,
            XFRM => Self::Xfrm,
            HSR => Self::Hsr,
            GENEVE => Self::Geneve,
            NETKIT => Self::Netkit,
            _ => Self::Other(s),
        })
    }
}
