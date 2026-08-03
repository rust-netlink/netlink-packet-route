// SPDX-License-Identifier: MIT

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_MPLS_UC: u16 = 0x8847;
const ETH_P_MPLS_MC: u16 = 0x8848;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum EthernetProtocol {
    Ip,
    Ipv6,
    MplsUc,
    MplsMc,
    Other(u16),
}

impl EthernetProtocol {
    pub fn value(&self) -> u16 {
        match self {
            Self::Ip => ETH_P_IP,
            Self::Ipv6 => ETH_P_IPV6,
            Self::MplsUc => ETH_P_MPLS_UC,
            Self::MplsMc => ETH_P_MPLS_MC,
            Self::Other(v) => *v,
        }
    }
}

impl From<u16> for EthernetProtocol {
    fn from(d: u16) -> Self {
        match d {
            ETH_P_IP => Self::Ip,
            ETH_P_IPV6 => Self::Ipv6,
            ETH_P_MPLS_UC => Self::MplsUc,
            ETH_P_MPLS_MC => Self::MplsMc,
            _ => Self::Other(d),
        }
    }
}

impl From<EthernetProtocol> for u16 {
    fn from(v: EthernetProtocol) -> u16 {
        v.value()
    }
}

impl std::fmt::Display for EthernetProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip => write!(f, "ip"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::MplsUc => write!(f, "mpls_uc"),
            Self::MplsMc => write!(f, "mpls_mc"),
            Self::Other(v) => write!(f, "{v:#x}"),
        }
    }
}
