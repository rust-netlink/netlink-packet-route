// SPDX-License-Identifier: MIT

pub mod gre_tap;
pub mod gre_tap6;
pub mod gre_tun;
pub mod gre_tun6;

use std::fmt::Display;

pub use self::gre_tap::InfoGreTap;
pub use self::gre_tap6::InfoGreTap6;
pub use self::gre_tun::InfoGreTun;
pub use self::gre_tun6::InfoGreTun6;

const GRE_CSUM: u16 = 0x8000;
const GRE_ROUTING: u16 = 0x4000;
const GRE_KEY: u16 = 0x2000;
const GRE_SEQ: u16 = 0x1000;
const GRE_STRICT: u16 = 0x0800;
const GRE_REC: u16 = 0x0700;
const GRE_ACK: u16 = 0x0080;
const GRE_FLAGS: u16 = 0x0078;
const GRE_VERSION: u16 = 0x0007;

const TUNNEL_ENCAP_FLAG_CSUM: u16 = 0x0100;
const TUNNEL_ENCAP_FLAG_CSUM6: u16 = 0x0200;
const TUNNEL_ENCAP_FLAG_REMCSUM: u16 = 0x0400;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct GreIOFlags: u16 {
        const Checksum = GRE_CSUM;
        const Routing = GRE_ROUTING;
        const Key = GRE_KEY;
        const Seq = GRE_SEQ;
        const Strict0 = GRE_STRICT;
        const Rec = GRE_REC;
        const Ack = GRE_ACK;
        const Flags = GRE_FLAGS;
        const Version = GRE_VERSION;
    }

    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct GreEncapFlags: u16 {
        const Checksum = TUNNEL_ENCAP_FLAG_CSUM;
        const Checksum6 = TUNNEL_ENCAP_FLAG_CSUM6;
        const RemoteChecksum = TUNNEL_ENCAP_FLAG_REMCSUM;
    }
}

const TUNNEL_ENCAP_NONE: u16 = 0;
const TUNNEL_ENCAP_FOU: u16 = 1;
const TUNNEL_ENCAP_GUE: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
#[repr(u16)]
pub enum GreEncapType {
    #[default]
    None,
    Fou,
    Gue,
    Other(u16),
}
impl From<u16> for GreEncapType {
    fn from(d: u16) -> Self {
        match d {
            TUNNEL_ENCAP_NONE => GreEncapType::None,
            TUNNEL_ENCAP_FOU => GreEncapType::Fou,
            TUNNEL_ENCAP_GUE => GreEncapType::Gue,
            _ => Self::Other(d),
        }
    }
}
impl From<&GreEncapType> for u16 {
    fn from(t: &GreEncapType) -> Self {
        match t {
            GreEncapType::None => TUNNEL_ENCAP_NONE,
            GreEncapType::Fou => TUNNEL_ENCAP_FOU,
            GreEncapType::Gue => TUNNEL_ENCAP_GUE,
            GreEncapType::Other(d) => *d,
        }
    }
}

impl Display for GreEncapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GreEncapType::None => write!(f, "none"),
            GreEncapType::Fou => write!(f, "fou"),
            GreEncapType::Gue => write!(f, "gue"),
            GreEncapType::Other(d) => write!(f, "other({d})"),
        }
    }
}

const IFLA_GRE_UNSPEC: u16 = 0;
//const IFLA_GRE_LINK: u16 = 1;
const IFLA_GRE_IFLAGS: u16 = 2;
const IFLA_GRE_OFLAGS: u16 = 3;
const IFLA_GRE_IKEY: u16 = 4;
const IFLA_GRE_OKEY: u16 = 5;
const IFLA_GRE_LOCAL: u16 = 6;
const IFLA_GRE_REMOTE: u16 = 7;
const IFLA_GRE_TTL: u16 = 8;
const IFLA_GRE_TOS: u16 = 9;
const IFLA_GRE_PMTUDISC: u16 = 10;
const IFLA_GRE_ENCAP_LIMIT: u16 = 11;
const IFLA_GRE_FLOWINFO: u16 = 12;
const IFLA_GRE_FLAGS: u16 = 13;
const IFLA_GRE_ENCAP_TYPE: u16 = 14;
const IFLA_GRE_ENCAP_FLAGS: u16 = 15;
const IFLA_GRE_ENCAP_SPORT: u16 = 16;
const IFLA_GRE_ENCAP_DPORT: u16 = 17;
const IFLA_GRE_COLLECT_METADATA: u16 = 18;
const IFLA_GRE_FWMARK: u16 = 20;
