// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_string, DecodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};

use super::*;

const LOOPBACK: &str = "lo";
const WLAN: &str = "wlan";
const LAGG: &str = "lagg";
const USBUS: &str = "usbus";
const TAP: &str = "tap";
const VMNET: &str = "vmnet";
const OPENVPN: &str = "openvpn";
const STF: &str = "stf";
const EPAIR: &str = "epair";
const ENC: &str = "enc";
const PFLOG: &str = "pflog";
const PFSYNC: &str = "pfsync";
const IPFW: &str = "ipfw";
const IPFWLOG: &str = "ipfwlog";
const DISC: &str = "disc";
const ME: &str = "me";
const EDSC: &str = "edsc";
const IPSEC: &str = "ipsec";
const GIF: &str = "gif";

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoKind {
    Bridge,
    Tun,
    Vlan,
    Vxlan,
    GreTun,
    Wireguard,
    Loopback,
    Wlan,
    Lagg,
    Usbus,
    Tap,
    Vmnet,
    Openvpn,
    Stf,
    Epair,
    Enc,
    Pflog,
    Pfsync,
    Ipfw,
    Ipfwlog,
    Disc,
    Me,
    Edsc,
    Ipsec,
    Gif,
    Other(String),
}

impl std::fmt::Display for InfoKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Bridge => BRIDGE,
                Self::Tun => TUN,
                Self::Vlan => VLAN,
                Self::Vxlan => VXLAN,
                Self::GreTun => GRE,
                Self::Wireguard => WIREGUARD,
                Self::Loopback => LOOPBACK,
                Self::Wlan => WLAN,
                Self::Lagg => LAGG,
                Self::Usbus => USBUS,
                Self::Tap => TAP,
                Self::Vmnet => VMNET,
                Self::Openvpn => OPENVPN,
                Self::Stf => STF,
                Self::Epair => EPAIR,
                Self::Enc => ENC,
                Self::Pflog => PFLOG,
                Self::Pfsync => PFSYNC,
                Self::Ipfw => IPFW,
                Self::Ipfwlog => IPFWLOG,
                Self::Disc => DISC,
                Self::Me => ME,
                Self::Edsc => EDSC,
                Self::Ipsec => IPSEC,
                Self::Gif => GIF,
                Self::Other(s) => s.as_str(),
            }
        )
    }
}

impl Nla for InfoKind {
    fn value_len(&self) -> usize {
        let len = match self {
            Self::Bridge => BRIDGE.len(),
            Self::Tun => TUN.len(),
            Self::Vlan => VLAN.len(),
            Self::Vxlan => VXLAN.len(),
            Self::GreTun => GRE.len(),
            Self::Wireguard => WIREGUARD.len(),
            Self::Loopback => LOOPBACK.len(),
            Self::Wlan => WLAN.len(),
            Self::Lagg => LAGG.len(),
            Self::Usbus => USBUS.len(),
            Self::Tap => TAP.len(),
            Self::Vmnet => VMNET.len(),
            Self::Openvpn => OPENVPN.len(),
            Self::Stf => STF.len(),
            Self::Epair => EPAIR.len(),
            Self::Enc => ENC.len(),
            Self::Pflog => PFLOG.len(),
            Self::Pfsync => PFSYNC.len(),
            Self::Ipfw => IPFW.len(),
            Self::Ipfwlog => IPFWLOG.len(),
            Self::Disc => DISC.len(),
            Self::Me => ME.len(),
            Self::Edsc => EDSC.len(),
            Self::Ipsec => IPSEC.len(),
            Self::Gif => GIF.len(),
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
            BRIDGE => Self::Bridge,
            TUN => Self::Tun,
            VLAN => Self::Vlan,
            VXLAN => Self::Vxlan,
            GRE => Self::GreTun,
            WIREGUARD => Self::Wireguard,
            LOOPBACK => Self::Loopback,
            WLAN => Self::Wlan,
            LAGG => Self::Lagg,
            USBUS => Self::Usbus,
            TAP => Self::Tap,
            VMNET => Self::Vmnet,
            OPENVPN => Self::Openvpn,
            STF => Self::Stf,
            EPAIR => Self::Epair,
            ENC => Self::Enc,
            PFLOG => Self::Pflog,
            PFSYNC => Self::Pfsync,
            IPFW => Self::Ipfw,
            IPFWLOG => Self::Ipfwlog,
            DISC => Self::Disc,
            ME => Self::Me,
            EDSC => Self::Edsc,
            IPSEC => Self::Ipsec,
            GIF => Self::Gif,
            _ => Self::Other(s),
        })
    }
}
