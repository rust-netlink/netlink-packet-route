// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, Emitable, EncodeError, ErrorContext, Nla,
    NlaBuffer, Parseable, ParseableParametrized,
};

use super::super::{
    InfoAmt, InfoBareUdp, InfoBatAdv, InfoBond, InfoBridge, InfoCan, InfoDsa,
    InfoGeneve, InfoGre, InfoGre6, InfoGtp, InfoHsr, InfoIpTunnel, InfoIpVlan,
    InfoIpVtap, InfoIpoib, InfoKind, InfoMacSec, InfoMacVlan, InfoMacVtap,
    InfoNetkit, InfoRmNet, InfoTun, InfoVeth, InfoVlan, InfoVrf, InfoVti,
    InfoVxcan, InfoVxlan, InfoWireguard, InfoWwan, InfoXfrm,
};

const IFLA_INFO_DATA: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoData {
    Bridge(Vec<InfoBridge>),
    Can(Vec<InfoCan>),
    Tun(Vec<InfoTun>),
    Vlan(Vec<InfoVlan>),
    Veth(InfoVeth),
    Vxlan(Vec<InfoVxlan>),
    Bond(Vec<InfoBond>),
    IpVlan(Vec<InfoIpVlan>),
    IpVtap(Vec<InfoIpVtap>),
    MacVlan(Vec<InfoMacVlan>),
    MacVtap(Vec<InfoMacVtap>),
    GreTap(Vec<InfoGre>),
    GreTap6(Vec<InfoGre6>),
    GreTun(Vec<InfoGre>),
    GreTun6(Vec<InfoGre6>),
    Vti(Vec<InfoVti>),
    Vrf(Vec<InfoVrf>),
    Gtp(Vec<InfoGtp>),
    Ipoib(Vec<InfoIpoib>),
    Xfrm(Vec<InfoXfrm>),
    MacSec(Vec<InfoMacSec>),
    Hsr(Vec<InfoHsr>),
    Geneve(Vec<InfoGeneve>),
    IpTunnel(Vec<InfoIpTunnel>),
    Netkit(Vec<InfoNetkit>),
    Vxcan(InfoVxcan),
    Amt(Vec<InfoAmt>),
    BatAdv(Vec<InfoBatAdv>),
    BareUdp(Vec<InfoBareUdp>),
    Dsa(Vec<InfoDsa>),
    Wwan(Vec<InfoWwan>),
    RmNet(Vec<InfoRmNet>),
    ErSpan(Vec<InfoGre>),
    Ip6ErSpan(Vec<InfoGre6>),
    Wireguard(Vec<InfoWireguard>),
    Other(Vec<u8>),
}

impl Nla for InfoData {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Can(nlas) => (nlas).emit(out),
            Self::Bond(nlas) => (nlas).emit(out),
            Self::Bridge(nlas) => (nlas).emit(out),
            Self::Vlan(nlas) => (nlas).emit(out),
            Self::Veth(msg) => msg.emit(out),
            Self::IpVlan(nlas) => (nlas).emit(out),
            Self::IpVtap(nlas) => (nlas).emit(out),
            Self::Ipoib(nlas) => (nlas).emit(out),
            Self::MacVlan(nlas) => (nlas).emit(out),
            Self::MacVtap(nlas) => (nlas).emit(out),
            Self::Vrf(nlas) => (nlas).emit(out),
            Self::Vxlan(nlas) => (nlas).emit(out),
            Self::Xfrm(nlas) => (nlas).emit(out),
            Self::MacSec(nlas) => (nlas).emit(out),
            Self::Hsr(nlas) => (nlas).emit(out),
            Self::Tun(nlas) => (nlas).emit(out),
            Self::GreTap(nlas) => (nlas).emit(out),
            Self::GreTap6(nlas) => (nlas).emit(out),
            Self::GreTun(nlas) => (nlas).emit(out),
            Self::GreTun6(nlas) => (nlas).emit(out),
            Self::Vti(nlas) => (nlas).emit(out),
            Self::Gtp(nlas) => (nlas).emit(out),
            Self::Geneve(nlas) => (nlas).emit(out),
            Self::IpTunnel(nlas) => (nlas).emit(out),
            Self::Netkit(nlas) => (nlas).emit(out),
            Self::Vxcan(msg) => msg.emit(out),
            Self::Amt(nlas) => (nlas).emit(out),
            Self::BatAdv(nlas) => (nlas).emit(out),
            Self::BareUdp(nlas) => (nlas).emit(out),
            Self::Dsa(nlas) => (nlas).emit(out),
            Self::Wwan(nlas) => (nlas).emit(out),
            Self::RmNet(nlas) => (nlas).emit(out),
            Self::ErSpan(nlas) => (nlas).emit(out),
            Self::Ip6ErSpan(nlas) => (nlas).emit(out),
            Self::Wireguard(nlas) => (nlas).emit(out),
            Self::Other(v) => {
                append_bytes(out, v.as_slice());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_DATA
    }
}

impl InfoData {
    pub(crate) fn parse_with_param(
        buf: &NlaBuffer<'_>,
        kind: &InfoKind,
    ) -> Result<InfoData, DecodeError> {
        let payload = buf.value();
        Ok(match kind {
            InfoKind::Can => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoCan::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Can(v)
            }
            InfoKind::Bridge => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoBridge::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Bridge(v)
            }
            InfoKind::Vlan => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoVlan::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Vlan(v)
            }
            InfoKind::Tun => {
                let mut nlas = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoTun::parse(nla)?;
                    nlas.push(parsed);
                }
                InfoData::Tun(nlas)
            }
            InfoKind::Veth => {
                let nla_buf = NlaBuffer::new(payload).with_context(|| {
                    format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                })?;
                let parsed = InfoVeth::parse(&nla_buf)?;
                InfoData::Veth(parsed)
            }
            InfoKind::Vxlan => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoVxlan::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Vxlan(v)
            }
            InfoKind::Bond => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoBond::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Bond(v)
            }
            InfoKind::IpVlan => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoIpVlan::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::IpVlan(v)
            }
            InfoKind::IpVtap => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoIpVtap::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::IpVtap(v)
            }
            InfoKind::MacVlan => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoMacVlan::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::MacVlan(v)
            }
            InfoKind::MacVtap => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoMacVtap::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::MacVtap(v)
            }
            InfoKind::GreTap => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGre::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::GreTap(v)
            }
            InfoKind::GreTap6 => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGre6::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::GreTap6(v)
            }
            InfoKind::GreTun => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGre::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::GreTun(v)
            }
            InfoKind::GreTun6 => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGre6::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::GreTun6(v)
            }
            InfoKind::Vti | InfoKind::Vti6 => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoVti::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Vti(v)
            }
            InfoKind::Vrf => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoVrf::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Vrf(v)
            }
            InfoKind::Gtp => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGtp::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Gtp(v)
            }
            InfoKind::Ipoib => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoIpoib::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Ipoib(v)
            }
            InfoKind::Xfrm => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoXfrm::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Xfrm(v)
            }
            InfoKind::MacSec => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoMacSec::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::MacSec(v)
            }
            InfoKind::Hsr => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoHsr::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Hsr(v)
            }
            InfoKind::IpIp | InfoKind::Ip6Tnl | InfoKind::SitTun => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed =
                        InfoIpTunnel::parse_with_param(nla, kind.clone())?;
                    v.push(parsed);
                }
                InfoData::IpTunnel(v)
            }
            InfoKind::Geneve => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGeneve::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Geneve(v)
            }
            InfoKind::Netkit => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoNetkit::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Netkit(v)
            }
            InfoKind::Vxcan => {
                let nla_buf = NlaBuffer::new(payload).with_context(|| {
                    format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                })?;
                let parsed = InfoVxcan::parse(&nla_buf)?;
                InfoData::Vxcan(parsed)
            }
            InfoKind::Amt => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoAmt::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Amt(v)
            }
            InfoKind::Wwan => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoWwan::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Wwan(v)
            }
            InfoKind::RmNet => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoRmNet::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::RmNet(v)
            }
            InfoKind::BatAdv => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoBatAdv::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::BatAdv(v)
            }
            InfoKind::BareUdp => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoBareUdp::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::BareUdp(v)
            }
            InfoKind::Dsa => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoDsa::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Dsa(v)
            }
            InfoKind::ErSpan => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGre::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::ErSpan(v)
            }
            InfoKind::Ip6ErSpan => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoGre6::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Ip6ErSpan(v)
            }
            InfoKind::Wireguard => {
                let mut v = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!("invalid IFLA_INFO_DATA for {kind} {payload:?}")
                    })?;
                    let parsed = InfoWireguard::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Wireguard(v)
            }
            _ => InfoData::Other(payload.to_vec()),
        })
    }
}
