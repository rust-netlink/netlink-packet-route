// SPDX-License-Identifier: MIT

use anyhow::Context;

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::parse_string,
    traits::{Emitable, Parseable},
    DecodeError,
};

use super::super::{
    InfoBond, InfoBondPort, InfoBridge, InfoHsr, InfoIpVlan, InfoIpoib,
    InfoMacSec, InfoMacVlan, InfoMacVtap, InfoVeth, InfoVlan, InfoVrf,
    InfoVxlan, InfoXfrm,
};

const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_INFO_XSTATS: u16 = 3;
const IFLA_INFO_PORT_KIND: u16 = 4;
const IFLA_INFO_PORT_DATA: u16 = 5;

const DUMMY: &str = "dummy";
const IFB: &str = "ifb";
const BRIDGE: &str = "bridge";
const TUN: &str = "tun";
const NLMON: &str = "nlmon";
const VLAN: &str = "vlan";
const VETH: &str = "veth";
const VXLAN: &str = "vxlan";
const BOND: &str = "bond";
const IPVLAN: &str = "ipvlan";
const MACVLAN: &str = "macvlan";
const MACVTAP: &str = "macvtap";
const GRETAP: &str = "gretap";
const IP6GRETAP: &str = "ip6gretap";
const IPIP: &str = "ipip";
const SIT: &str = "sit";
const GRE: &str = "gre";
const IP6GRE: &str = "ip6gre";
const VTI: &str = "vti";
const VRF: &str = "vrf";
const GTP: &str = "gtp";
const IPOIB: &str = "ipoib";
const WIREGUARD: &str = "wireguard";
const XFRM: &str = "xfrm";
const MACSEC: &str = "macsec";
const HSR: &str = "hsr";

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum LinkInfo {
    Xstats(Vec<u8>),
    Kind(InfoKind),
    Data(InfoData),
    PortKind(InfoPortKind),
    PortData(InfoPortData),
    Other(DefaultNla),
}

impl Nla for LinkInfo {
    fn value_len(&self) -> usize {
        use self::LinkInfo::*;
        match self {
            Xstats(ref bytes) => bytes.len(),
            Kind(ref nla) => nla.value_len(),
            Data(ref nla) => nla.value_len(),
            PortKind(ref nla) => nla.value_len(),
            PortData(ref nla) => nla.value_len(),
            Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkInfo::*;
        match self {
            Xstats(ref bytes) => buffer.copy_from_slice(bytes),
            Kind(ref nla) => nla.emit_value(buffer),
            Data(ref nla) => nla.emit_value(buffer),
            PortKind(ref nla) => nla.emit_value(buffer),
            PortData(ref nla) => nla.emit_value(buffer),
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkInfo::*;
        match self {
            Xstats(_) => IFLA_INFO_XSTATS,
            PortKind(_) => IFLA_INFO_PORT_KIND,
            PortData(_) => IFLA_INFO_PORT_DATA,
            Kind(_) => IFLA_INFO_KIND,
            Data(_) => IFLA_INFO_DATA,
            Other(ref nla) => nla.kind(),
        }
    }
}

pub(crate) struct VecLinkInfo(pub(crate) Vec<LinkInfo>);

// We cannot `impl Parseable<_> for Info` because some attributes
// depend on each other. To parse IFLA_INFO_DATA we first need to
// parse the preceding IFLA_INFO_KIND for example.
//
// Moreover, with cannot `impl Parseable for Vec<LinkInfo>` due to the
// orphan rule: `Parseable` and `Vec<_>` are both defined outside of
// this crate. Thus, we create this internal VecLinkInfo struct that wraps
// `Vec<LinkInfo>` and allows us to circumvent the orphan rule.
//
// The downside is that this impl will not be exposed.

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for VecLinkInfo {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = Vec::new();
        let mut link_info_kind: Option<InfoKind> = None;
        let mut link_info_port_kind: Option<InfoPortKind> = None;
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = nla?;
            match nla.kind() {
                IFLA_INFO_XSTATS => {
                    nlas.push(LinkInfo::Xstats(nla.value().to_vec()))
                }
                IFLA_INFO_PORT_KIND => {
                    let parsed = InfoPortKind::parse(&nla)?;
                    nlas.push(LinkInfo::PortKind(parsed.clone()));
                    link_info_port_kind = Some(parsed);
                }
                IFLA_INFO_PORT_DATA => {
                    if let Some(link_info_port_kind) = link_info_port_kind {
                        nlas.push(LinkInfo::PortData(
                            parse_info_port_data_with_kind(
                                nla.value(),
                                link_info_port_kind,
                            )?,
                        ));
                    } else {
                        return Err("IFLA_INFO_PORT_DATA is not preceded by \
                            an IFLA_INFO_PORT_KIND"
                            .into());
                    }
                    link_info_port_kind = None;
                }
                IFLA_INFO_KIND => {
                    let parsed = InfoKind::parse(&nla)?;
                    nlas.push(LinkInfo::Kind(parsed.clone()));
                    link_info_kind = Some(parsed);
                }
                IFLA_INFO_DATA => {
                    if let Some(link_info_kind) = link_info_kind {
                        nlas.push(LinkInfo::Data(parse_info_data_with_kind(
                            nla.value(),
                            link_info_kind,
                        )?));
                    } else {
                        return Err("IFLA_INFO_DATA is not preceded by an \
                            IFLA_INFO_KIND"
                            .into());
                    }
                    link_info_kind = None;
                }
                _kind => nlas.push(LinkInfo::Other(
                    DefaultNla::parse(&nla).context(format!(
                        "Unknown NLA type for IFLA_INFO_DATA {:?}",
                        nla
                    ))?,
                )),
            }
        }
        Ok(Self(nlas))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoData {
    Bridge(Vec<InfoBridge>),
    Tun(Vec<u8>),
    Nlmon(Vec<u8>),
    Vlan(Vec<InfoVlan>),
    Dummy(Vec<u8>),
    Ifb(Vec<u8>),
    Veth(InfoVeth),
    Vxlan(Vec<InfoVxlan>),
    Bond(Vec<InfoBond>),
    IpVlan(Vec<InfoIpVlan>),
    MacVlan(Vec<InfoMacVlan>),
    MacVtap(Vec<InfoMacVtap>),
    GreTap(Vec<u8>),
    GreTap6(Vec<u8>),
    IpTun(Vec<u8>),
    SitTun(Vec<u8>),
    GreTun(Vec<u8>),
    GreTun6(Vec<u8>),
    Vti(Vec<u8>),
    Vrf(Vec<InfoVrf>),
    Gtp(Vec<u8>),
    Ipoib(Vec<InfoIpoib>),
    Wireguard(Vec<u8>),
    Xfrm(Vec<InfoXfrm>),
    MacSec(Vec<InfoMacSec>),
    Hsr(Vec<InfoHsr>),
    Other(Vec<u8>),
}

impl Nla for InfoData {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::InfoData::*;
        match self {
            Bond(ref nlas) => nlas.as_slice().buffer_len(),
            Bridge(ref nlas) => nlas.as_slice().buffer_len(),
            Vlan(ref nlas) =>  nlas.as_slice().buffer_len(),
            Veth(ref msg) => msg.buffer_len(),
            IpVlan(ref nlas) => nlas.as_slice().buffer_len(),
            Ipoib(ref nlas) => nlas.as_slice().buffer_len(),
            MacVlan(ref nlas) => nlas.as_slice().buffer_len(),
            MacVtap(ref nlas) => nlas.as_slice().buffer_len(),
            Vrf(ref nlas) => nlas.as_slice().buffer_len(),
            Vxlan(ref nlas) => nlas.as_slice().buffer_len(),
            Xfrm(ref nlas)  => nlas.as_slice().buffer_len(),
            MacSec(ref nlas) => nlas.as_slice().buffer_len(),
            Hsr(ref nlas) => nlas.as_slice().buffer_len(),
            Dummy(ref bytes)
                | Tun(ref bytes)
                | Nlmon(ref bytes)
                | Ifb(ref bytes)
                | GreTap(ref bytes)
                | GreTap6(ref bytes)
                | IpTun(ref bytes)
                | SitTun(ref bytes)
                | GreTun(ref bytes)
                | GreTun6(ref bytes)
                | Vti(ref bytes)
                | Gtp(ref bytes)
                | Wireguard(ref bytes)
                | Other(ref bytes)
                => bytes.len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoData::*;
        match self {
            Bond(ref nlas) => nlas.as_slice().emit(buffer),
            Bridge(ref nlas) => nlas.as_slice().emit(buffer),
            Vlan(ref nlas) => nlas.as_slice().emit(buffer),
            Veth(ref msg) => msg.emit(buffer),
            IpVlan(ref nlas) => nlas.as_slice().emit(buffer),
            Ipoib(ref nlas) => nlas.as_slice().emit(buffer),
            MacVlan(ref nlas) => nlas.as_slice().emit(buffer),
            MacVtap(ref nlas) => nlas.as_slice().emit(buffer),
            Vrf(ref nlas) => nlas.as_slice().emit(buffer),
            Vxlan(ref nlas) => nlas.as_slice().emit(buffer),
            Xfrm(ref nlas)  => nlas.as_slice().emit(buffer),
            MacSec(ref nlas) => nlas.as_slice().emit(buffer),
            Hsr(ref nlas) => nlas.as_slice().emit(buffer),
            Dummy(ref bytes)
                | Tun(ref bytes)
                | Nlmon(ref bytes)
                | Ifb(ref bytes)
                | GreTap(ref bytes)
                | GreTap6(ref bytes)
                | IpTun(ref bytes)
                | SitTun(ref bytes)
                | GreTun(ref bytes)
                | GreTun6(ref bytes)
                | Vti(ref bytes)
                | Gtp(ref bytes)
                | Wireguard(ref bytes)
                | Other(ref bytes)
                => buffer.copy_from_slice(bytes),
        }
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_DATA
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoPortData {
    BondPort(Vec<InfoBondPort>),
    Other(Vec<u8>),
}

impl Nla for InfoPortData {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::InfoPortData::*;
        match self {
            BondPort(ref nlas) => nlas.as_slice().buffer_len(),
            Other(ref bytes) => bytes.len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoPortData::*;
        match self {
            BondPort(ref nlas) => nlas.as_slice().emit(buffer),
            Other(ref bytes) => buffer.copy_from_slice(bytes),
        }
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_PORT_DATA
    }
}

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
    MacVlan,
    MacVtap,
    GreTap,
    GreTap6,
    IpTun,
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
                Self::MacVlan => MACVLAN,
                Self::MacVtap => MACVTAP,
                Self::GreTap => GRETAP,
                Self::GreTap6 => IP6GRETAP,
                Self::IpTun => IPIP,
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
                Self::Other(s) => s.as_str(),
            }
        )
    }
}

impl Nla for InfoKind {
    fn value_len(&self) -> usize {
        use self::InfoKind::*;
        let len = match *self {
            Dummy => DUMMY.len(),
            Ifb => IFB.len(),
            Bridge => BRIDGE.len(),
            Tun => TUN.len(),
            Nlmon => NLMON.len(),
            Vlan => VLAN.len(),
            Veth => VETH.len(),
            Vxlan => VXLAN.len(),
            Bond => BOND.len(),
            IpVlan => IPVLAN.len(),
            MacVlan => MACVLAN.len(),
            MacVtap => MACVTAP.len(),
            GreTap => GRETAP.len(),
            GreTap6 => IP6GRETAP.len(),
            IpTun => IPIP.len(),
            SitTun => SIT.len(),
            GreTun => GRE.len(),
            GreTun6 => IP6GRE.len(),
            Vti => VTI.len(),
            Vrf => VRF.len(),
            Gtp => GTP.len(),
            Ipoib => IPOIB.len(),
            Wireguard => WIREGUARD.len(),
            Xfrm => XFRM.len(),
            MacSec => MACSEC.len(),
            Hsr => HSR.len(),
            Other(ref s) => s.len(),
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
        use self::InfoKind::*;
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
            DUMMY => Dummy,
            IFB => Ifb,
            BRIDGE => Bridge,
            TUN => Tun,
            NLMON => Nlmon,
            VLAN => Vlan,
            VETH => Veth,
            VXLAN => Vxlan,
            BOND => Bond,
            IPVLAN => IpVlan,
            MACVLAN => MacVlan,
            MACVTAP => MacVtap,
            GRETAP => GreTap,
            IP6GRETAP => GreTap6,
            IPIP => IpTun,
            SIT => SitTun,
            GRE => GreTun,
            IP6GRE => GreTun6,
            VTI => Vti,
            VRF => Vrf,
            GTP => Gtp,
            IPOIB => Ipoib,
            WIREGUARD => Wireguard,
            MACSEC => MacSec,
            XFRM => Xfrm,
            HSR => Hsr,
            _ => Other(s),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoPortKind {
    Bond,
    Other(String),
}

impl std::fmt::Display for InfoPortKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Bond => BOND,
                Self::Other(s) => s.as_str(),
            }
        )
    }
}

impl Nla for InfoPortKind {
    fn value_len(&self) -> usize {
        use self::InfoPortKind::*;
        let len = match *self {
            Bond => BOND.len(),
            Other(ref s) => s.len(),
        };
        len + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoPortKind::*;
        let s = match *self {
            Bond => BOND,
            Other(ref s) => s.as_str(),
        };
        buffer[..s.len()].copy_from_slice(s.as_bytes());
        buffer[s.len()] = 0;
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_PORT_KIND
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoPortKind {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<InfoPortKind, DecodeError> {
        use self::InfoPortKind::*;
        if buf.kind() != IFLA_INFO_PORT_KIND {
            return Err(format!(
                "failed to parse IFLA_INFO_PORT_KIND: NLA type is {}",
                buf.kind()
            )
            .into());
        }
        let s = parse_string(buf.value())
            .context("invalid IFLA_INFO_PORT_KIND value")?;
        Ok(match s.as_str() {
            BOND => Bond,
            _ => Other(s),
        })
    }
}

fn parse_info_data_with_kind(
    payload: &[u8],
    kind: InfoKind,
) -> Result<InfoData, DecodeError> {
    Ok(match kind {
        InfoKind::Dummy => InfoData::Dummy(payload.to_vec()),
        InfoKind::Ifb => InfoData::Ifb(payload.to_vec()),
        InfoKind::Bridge => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'bridge')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoBridge::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Bridge(v)
        }
        InfoKind::Vlan => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'vlan')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoVlan::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Vlan(v)
        }
        InfoKind::Tun => InfoData::Tun(payload.to_vec()),
        InfoKind::Nlmon => InfoData::Nlmon(payload.to_vec()),
        InfoKind::Veth => {
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'veth')";
            let nla_buf = NlaBuffer::new_checked(&payload).context(err)?;
            let parsed = InfoVeth::parse(&nla_buf).context(err)?;
            InfoData::Veth(parsed)
        }
        InfoKind::Vxlan => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'vxlan')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoVxlan::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Vxlan(v)
        }
        InfoKind::Bond => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'bond')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoBond::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Bond(v)
        }
        InfoKind::IpVlan => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'ipvlan')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoIpVlan::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::IpVlan(v)
        }
        InfoKind::MacVlan => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'macvlan')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoMacVlan::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::MacVlan(v)
        }
        InfoKind::MacVtap => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'macvtap')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoMacVtap::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::MacVtap(v)
        }
        InfoKind::GreTap => InfoData::GreTap(payload.to_vec()),
        InfoKind::GreTap6 => InfoData::GreTap6(payload.to_vec()),
        InfoKind::IpTun => InfoData::IpTun(payload.to_vec()),
        InfoKind::SitTun => InfoData::SitTun(payload.to_vec()),
        InfoKind::GreTun => InfoData::GreTun(payload.to_vec()),
        InfoKind::GreTun6 => InfoData::GreTun6(payload.to_vec()),
        InfoKind::Vti => InfoData::Vti(payload.to_vec()),
        InfoKind::Vrf => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'vrf')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoVrf::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Vrf(v)
        }
        InfoKind::Gtp => InfoData::Gtp(payload.to_vec()),
        InfoKind::Ipoib => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'ipoib')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoIpoib::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Ipoib(v)
        }
        InfoKind::Wireguard => InfoData::Wireguard(payload.to_vec()),
        InfoKind::Other(_) => InfoData::Other(payload.to_vec()),
        InfoKind::Xfrm => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'Xfrm')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoXfrm::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Xfrm(v)
        }
        InfoKind::MacSec => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'macsec')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoMacSec::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::MacSec(v)
        }
        InfoKind::Hsr => {
            let mut v = Vec::new();
            let err =
                "failed to parse IFLA_INFO_DATA (IFLA_INFO_KIND is 'hsr')";
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(err)?;
                let parsed = InfoHsr::parse(nla).context(err)?;
                v.push(parsed);
            }
            InfoData::Hsr(v)
        }
    })
}

fn parse_info_port_data_with_kind(
    payload: &[u8],
    kind: InfoPortKind,
) -> Result<InfoPortData, DecodeError> {
    Ok(match kind {
        InfoPortKind::Bond => {
            let mut v = Vec::new();
            for nla in NlasIterator::new(payload) {
                let nla = &nla.context(format!(
                    "failed to parse IFLA_INFO_PORT_DATA \
                    (IFLA_INFO_PORT_KIND is '{kind}')"
                ))?;
                let parsed = InfoBondPort::parse(nla).context(format!(
                    "failed to parse IFLA_INFO_PORT_DATA \
                    (IFLA_INFO_PORT_KIND is '{kind}')"
                ))?;
                v.push(parsed);
            }
            InfoPortData::BondPort(v)
        }
        InfoPortKind::Other(_) => InfoPortData::Other(payload.to_vec()),
    })
}
