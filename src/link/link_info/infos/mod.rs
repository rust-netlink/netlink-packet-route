// SPDX-License-Identifier: MIT

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(not(target_os = "freebsd"))]
mod linux;

use netlink_packet_core::{
    DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer, NlasIterator,
    Parseable,
};

#[cfg(target_os = "freebsd")]
pub use self::freebsd::InfoKind;
#[cfg(not(target_os = "freebsd"))]
pub use self::linux::InfoKind;
use super::super::InfoData;
#[cfg(not(target_os = "freebsd"))]
pub use super::super::{InfoPortData, InfoPortKind, LinkXstats};

const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
#[cfg(not(target_os = "freebsd"))]
const IFLA_INFO_XSTATS: u16 = 3;
#[cfg(not(target_os = "freebsd"))]
const IFLA_INFO_PORT_KIND: u16 = 4;
#[cfg(not(target_os = "freebsd"))]
const IFLA_INFO_PORT_DATA: u16 = 5;

const BRIDGE: &str = "bridge";
const TUN: &str = "tun";
const VLAN: &str = "vlan";
const VXLAN: &str = "vxlan";
const GRE: &str = "gre";
#[cfg(not(target_os = "freebsd"))]
const WIREGUARD: &str = "wireguard";
#[cfg(target_os = "freebsd")]
const WIREGUARD: &str = "wg";

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum LinkInfo {
    #[cfg(not(target_os = "freebsd"))]
    Xstats(LinkXstats),
    Kind(InfoKind),
    Data(InfoData),
    #[cfg(not(target_os = "freebsd"))]
    PortKind(InfoPortKind),
    #[cfg(not(target_os = "freebsd"))]
    PortData(InfoPortData),
    Other(DefaultNla),
}

impl Nla for LinkInfo {
    fn value_len(&self) -> usize {
        match self {
            #[cfg(not(target_os = "freebsd"))]
            Self::Xstats(v) => v.buffer_len(),
            Self::Kind(nla) => nla.value_len(),
            Self::Data(nla) => nla.value_len(),
            #[cfg(not(target_os = "freebsd"))]
            Self::PortKind(nla) => nla.value_len(),
            #[cfg(not(target_os = "freebsd"))]
            Self::PortData(nla) => nla.value_len(),
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            #[cfg(not(target_os = "freebsd"))]
            Self::Xstats(v) => v.emit(buffer),
            Self::Kind(nla) => nla.emit_value(buffer),
            Self::Data(nla) => nla.emit_value(buffer),
            #[cfg(not(target_os = "freebsd"))]
            Self::PortKind(nla) => nla.emit_value(buffer),
            #[cfg(not(target_os = "freebsd"))]
            Self::PortData(nla) => nla.emit_value(buffer),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            #[cfg(not(target_os = "freebsd"))]
            Self::Xstats(_) => IFLA_INFO_XSTATS,
            #[cfg(not(target_os = "freebsd"))]
            Self::PortKind(_) => IFLA_INFO_PORT_KIND,
            #[cfg(not(target_os = "freebsd"))]
            Self::PortData(_) => IFLA_INFO_PORT_DATA,
            Self::Kind(_) => IFLA_INFO_KIND,
            Self::Data(_) => IFLA_INFO_DATA,
            Self::Other(nla) => nla.kind(),
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
        #[cfg(not(target_os = "freebsd"))]
        let mut link_info_port_kind: Option<InfoPortKind> = None;
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = nla?;
            match nla.kind() {
                #[cfg(not(target_os = "freebsd"))]
                IFLA_INFO_XSTATS => {
                    if let Some(link_info_kind) = &link_info_kind {
                        nlas.push(LinkInfo::Xstats(
                            LinkXstats::parse_with_param(&nla, link_info_kind)?,
                        ));
                    } else {
                        return Err("IFLA_INFO_XSTATS is not preceded by an \
                                    IFLA_INFO_KIND"
                            .into());
                    }
                }
                #[cfg(not(target_os = "freebsd"))]
                IFLA_INFO_PORT_KIND => {
                    let parsed = InfoPortKind::parse(&nla)?;
                    nlas.push(LinkInfo::PortKind(parsed.clone()));
                    link_info_port_kind = Some(parsed);
                }
                #[cfg(not(target_os = "freebsd"))]
                IFLA_INFO_PORT_DATA => {
                    if let Some(link_info_port_kind) = link_info_port_kind {
                        nlas.push(LinkInfo::PortData(
                            InfoPortData::parse_with_param(
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
                    if let Some(link_info_kind) = &link_info_kind {
                        nlas.push(LinkInfo::Data(InfoData::parse_with_param(
                            nla.value(),
                            link_info_kind,
                        )?));
                    } else {
                        return Err("IFLA_INFO_DATA is not preceded by an \
                                    IFLA_INFO_KIND"
                            .into());
                    }
                }
                _kind => nlas.push(LinkInfo::Other(
                    DefaultNla::parse(&nla).context(format!(
                        "Unknown NLA type for IFLA_INFO_DATA {nla:?}"
                    ))?,
                )),
            }
        }
        Ok(Self(nlas))
    }
}
