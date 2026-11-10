// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

use crate::link::{
    VfInfoBroadcast, VfInfoGuid, VfInfoLinkState, VfInfoMac, VfInfoRate,
    VfInfoRssQueryEn, VfInfoSpoofCheck, VfInfoTrust, VfInfoTxRate, VfInfoVlan,
    VfStats, VfVlan,
};

const IFLA_VF_INFO: u16 = 1;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VecLinkVfInfo(pub(crate) Vec<LinkVfInfo>);

impl<'a> Parseable<NlaBuffer<'a>> for VecLinkVfInfo {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self(buf.parse_nlas_with(|nla| {
            if nla.kind() == IFLA_VF_INFO {
                Ok(Some(LinkVfInfo::parse(&nla)?))
            } else {
                log::warn!(
                    "BUG: Expecting IFLA_VF_INFO in IFLA_VFINFO_LIST, but got \
                     {}",
                    nla.kind()
                );
                Ok(None)
            }
        })?))
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct LinkVfInfo(pub Vec<VfInfo>);

impl Nla for LinkVfInfo {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.0.emit(out)
    }

    fn kind(&self) -> u16 {
        IFLA_VF_INFO
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for LinkVfInfo {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in buf.nlas() {
            let nla = nla.with_context(|| {
                format!("invalid IFLA_VF_INFO value {:?}", buf.value())
            })?;
            nlas.push(VfInfo::parse(&nla)?);
        }
        Ok(Self(nlas))
    }
}

const IFLA_VF_MAC: u16 = 1;
const IFLA_VF_VLAN: u16 = 2;
const IFLA_VF_TX_RATE: u16 = 3;
const IFLA_VF_SPOOFCHK: u16 = 4;
const IFLA_VF_LINK_STATE: u16 = 5;
const IFLA_VF_RATE: u16 = 6;
const IFLA_VF_RSS_QUERY_EN: u16 = 7;
const IFLA_VF_STATS: u16 = 8;
const IFLA_VF_TRUST: u16 = 9;
const IFLA_VF_IB_NODE_GUID: u16 = 10;
const IFLA_VF_IB_PORT_GUID: u16 = 11;
const IFLA_VF_VLAN_LIST: u16 = 12;
const IFLA_VF_BROADCAST: u16 = 13;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum VfInfo {
    Mac(VfInfoMac),
    Broadcast(VfInfoBroadcast),
    Vlan(VfInfoVlan),
    Rate(VfInfoRate),
    TxRate(VfInfoTxRate),
    SpoofCheck(VfInfoSpoofCheck),
    LinkState(VfInfoLinkState),
    RssQueryEn(VfInfoRssQueryEn),
    Trust(VfInfoTrust),
    IbNodeGuid(VfInfoGuid),
    IbPortGuid(VfInfoGuid),
    VlanList(Vec<VfVlan>),
    Stats(Vec<VfStats>),
    Other(DefaultNla),
}

impl Nla for VfInfo {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Mac(v) => v.emit(out)?,
            Self::Vlan(v) => v.emit(out)?,
            Self::Broadcast(v) => v.emit(out)?,
            Self::Rate(v) => v.emit(out)?,
            Self::TxRate(v) => v.emit(out)?,
            Self::SpoofCheck(v) => v.emit(out)?,
            Self::LinkState(v) => v.emit(out)?,
            Self::RssQueryEn(v) => v.emit(out)?,
            Self::Trust(v) => v.emit(out)?,
            Self::IbNodeGuid(v) => v.emit(out)?,
            Self::IbPortGuid(v) => v.emit(out)?,
            Self::VlanList(v) => (v).emit(out)?,
            Self::Stats(v) => (v).emit(out)?,
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Mac(_) => IFLA_VF_MAC,
            Self::Vlan(_) => IFLA_VF_VLAN,
            Self::Broadcast(_) => IFLA_VF_BROADCAST,
            Self::Rate(_) => IFLA_VF_RATE,
            Self::TxRate(_) => IFLA_VF_TX_RATE,
            Self::SpoofCheck(_) => IFLA_VF_SPOOFCHK,
            Self::LinkState(_) => IFLA_VF_LINK_STATE,
            Self::RssQueryEn(_) => IFLA_VF_RSS_QUERY_EN,
            Self::Trust(_) => IFLA_VF_TRUST,
            Self::IbNodeGuid(_) => IFLA_VF_IB_NODE_GUID,
            Self::IbPortGuid(_) => IFLA_VF_IB_PORT_GUID,
            Self::VlanList(_) => IFLA_VF_VLAN_LIST,
            Self::Stats(_) => IFLA_VF_STATS,
            Self::Other(v) => v.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for VfInfo {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VF_MAC => {
                Self::Mac(VfInfoMac::parse(payload).with_context(|| {
                    format!("invalid IFLA_VF_MAC {payload:?}")
                })?)
            }
            IFLA_VF_VLAN => {
                Self::Vlan(VfInfoVlan::parse(payload).with_context(|| {
                    format!("invalid IFLA_VF_VLAN {payload:?}")
                })?)
            }
            IFLA_VF_BROADCAST => {
                Self::Broadcast(VfInfoBroadcast::parse(payload).with_context(
                    || format!("invalid IFLA_VF_BROADCAST {payload:?}"),
                )?)
            }
            IFLA_VF_RATE => {
                Self::Rate(VfInfoRate::parse(payload).with_context(|| {
                    format!("invalid IFLA_VF_RATE {payload:?}")
                })?)
            }
            IFLA_VF_TX_RATE => {
                Self::TxRate(VfInfoTxRate::parse(payload).with_context(
                    || format!("invalid IFLA_VF_TX_RATE {payload:?}"),
                )?)
            }
            IFLA_VF_SPOOFCHK => Self::SpoofCheck(
                VfInfoSpoofCheck::parse(payload).with_context(|| {
                    format!("invalid IFLA_VF_SPOOFCHK {payload:?}")
                })?,
            ),
            IFLA_VF_LINK_STATE => {
                Self::LinkState(VfInfoLinkState::parse(payload).with_context(
                    || format!("invalid IFLA_VF_LINK_STATE {payload:?}"),
                )?)
            }
            IFLA_VF_RSS_QUERY_EN => Self::RssQueryEn(
                VfInfoRssQueryEn::parse(payload).with_context(|| {
                    format!("invalid IFLA_VF_RSS_QUERY_EN {payload:?}")
                })?,
            ),
            IFLA_VF_TRUST => {
                Self::Trust(VfInfoTrust::parse(payload).with_context(|| {
                    format!("invalid IFLA_VF_TRUST {payload:?}")
                })?)
            }
            IFLA_VF_IB_NODE_GUID => {
                Self::IbNodeGuid(VfInfoGuid::parse(payload).with_context(
                    || format!("invalid IFLA_VF_IB_NODE_GUID {payload:?}"),
                )?)
            }
            IFLA_VF_IB_PORT_GUID => {
                Self::IbPortGuid(VfInfoGuid::parse(payload).with_context(
                    || format!("invalid IFLA_VF_IB_PORT_GUID {payload:?}"),
                )?)
            }
            IFLA_VF_VLAN_LIST => {
                let mut nlas: Vec<VfVlan> = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!(
                            "invalid IFLA_VF_VLAN_LIST value: {:?}",
                            buf.value()
                        )
                    })?;

                    nlas.push(VfVlan::parse(nla)?);
                }
                Self::VlanList(nlas)
            }
            IFLA_VF_STATS => {
                let mut nlas: Vec<VfStats> = Vec::new();
                for nla in buf.nlas() {
                    let nla = &nla.with_context(|| {
                        format!(
                            "invalid IFLA_VF_STATS value: {:?}",
                            buf.value()
                        )
                    })?;

                    nlas.push(VfStats::parse(nla)?);
                }
                Self::Stats(nlas)
            }
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("failed to parse {kind} as DefaultNla: {payload:?}")
            })?),
        })
    }
}
