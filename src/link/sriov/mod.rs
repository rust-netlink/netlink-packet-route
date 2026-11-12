// SPDX-License-Identifier: MIT

mod broadcast;
mod guid;
mod link_state;
mod mac;
mod rate;
mod rss_query;
mod spoofchk;
mod stats;
mod trust;
mod tx_rate;
mod vf_list;
mod vf_port;
mod vf_vlan;
mod vlan;

pub use self::{
    broadcast::VfInfoBroadcast,
    guid::VfInfoGuid,
    link_state::{VfInfoLinkState, VfLinkState},
    mac::VfInfoMac,
    rate::VfInfoRate,
    rss_query::VfInfoRssQueryEn,
    spoofchk::VfInfoSpoofCheck,
    stats::VfStats,
    trust::VfInfoTrust,
    tx_rate::VfInfoTxRate,
    vf_list::{LinkVfInfo, VfInfo},
    vf_port::{LinkVfPort, VfPort},
    vf_vlan::{VfVlan, VfVlanInfo},
    vlan::VfInfoVlan,
};
pub(crate) use self::{vf_list::VecLinkVfInfo, vf_port::VecLinkVfPort};
