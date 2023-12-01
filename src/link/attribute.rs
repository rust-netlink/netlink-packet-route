// SPDX-License-Identifier: MIT

use std::os::unix::io::RawFd;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator, NLA_F_NESTED},
    parsers::{parse_i32, parse_string, parse_u32, parse_u8},
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

#[cfg(any(target_os = "linux", target_os = "fuchsia",))]
use super::af_spec::VecAfSpecBridge;
use super::{
    af_spec::VecAfSpecUnspec, buffer_tool::expand_buffer_if_small,
    link_info::VecLinkInfo, stats::LINK_STATS_LEN, stats64::LINK_STATS64_LEN,
    xdp::VecXdp, AfSpecBridge, AfSpecUnspec, LinkInfo, Map, MapBuffer, Prop,
    State, Stats, Stats64, Stats64Buffer, StatsBuffer, Xdp,
};
use crate::AddressFamily;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_QDISC: u16 = 6;
const IFLA_STATS: u16 = 7;
// No kernel is using IFLA_COST
// const IFLA_COST: u16 = 8;
// No kernel is using IFLA_PRIORITY
// const IFLA_PRIORITY: u16 = 9;
const IFLA_MASTER: u16 = 10;
const IFLA_WIRELESS: u16 = 11;
const IFLA_PROTINFO: u16 = 12;
const IFLA_TXQLEN: u16 = 13;
const IFLA_MAP: u16 = 14;
const IFLA_WEIGHT: u16 = 15;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_IFALIAS: u16 = 20;
const IFLA_NUM_VF: u16 = 21;
const IFLA_VFINFO_LIST: u16 = 22;
const IFLA_STATS64: u16 = 23;
const IFLA_VF_PORTS: u16 = 24;
const IFLA_PORT_SELF: u16 = 25;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_GROUP: u16 = 27;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_EXT_MASK: u16 = 29;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_CARRIER: u16 = 33;
const IFLA_PHYS_PORT_ID: u16 = 34;
const IFLA_CARRIER_CHANGES: u16 = 35;
const IFLA_PHYS_SWITCH_ID: u16 = 36;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_PHYS_PORT_NAME: u16 = 38;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_PAD: u16 = 42;
const IFLA_XDP: u16 = 43;
const IFLA_EVENT: u16 = 44;
const IFLA_NEW_NETNSID: u16 = 45;
const IFLA_IF_NETNSID: u16 = 46;
const IFLA_CARRIER_UP_COUNT: u16 = 47;
const IFLA_CARRIER_DOWN_COUNT: u16 = 48;
const IFLA_NEW_IFINDEX: u16 = 49;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_PROP_LIST: u16 = 52;
const IFLA_PERM_ADDRESS: u16 = 54;
const IFLA_PROTO_DOWN_REASON: u16 = 55;

/* TODO:(Gris Ge)
const IFLA_PARENT_DEV_NAME: u16 = 56;
const IFLA_PARENT_DEV_BUS_NAME: u16 = 57;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;
const IFLA_DEVLINK_PORT: u16 = 62;
*/

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum LinkAttribute {
    Weight(Vec<u8>),
    VfInfoList(Vec<u8>),
    VfPorts(Vec<u8>),
    PortSelf(Vec<u8>),
    PhysPortId(Vec<u8>),
    PhysSwitchId(Vec<u8>),
    Pad(Vec<u8>),
    Xdp(Vec<Xdp>),
    Event(Vec<u8>),
    NewNetnsId(Vec<u8>),
    IfNetnsId(Vec<u8>),
    CarrierUpCount(Vec<u8>),
    CarrierDownCount(Vec<u8>),
    NewIfIndex(Vec<u8>),
    LinkInfo(Vec<LinkInfo>),
    Wireless(Vec<u8>),
    ProtoInfo(Vec<u8>),
    PropList(Vec<Prop>),
    ProtoDownReason(Vec<u8>),
    Address(Vec<u8>),
    Broadcast(Vec<u8>),
    /// Permanent hardware address of the device. The provides the same
    /// information as the ethtool ioctl interface.
    PermAddress(Vec<u8>),
    IfName(String),
    Qdisc(String),
    IfAlias(String),
    PhysPortName(String),
    Mode(u8),
    Carrier(u8),
    ProtoDown(u8),
    Mtu(u32),
    Link(u32),
    Controller(u32),
    TxQueueLen(u32),
    NetNsPid(u32),
    NumVf(u32),
    Group(u32),
    NetNsFd(RawFd),
    ExtMask(u32),
    Promiscuity(u32),
    NumTxQueues(u32),
    NumRxQueues(u32),
    CarrierChanges(u32),
    GsoMaxSegs(u32),
    GsoMaxSize(u32),
    /// The minimum MTU for the device.
    MinMtu(u32),
    /// The maximum MTU for the device.
    MaxMtu(u32),
    NetnsId(i32),
    OperState(State),
    Stats(Stats),
    Stats64(Stats64),
    Map(Map),
    // AF_SPEC (the type of af_spec depends on the interface family of the
    // message)
    AfSpecUnspec(Vec<AfSpecUnspec>),
    AfSpecBridge(Vec<AfSpecBridge>),
    AfSpecUnknown(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for LinkAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Weight(bytes)
            | Self::VfInfoList(bytes)
            | Self::VfPorts(bytes)
            | Self::PortSelf(bytes)
            | Self::PhysPortId(bytes)
            | Self::PhysSwitchId(bytes)
            | Self::Pad(bytes)
            | Self::Event(bytes)
            | Self::NewNetnsId(bytes)
            | Self::IfNetnsId(bytes)
            | Self::Wireless(bytes)
            | Self::ProtoInfo(bytes)
            | Self::CarrierUpCount(bytes)
            | Self::CarrierDownCount(bytes)
            | Self::NewIfIndex(bytes)
            | Self::Address(bytes)
            | Self::Broadcast(bytes)
            | Self::PermAddress(bytes)
            | Self::AfSpecUnknown(bytes)
            | Self::ProtoDownReason(bytes) => bytes.len(),

            Self::IfName(string)
            | Self::Qdisc(string)
            | Self::IfAlias(string)
            | Self::PhysPortName(string) => string.as_bytes().len() + 1,

            Self::Mode(_) | Self::Carrier(_) | Self::ProtoDown(_) => 1,

            Self::Mtu(_)
            | Self::Link(_)
            | Self::Controller(_)
            | Self::TxQueueLen(_)
            | Self::NetNsPid(_)
            | Self::NumVf(_)
            | Self::Group(_)
            | Self::NetNsFd(_)
            | Self::ExtMask(_)
            | Self::Promiscuity(_)
            | Self::NumTxQueues(_)
            | Self::NumRxQueues(_)
            | Self::CarrierChanges(_)
            | Self::GsoMaxSegs(_)
            | Self::GsoMaxSize(_)
            | Self::NetnsId(_)
            | Self::MinMtu(_)
            | Self::MaxMtu(_) => 4,

            Self::OperState(_) => 1,
            Self::Stats(_) => LINK_STATS_LEN,
            Self::Stats64(_) => LINK_STATS64_LEN,
            Self::Map(nla) => nla.buffer_len(),
            Self::LinkInfo(nlas) => nlas.as_slice().buffer_len(),
            Self::Xdp(nlas) => nlas.as_slice().buffer_len(),
            Self::PropList(nlas) => nlas.as_slice().buffer_len(),
            Self::AfSpecUnspec(nlas) => nlas.as_slice().buffer_len(),
            Self::AfSpecBridge(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Weight(bytes)
            | Self::VfInfoList(bytes)
            | Self::VfPorts(bytes)
            | Self::PortSelf(bytes)
            | Self::PhysPortId(bytes)
            | Self::PhysSwitchId(bytes)
            | Self::Wireless(bytes)
            | Self::ProtoInfo(bytes)
            | Self::Pad(bytes)
            | Self::Event(bytes)
            | Self::NewNetnsId(bytes)
            | Self::IfNetnsId(bytes)
            | Self::CarrierUpCount(bytes)
            | Self::CarrierDownCount(bytes)
            | Self::NewIfIndex(bytes)
            | Self::Address(bytes)
            | Self::Broadcast(bytes)
            | Self::PermAddress(bytes)
            | Self::AfSpecUnknown(bytes)
            | Self::ProtoDownReason(bytes) => {
                buffer.copy_from_slice(bytes.as_slice())
            }

            Self::IfName(string)
            | Self::Qdisc(string)
            | Self::IfAlias(string)
            | Self::PhysPortName(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }

            Self::Mode(val) | Self::Carrier(val) | Self::ProtoDown(val) => {
                buffer[0] = *val
            }

            Self::Mtu(value)
            | Self::Link(value)
            | Self::Controller(value)
            | Self::TxQueueLen(value)
            | Self::NetNsPid(value)
            | Self::NumVf(value)
            | Self::Group(value)
            | Self::ExtMask(value)
            | Self::Promiscuity(value)
            | Self::NumTxQueues(value)
            | Self::NumRxQueues(value)
            | Self::CarrierChanges(value)
            | Self::GsoMaxSegs(value)
            | Self::GsoMaxSize(value)
            | Self::MinMtu(value)
            | Self::MaxMtu(value) => NativeEndian::write_u32(buffer, *value),

            Self::NetnsId(value) | Self::NetNsFd(value) => {
                NativeEndian::write_i32(buffer, *value)
            }
            Self::Stats(nla) => nla.emit(buffer),
            Self::Map(nla) => nla.emit(buffer),
            Self::Stats64(nla) => nla.emit(buffer),
            Self::OperState(state) => buffer[0] = (*state).into(),
            Self::LinkInfo(nlas) => nlas.as_slice().emit(buffer),
            Self::Xdp(nlas) => nlas.as_slice().emit(buffer),
            Self::PropList(nlas) => nlas.as_slice().emit(buffer),
            Self::AfSpecUnspec(nlas) => nlas.as_slice().emit(buffer),
            Self::AfSpecBridge(nlas) => nlas.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Weight(_) => IFLA_WEIGHT,
            Self::VfInfoList(_) => IFLA_VFINFO_LIST,
            Self::VfPorts(_) => IFLA_VF_PORTS,
            Self::PortSelf(_) => IFLA_PORT_SELF,
            Self::PhysPortId(_) => IFLA_PHYS_PORT_ID,
            Self::PhysSwitchId(_) => IFLA_PHYS_SWITCH_ID,
            Self::LinkInfo(_) => IFLA_LINKINFO,
            Self::Wireless(_) => IFLA_WIRELESS,
            Self::ProtoInfo(_) => IFLA_PROTINFO,
            Self::Pad(_) => IFLA_PAD,
            Self::Xdp(_) => IFLA_XDP,
            Self::Event(_) => IFLA_EVENT,
            Self::NewNetnsId(_) => IFLA_NEW_NETNSID,
            Self::IfNetnsId(_) => IFLA_IF_NETNSID,
            Self::CarrierUpCount(_) => IFLA_CARRIER_UP_COUNT,
            Self::CarrierDownCount(_) => IFLA_CARRIER_DOWN_COUNT,
            Self::NewIfIndex(_) => IFLA_NEW_IFINDEX,
            Self::PropList(_) => IFLA_PROP_LIST | NLA_F_NESTED,
            Self::ProtoDownReason(_) => IFLA_PROTO_DOWN_REASON,
            Self::Address(_) => IFLA_ADDRESS,
            Self::Broadcast(_) => IFLA_BROADCAST,
            Self::PermAddress(_) => IFLA_PERM_ADDRESS,
            Self::IfName(_) => IFLA_IFNAME,
            Self::Qdisc(_) => IFLA_QDISC,
            Self::IfAlias(_) => IFLA_IFALIAS,
            Self::PhysPortName(_) => IFLA_PHYS_PORT_NAME,
            Self::Mode(_) => IFLA_LINKMODE,
            Self::Carrier(_) => IFLA_CARRIER,
            Self::ProtoDown(_) => IFLA_PROTO_DOWN,
            Self::Mtu(_) => IFLA_MTU,
            Self::Link(_) => IFLA_LINK,
            Self::Controller(_) => IFLA_MASTER,
            Self::TxQueueLen(_) => IFLA_TXQLEN,
            Self::NetNsPid(_) => IFLA_NET_NS_PID,
            Self::NumVf(_) => IFLA_NUM_VF,
            Self::Group(_) => IFLA_GROUP,
            Self::NetNsFd(_) => IFLA_NET_NS_FD,
            Self::ExtMask(_) => IFLA_EXT_MASK,
            Self::Promiscuity(_) => IFLA_PROMISCUITY,
            Self::NumTxQueues(_) => IFLA_NUM_TX_QUEUES,
            Self::NumRxQueues(_) => IFLA_NUM_RX_QUEUES,
            Self::CarrierChanges(_) => IFLA_CARRIER_CHANGES,
            Self::GsoMaxSegs(_) => IFLA_GSO_MAX_SEGS,
            Self::GsoMaxSize(_) => IFLA_GSO_MAX_SIZE,
            Self::MinMtu(_) => IFLA_MIN_MTU,
            Self::MaxMtu(_) => IFLA_MAX_MTU,
            Self::NetnsId(_) => IFLA_LINK_NETNSID,
            Self::OperState(_) => IFLA_OPERSTATE,
            Self::Map(_) => IFLA_MAP,
            Self::Stats(_) => IFLA_STATS,
            Self::Stats64(_) => IFLA_STATS64,
            Self::AfSpecUnspec(_)
            | Self::AfSpecBridge(_)
            | Self::AfSpecUnknown(_) => IFLA_AF_SPEC,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NlaBuffer<&'a T>, AddressFamily> for LinkAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        interface_family: AddressFamily,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_WEIGHT => Self::Weight(payload.to_vec()),
            IFLA_VFINFO_LIST => Self::VfInfoList(payload.to_vec()),
            IFLA_VF_PORTS => Self::VfPorts(payload.to_vec()),
            IFLA_PORT_SELF => Self::PortSelf(payload.to_vec()),
            IFLA_PHYS_PORT_ID => Self::PhysPortId(payload.to_vec()),
            IFLA_PHYS_SWITCH_ID => Self::PhysSwitchId(payload.to_vec()),
            IFLA_WIRELESS => Self::Wireless(payload.to_vec()),
            IFLA_PROTINFO => Self::ProtoInfo(payload.to_vec()),
            IFLA_PAD => Self::Pad(payload.to_vec()),
            IFLA_EVENT => Self::Event(payload.to_vec()),
            IFLA_NEW_NETNSID => Self::NewNetnsId(payload.to_vec()),
            IFLA_IF_NETNSID => Self::IfNetnsId(payload.to_vec()),
            IFLA_CARRIER_UP_COUNT => Self::CarrierUpCount(payload.to_vec()),
            IFLA_CARRIER_DOWN_COUNT => Self::CarrierDownCount(payload.to_vec()),
            IFLA_NEW_IFINDEX => Self::NewIfIndex(payload.to_vec()),
            IFLA_PROP_LIST => {
                let error_msg = "invalid IFLA_PROP_LIST value";
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(error_msg)?;
                    let parsed = Prop::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::PropList(nlas)
            }
            IFLA_PROTO_DOWN_REASON => Self::ProtoDownReason(payload.to_vec()),
            // HW address (we parse them as Vec for now, because for IP over
            // GRE, the HW address is an IP instead of a MAC for
            // example
            IFLA_ADDRESS => Self::Address(payload.to_vec()),
            IFLA_BROADCAST => Self::Broadcast(payload.to_vec()),
            IFLA_PERM_ADDRESS => Self::PermAddress(payload.to_vec()),
            // String
            IFLA_IFNAME => Self::IfName(
                parse_string(payload).context("invalid IFLA_IFNAME value")?,
            ),
            IFLA_QDISC => Self::Qdisc(
                parse_string(payload).context("invalid IFLA_QDISC value")?,
            ),
            IFLA_IFALIAS => Self::IfAlias(
                parse_string(payload).context("invalid IFLA_IFALIAS value")?,
            ),
            IFLA_PHYS_PORT_NAME => Self::PhysPortName(
                parse_string(payload)
                    .context("invalid IFLA_PHYS_PORT_NAME value")?,
            ),
            // u8
            IFLA_LINKMODE => Self::Mode(
                parse_u8(payload).context("invalid IFLA_LINKMODE value")?,
            ),
            IFLA_CARRIER => Self::Carrier(
                parse_u8(payload).context("invalid IFLA_CARRIER value")?,
            ),
            IFLA_PROTO_DOWN => Self::ProtoDown(
                parse_u8(payload).context("invalid IFLA_PROTO_DOWN value")?,
            ),

            IFLA_MTU => {
                Self::Mtu(parse_u32(payload).context("invalid IFLA_MTU value")?)
            }
            IFLA_LINK => Self::Link(
                parse_u32(payload).context("invalid IFLA_LINK value")?,
            ),
            IFLA_MASTER => Self::Controller(
                parse_u32(payload).context("invalid IFLA_MASTER value")?,
            ),
            IFLA_TXQLEN => Self::TxQueueLen(
                parse_u32(payload).context("invalid IFLA_TXQLEN value")?,
            ),
            IFLA_NET_NS_PID => Self::NetNsPid(
                parse_u32(payload).context("invalid IFLA_NET_NS_PID value")?,
            ),
            IFLA_NUM_VF => Self::NumVf(
                parse_u32(payload).context("invalid IFLA_NUM_VF value")?,
            ),
            IFLA_GROUP => Self::Group(
                parse_u32(payload).context("invalid IFLA_GROUP value")?,
            ),
            IFLA_NET_NS_FD => Self::NetNsFd(
                parse_i32(payload).context("invalid IFLA_NET_NS_FD value")?,
            ),
            IFLA_EXT_MASK => Self::ExtMask(
                parse_u32(payload).context("invalid IFLA_EXT_MASK value")?,
            ),
            IFLA_PROMISCUITY => Self::Promiscuity(
                parse_u32(payload).context("invalid IFLA_PROMISCUITY value")?,
            ),
            IFLA_NUM_TX_QUEUES => Self::NumTxQueues(
                parse_u32(payload)
                    .context("invalid IFLA_NUM_TX_QUEUES value")?,
            ),
            IFLA_NUM_RX_QUEUES => Self::NumRxQueues(
                parse_u32(payload)
                    .context("invalid IFLA_NUM_RX_QUEUES value")?,
            ),
            IFLA_CARRIER_CHANGES => Self::CarrierChanges(
                parse_u32(payload)
                    .context("invalid IFLA_CARRIER_CHANGES value")?,
            ),
            IFLA_GSO_MAX_SEGS => Self::GsoMaxSegs(
                parse_u32(payload)
                    .context("invalid IFLA_GSO_MAX_SEGS value")?,
            ),
            IFLA_GSO_MAX_SIZE => Self::GsoMaxSize(
                parse_u32(payload)
                    .context("invalid IFLA_GSO_MAX_SIZE value")?,
            ),
            IFLA_MIN_MTU => Self::MinMtu(
                parse_u32(payload).context("invalid IFLA_MIN_MTU value")?,
            ),
            IFLA_MAX_MTU => Self::MaxMtu(
                parse_u32(payload).context("invalid IFLA_MAX_MTU value")?,
            ),
            IFLA_LINK_NETNSID => Self::NetnsId(
                parse_i32(payload)
                    .context("invalid IFLA_LINK_NETNSID value")?,
            ),
            IFLA_OPERSTATE => Self::OperState(
                parse_u8(payload)
                    .context("invalid IFLA_OPERSTATE value")?
                    .into(),
            ),
            IFLA_MAP => Self::Map(
                super::Map::parse(&MapBuffer::new(payload))
                    .context(format!("Invalid IFLA_MAP value {:?}", payload))?,
            ),
            IFLA_STATS => Self::Stats(
                super::Stats::parse(&StatsBuffer::new(payload)).context(
                    format!("Invalid IFLA_STATS value {:?}", payload),
                )?,
            ),
            IFLA_STATS64 => {
                let payload = expand_buffer_if_small(
                    payload,
                    LINK_STATS64_LEN,
                    "IFLA_STATS64",
                );
                Self::Stats64(
                    super::Stats64::parse(&Stats64Buffer::new(
                        payload.as_slice(),
                    ))
                    .context(format!(
                        "Invalid IFLA_STATS64 value {:?}",
                        payload
                    ))?,
                )
            }
            IFLA_AF_SPEC => match interface_family {
                AddressFamily::Unspec => Self::AfSpecUnspec(
                    VecAfSpecUnspec::parse(&NlaBuffer::new(&buf.value()))
                        .context("invalid IFLA_AF_SPEC value for AF_UNSPEC")?
                        .0,
                ),
                #[cfg(any(target_os = "linux", target_os = "fuchsia",))]
                AddressFamily::Bridge => Self::AfSpecBridge(
                    VecAfSpecBridge::parse(&NlaBuffer::new(&buf.value()))
                        .context("invalid IFLA_AF_SPEC value for AF_BRIDGE")?
                        .0,
                ),
                _ => Self::AfSpecUnknown(payload.to_vec()),
            },
            IFLA_LINKINFO => Self::LinkInfo(
                VecLinkInfo::parse(&NlaBuffer::new(&buf.value()))
                    .context("invalid IFLA_LINKINFO value")?
                    .0,
            ),
            IFLA_XDP => {
                let err = "invalid IFLA_XDP value";
                let buf = NlaBuffer::new_checked(payload).context(err)?;
                Self::Xdp(VecXdp::parse(&buf).context(err)?.0)
            }
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
