// SPDX-License-Identifier: MIT

use std::{mem::size_of, os::unix::io::RawFd};

use netlink_packet_core::{
    append_bytes, append_i32, append_u32, parse_i32, parse_string, parse_u32,
    parse_u8, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable, ParseableParametrized, NLA_F_NESTED,
};

use super::{
    buffer_tool::expand_buffer_if_small, devlink_port::DevlinkPort,
    dpll_pin::DpllPin, ext_mask::VecLinkExtentMask, LinkEvent, LinkExtentMask,
    LinkMode, LinkPhysId, LinkProtoInfoBridge, LinkProtoInfoInet6,
    LinkProtocolDownReason, LinkXdp, Map, Prop, State, Stats, Stats64,
    Stats64Buffer, StatsBuffer, WirelessEvent,
};
#[cfg(feature = "link-info")]
use super::{link_info::VecLinkInfo, LinkInfo};
#[cfg(feature = "link-sriov")]
use super::{
    sriov::{VecLinkVfInfo, VecLinkVfPort},
    LinkVfInfo, LinkVfPort,
};
#[cfg(feature = "link-af-spec")]
use super::{AfSpecBridge, AfSpecUnspec};
use crate::AddressFamily;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_QDISC: u16 = 6;
const IFLA_STATS: u16 = 7;
// No kernel code is using IFLA_COST
// const IFLA_COST: u16 = 8;
// No kernel code is using IFLA_PRIORITY
// const IFLA_PRIORITY: u16 = 9;
const IFLA_MASTER: u16 = 10;
const IFLA_WIRELESS: u16 = 11;
const IFLA_PROTINFO: u16 = 12;
const IFLA_TXQLEN: u16 = 13;
const IFLA_MAP: u16 = 14;
// No kernel code is using IFLA_WEIGHT
// const IFLA_WEIGHT: u16 = 15;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKMODE: u16 = 17;
#[cfg(feature = "link-info")]
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_IFALIAS: u16 = 20;
const IFLA_NUM_VF: u16 = 21;
#[cfg(feature = "link-sriov")]
const IFLA_VFINFO_LIST: u16 = 22;
const IFLA_STATS64: u16 = 23;
#[cfg(feature = "link-sriov")]
const IFLA_VF_PORTS: u16 = 24;
#[cfg(feature = "link-sriov")]
const IFLA_PORT_SELF: u16 = 25;
#[cfg(feature = "link-af-spec")]
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
// const IFLA_PAD: u16 = 42;
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
const IFLA_PARENT_DEV_NAME: u16 = 56;
const IFLA_PARENT_DEV_BUS_NAME: u16 = 57;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;
const IFLA_DEVLINK_PORT: u16 = 62;
const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
const IFLA_DPLL_PIN: u16 = 65;
// const IFLA_MAX_PACING_OFFLOAD_HORIZON: u16 = 66;
const IFLA_NETNS_IMMUTABLE: u16 = 67;
// const IFLA_HEADROOM: u16 = 68;
// const IFLA_TAILROOM: u16 = 69;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum LinkAttribute {
    #[cfg(feature = "link-sriov")]
    VfInfoList(Vec<LinkVfInfo>),
    #[cfg(feature = "link-sriov")]
    VfPorts(Vec<LinkVfPort>),
    #[cfg(feature = "link-sriov")]
    PortSelf(LinkVfPort),
    PhysPortId(LinkPhysId),
    PhysSwitchId(LinkPhysId),
    Xdp(Vec<LinkXdp>),
    Event(LinkEvent),
    NewNetnsId(i32),
    IfNetnsId(i32),
    CarrierUpCount(u32),
    CarrierDownCount(u32),
    NewIfIndex(i32),
    #[cfg(feature = "link-info")]
    LinkInfo(Vec<LinkInfo>),
    ProtoInfoBridge(Vec<LinkProtoInfoBridge>),
    ProtoInfoInet6(Vec<LinkProtoInfoInet6>),
    ProtoInfoUnknown(DefaultNla),
    Wireless(WirelessEvent),
    PropList(Vec<Prop>),
    ProtoDownReason(Vec<LinkProtocolDownReason>),
    Address(Vec<u8>),
    Broadcast(Vec<u8>),
    /// Permanent hardware address of the device. The provides the same
    /// information as the ethtool ioctl interface.
    PermAddress(Vec<u8>),
    IfName(String),
    Qdisc(String),
    IfAlias(String),
    PhysPortName(String),
    Mode(LinkMode),
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
    ExtMask(Vec<LinkExtentMask>),
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
    LinkNetNsId(i32),
    OperState(State),
    Stats(Stats),
    Stats64(Stats64),
    Map(Map),
    // AF_SPEC (the type of af_spec depends on the interface family of the
    // message)
    #[cfg(feature = "link-af-spec")]
    AfSpecUnspec(Vec<AfSpecUnspec>),
    #[cfg(feature = "link-af-spec")]
    AfSpecBridge(Vec<AfSpecBridge>),
    #[cfg(feature = "link-af-spec")]
    AfSpecUnknown(Vec<u8>),
    ParentDevName(String),
    ParentDevBusName(String),
    GroMaxSize(u32),
    TsoMaxSize(u32),
    TsoMaxSegs(u32),
    AllMulticast(u32),
    GsoIpv4MaxSize(u32),
    GroIpv4MaxSize(u32),
    NetnsImmutable(bool),
    DevlinkPort(Vec<DevlinkPort>),
    DpllPin(Vec<DpllPin>),
    Other(DefaultNla),
}

impl Nla for LinkAttribute {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            #[cfg(feature = "link-sriov")]
            Self::VfInfoList(v) => (v).emit(out)?,
            #[cfg(feature = "link-sriov")]
            Self::VfPorts(v) => (v).emit(out)?,
            #[cfg(feature = "link-sriov")]
            Self::PortSelf(v) => v.emit(out)?,
            Self::PhysPortId(v) => v.emit(out)?,
            Self::PhysSwitchId(v) => v.emit(out)?,
            Self::Event(v) => v.emit(out)?,
            Self::ProtoInfoBridge(v) => (v).emit(out)?,
            Self::ProtoInfoInet6(v) => (v).emit(out)?,
            Self::ProtoDownReason(v) => (v).emit(out)?,
            Self::Address(bytes)
            | Self::Broadcast(bytes)
            | Self::PermAddress(bytes) => append_bytes(out, bytes.as_slice()),

            #[cfg(feature = "link-af-spec")]
            Self::AfSpecUnknown(bytes) => append_bytes(out, bytes.as_slice()),

            Self::IfName(string)
            | Self::Qdisc(string)
            | Self::IfAlias(string)
            | Self::PhysPortName(string)
            | Self::ParentDevName(string)
            | Self::ParentDevBusName(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Mode(v) => out.push((*v).into()),

            Self::Carrier(val) | Self::ProtoDown(val) => out.push(*val),

            Self::NetnsImmutable(val) => out.push(u8::from(*val)),

            Self::Mtu(value)
            | Self::Link(value)
            | Self::Controller(value)
            | Self::TxQueueLen(value)
            | Self::NetNsPid(value)
            | Self::NumVf(value)
            | Self::Group(value)
            | Self::Promiscuity(value)
            | Self::NumTxQueues(value)
            | Self::NumRxQueues(value)
            | Self::CarrierChanges(value)
            | Self::CarrierUpCount(value)
            | Self::CarrierDownCount(value)
            | Self::GsoMaxSegs(value)
            | Self::GsoMaxSize(value)
            | Self::MinMtu(value)
            | Self::MaxMtu(value)
            | Self::GroMaxSize(value)
            | Self::TsoMaxSize(value)
            | Self::TsoMaxSegs(value)
            | Self::AllMulticast(value)
            | Self::GsoIpv4MaxSize(value)
            | Self::GroIpv4MaxSize(value) => append_u32(out, *value),

            Self::ExtMask(value) => {
                append_u32(out, u32::from(&VecLinkExtentMask(value.to_vec())))
            }

            Self::LinkNetNsId(v)
            | Self::NetNsFd(v)
            | Self::NewNetnsId(v)
            | Self::NewIfIndex(v)
            | Self::IfNetnsId(v) => append_i32(out, *v),
            Self::Stats(nla) => nla.emit(out)?,
            Self::Map(nla) => nla.emit(out)?,
            Self::Stats64(nla) => nla.emit(out)?,
            Self::OperState(state) => out.push((*state).into()),
            #[cfg(feature = "link-info")]
            Self::LinkInfo(nlas) => (nlas).emit(out)?,
            Self::Xdp(nlas) => (nlas).emit(out)?,
            Self::PropList(nlas) => (nlas).emit(out)?,
            #[cfg(feature = "link-af-spec")]
            Self::AfSpecUnspec(nlas) => (nlas).emit(out)?,
            #[cfg(feature = "link-af-spec")]
            Self::AfSpecBridge(nlas) => (nlas).emit(out)?,
            Self::DevlinkPort(nlas) => (nlas).emit(out)?,
            Self::DpllPin(nlas) => (nlas).emit(out)?,
            Self::Wireless(v) => v.emit(out)?,
            Self::ProtoInfoUnknown(attr) | Self::Other(attr) => {
                append_bytes(out, attr.value())
            }
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            #[cfg(feature = "link-sriov")]
            Self::VfInfoList(_) => IFLA_VFINFO_LIST,
            #[cfg(feature = "link-sriov")]
            Self::VfPorts(_) => IFLA_VF_PORTS,
            #[cfg(feature = "link-sriov")]
            Self::PortSelf(_) => IFLA_PORT_SELF,
            Self::PhysPortId(_) => IFLA_PHYS_PORT_ID,
            Self::PhysSwitchId(_) => IFLA_PHYS_SWITCH_ID,
            #[cfg(feature = "link-info")]
            Self::LinkInfo(_) => IFLA_LINKINFO,
            Self::ProtoInfoBridge(_) | Self::ProtoInfoInet6(_) => {
                IFLA_PROTINFO | NLA_F_NESTED
            }
            Self::ProtoInfoUnknown(attr) => attr.kind(),
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
            Self::LinkNetNsId(_) => IFLA_LINK_NETNSID,
            Self::OperState(_) => IFLA_OPERSTATE,
            Self::Map(_) => IFLA_MAP,
            Self::Stats(_) => IFLA_STATS,
            Self::Stats64(_) => IFLA_STATS64,
            #[cfg(feature = "link-af-spec")]
            Self::AfSpecUnspec(_)
            | Self::AfSpecBridge(_)
            | Self::AfSpecUnknown(_) => IFLA_AF_SPEC,
            Self::Wireless(_) => IFLA_WIRELESS,
            Self::ParentDevName(_) => IFLA_PARENT_DEV_NAME,
            Self::ParentDevBusName(_) => IFLA_PARENT_DEV_BUS_NAME,
            Self::GroMaxSize(_) => IFLA_GRO_MAX_SIZE,
            Self::TsoMaxSize(_) => IFLA_TSO_MAX_SIZE,
            Self::TsoMaxSegs(_) => IFLA_TSO_MAX_SEGS,
            Self::AllMulticast(_) => IFLA_ALLMULTI,
            Self::GsoIpv4MaxSize(_) => IFLA_GSO_IPV4_MAX_SIZE,
            Self::GroIpv4MaxSize(_) => IFLA_GRO_IPV4_MAX_SIZE,
            Self::NetnsImmutable(_) => IFLA_NETNS_IMMUTABLE,
            Self::DevlinkPort(_) => IFLA_DEVLINK_PORT | NLA_F_NESTED,
            Self::DpllPin(_) => IFLA_DPLL_PIN | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a> ParseableParametrized<NlaBuffer<'a>, AddressFamily> for LinkAttribute {
    fn parse_with_param(
        buf: &NlaBuffer<'a>,
        interface_family: AddressFamily,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            #[cfg(feature = "link-sriov")]
            IFLA_VFINFO_LIST => {
                let err = || format!("invalid IFLA_VFINFO_LIST {payload:?}");
                if !payload.is_empty() {
                    Self::VfInfoList(
                        VecLinkVfInfo::parse(buf).with_context(err)?.0,
                    )
                } else {
                    // Empty IFLA_VFINFO_LIST, this is likely a netdevsim device
                    // no need to parse it, it is empty
                    Self::VfInfoList(vec![])
                }
            }
            #[cfg(feature = "link-sriov")]
            IFLA_VF_PORTS => {
                let err = || format!("invalid IFLA_VF_PORTS {payload:?}");
                Self::VfPorts(VecLinkVfPort::parse(buf).with_context(err)?.0)
            }
            #[cfg(feature = "link-sriov")]
            IFLA_PORT_SELF => {
                let err = || format!("invalid IFLA_PORT_SELF {payload:?}");
                Self::PortSelf(LinkVfPort::parse(buf).with_context(err)?)
            }
            IFLA_PHYS_PORT_ID => {
                Self::PhysPortId(LinkPhysId::parse(payload).with_context(
                    || format!("invalid IFLA_PHYS_PORT_ID value {payload:?}"),
                )?)
            }
            IFLA_PHYS_SWITCH_ID => {
                Self::PhysSwitchId(LinkPhysId::parse(payload).with_context(
                    || format!("invalid IFLA_PHYS_SWITCH_ID value {payload:?}"),
                )?)
            }
            IFLA_PROTINFO => {
                let err = || {
                    format!("invalid IFLA_PROTINFO for AF_INET6 {payload:?}")
                };
                match interface_family {
                    AddressFamily::Inet6 => Self::ProtoInfoInet6(
                        Vec::<LinkProtoInfoInet6>::parse(buf)
                            .with_context(err)?,
                    ),
                    #[cfg(any(
                        target_os = "linux",
                        target_os = "fuchsia",
                        target_os = "android"
                    ))]
                    AddressFamily::Bridge => Self::ProtoInfoBridge(
                        Vec::<LinkProtoInfoBridge>::parse(buf).with_context(
                            || {
                                format!(
                                    "invalid IFLA_PROTINFO for AF_BRIDGE \
                                     {payload:?}"
                                )
                            },
                        )?,
                    ),
                    _ => Self::ProtoInfoUnknown(
                        DefaultNla::parse(buf).with_context(|| {
                            format!(
                                "invalid IFLA_PROTINFO for \
                                 {interface_family:?}: {payload:?}"
                            )
                        })?,
                    ),
                }
            }
            IFLA_EVENT => {
                Self::Event(LinkEvent::parse(payload).with_context(|| {
                    format!("invalid IFLA_EVENT {payload:?}")
                })?)
            }
            IFLA_NEW_NETNSID => Self::NewNetnsId(
                parse_i32(payload).context("invalid IFLA_NEW_NETNSID value")?,
            ),
            IFLA_IF_NETNSID => Self::IfNetnsId(
                parse_i32(payload).context("invalid IFLA_IF_NETNSID value")?,
            ),
            IFLA_CARRIER_UP_COUNT => Self::CarrierUpCount(
                parse_u32(payload)
                    .context("invalid IFLA_CARRIER_UP_COUNT value")?,
            ),
            IFLA_CARRIER_DOWN_COUNT => Self::CarrierDownCount(
                parse_u32(payload)
                    .context("invalid IFLA_CARRIER_DOWN_COUNT value")?,
            ),
            IFLA_NEW_IFINDEX => Self::NewIfIndex(
                parse_i32(payload).context("invalid IFLA_NEW_IFINDEX value")?,
            ),

            IFLA_PROP_LIST => {
                let error_msg = "invalid IFLA_PROP_LIST value";
                let mut nlas = vec![];
                for nla in buf.nlas() {
                    let nla = &nla.context(error_msg)?;
                    let parsed = Prop::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::PropList(nlas)
            }
            IFLA_PROTO_DOWN_REASON => {
                let mut nlas = vec![];
                for nla in buf.nlas() {
                    let nla =
                        &nla.context("invalid IFLA_PROTO_DOWN_REASON value")?;
                    let parsed = LinkProtocolDownReason::parse(nla)?;
                    nlas.push(parsed);
                }
                Self::ProtoDownReason(nlas)
            }
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
            IFLA_LINKMODE => Self::Mode(LinkMode::from(
                parse_u8(payload).context("invalid IFLA_LINKMODE value")?,
            )),
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
                VecLinkExtentMask::from(
                    parse_u32(payload)
                        .context("invalid IFLA_EXT_MASK value")?,
                )
                .0,
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
            IFLA_LINK_NETNSID => Self::LinkNetNsId(
                parse_i32(payload)
                    .context("invalid IFLA_LINK_NETNSID value")?,
            ),
            IFLA_OPERSTATE => Self::OperState(
                parse_u8(payload)
                    .context("invalid IFLA_OPERSTATE value")?
                    .into(),
            ),
            IFLA_MAP => {
                Self::Map(super::Map::parse(payload).with_context(|| {
                    format!("Invalid IFLA_MAP value {payload:?}")
                })?)
            }
            IFLA_STATS => Self::Stats(
                super::Stats::parse(
                    expand_buffer_if_small(
                        payload,
                        size_of::<StatsBuffer>(),
                        "IFLA_STATS",
                    )
                    .as_slice(),
                )
                .with_context(|| {
                    format!("Invalid IFLA_STATS value {payload:?}")
                })?,
            ),
            IFLA_STATS64 => {
                let payload = expand_buffer_if_small(
                    payload,
                    size_of::<Stats64Buffer>(),
                    "IFLA_STATS64",
                );
                Self::Stats64(
                    super::Stats64::parse(payload.as_slice()).with_context(
                        || format!("Invalid IFLA_STATS64 value {payload:?}"),
                    )?,
                )
            }
            #[cfg(feature = "link-af-spec")]
            IFLA_AF_SPEC => match interface_family {
                AddressFamily::Unspec => {
                    let err = "invalid IFLA_AF_SPEC value for AF_UNSPEC";
                    Self::AfSpecUnspec(
                        Vec::<AfSpecUnspec>::parse(buf).context(err)?,
                    )
                }
                #[cfg(any(
                    target_os = "linux",
                    target_os = "fuchsia",
                    target_os = "android"
                ))]
                AddressFamily::Bridge => {
                    let err = "invalid IFLA_AF_SPEC value for AF_BRIDGE";
                    Self::AfSpecBridge(
                        Vec::<AfSpecBridge>::parse(buf).context(err)?,
                    )
                }
                _ => Self::AfSpecUnknown(payload.to_vec()),
            },
            #[cfg(feature = "link-info")]
            IFLA_LINKINFO => {
                let err = "invalid IFLA_LINKINFO value";
                Self::LinkInfo(VecLinkInfo::parse(buf).context(err)?.0)
            }
            IFLA_XDP => {
                let err = "invalid IFLA_XDP value";
                Self::Xdp(Vec::<LinkXdp>::parse(buf).context(err)?)
            }
            IFLA_WIRELESS => Self::Wireless(
                WirelessEvent::parse(payload)
                    .context("invalid IFLA_WIRELESS value")?,
            ),
            IFLA_PARENT_DEV_NAME => Self::ParentDevName(
                parse_string(payload)
                    .context("invalid IFLA_PARENT_DEV_NAME value")?,
            ),
            IFLA_PARENT_DEV_BUS_NAME => Self::ParentDevBusName(
                parse_string(payload)
                    .context("invalid IFLA_PARENT_DEV_BUS_NAME value")?,
            ),
            IFLA_GRO_MAX_SIZE => Self::GroMaxSize(
                parse_u32(payload)
                    .context("invalid IFLA_GRO_MAX_SIZE value")?,
            ),
            IFLA_TSO_MAX_SIZE => Self::TsoMaxSize(
                parse_u32(payload)
                    .context("invalid IFLA_TSO_MAX_SIZE value")?,
            ),
            IFLA_TSO_MAX_SEGS => Self::TsoMaxSegs(
                parse_u32(payload)
                    .context("invalid IFLA_TSO_MAX_SEGS value")?,
            ),
            IFLA_ALLMULTI => Self::AllMulticast(
                parse_u32(payload).context("invalid IFLA_ALLMULTI value")?,
            ),
            IFLA_GSO_IPV4_MAX_SIZE => Self::GsoIpv4MaxSize(
                parse_u32(payload)
                    .context("invalid IFLA_GSO_IPV4_MAX_SIZE value")?,
            ),
            IFLA_GRO_IPV4_MAX_SIZE => Self::GroIpv4MaxSize(
                parse_u32(payload)
                    .context("invalid IFLA_GRO_IPV4_MAX_SIZE value")?,
            ),
            IFLA_NETNS_IMMUTABLE => Self::NetnsImmutable(
                parse_u8(payload)
                    .context("invalid IFLA_NETNS_IMMUTABLE value")?
                    != 0,
            ),
            IFLA_DEVLINK_PORT => {
                let err = "invalid IFLA_DEVLINK_PORT value";
                let mut nlas = vec![];
                for nla in buf.nlas() {
                    let nla = &nla.context(err)?;
                    let parsed = DevlinkPort::parse(nla).context(err)?;
                    nlas.push(parsed);
                }
                Self::DevlinkPort(nlas)
            }
            IFLA_DPLL_PIN => {
                let err = "invalid IFLA_DPLL_PIN value";
                let mut nlas = vec![];
                for nla in buf.nlas() {
                    let nla = &nla.context(err)?;
                    let parsed = DpllPin::parse(nla).context(err)?;
                    nlas.push(parsed);
                }
                Self::DpllPin(nlas)
            }
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .with_context(|| format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
