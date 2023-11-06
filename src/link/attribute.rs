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
    xdp::VecXdp, LinkInfo, Map, MapBuffer, Prop, State, Stats, Stats64,
    Stats64Buffer, StatsBuffer, Xdp,
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
const IFLA_PRIORITY: u16 = 9;
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
    Priority(Vec<u8>),
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
    // string
    // FIXME: for empty string, should we encode the NLA as \0 or should we
    // not set a payload? It seems that for certain attriutes, this
    // matter: https://elixir.bootlin.com/linux/v4.17-rc5/source/net/core/rtnetlink.c#L1660
    IfName(String),
    Qdisc(String),
    IfAlias(String),
    PhysPortName(String),
    // byte
    Mode(u8),
    Carrier(u8),
    ProtoDown(u8),
    // u32
    Mtu(u32),
    Link(u32),
    Master(u32),
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
    // i32
    NetnsId(i32),
    OperState(State),
    Stats(Stats),
    Stats64(Stats64),
    Map(Map),
    // AF_SPEC (the type of af_spec depends on the interface family of the
    // message)
    AfSpecUnspec(Vec<super::AfSpecUnspec>),
    AfSpecBridge(Vec<super::AfSpecBridge>),
    AfSpecUnknown(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for LinkAttribute {
    fn value_len(&self) -> usize {
        use self::LinkAttribute::*;
        match *self {
            Priority(ref bytes)
            | Weight(ref bytes)
            | VfInfoList(ref bytes)
            | VfPorts(ref bytes)
            | PortSelf(ref bytes)
            | PhysPortId(ref bytes)
            | PhysSwitchId(ref bytes)
            | Pad(ref bytes)
            | Event(ref bytes)
            | NewNetnsId(ref bytes)
            | IfNetnsId(ref bytes)
            | Wireless(ref bytes)
            | ProtoInfo(ref bytes)
            | CarrierUpCount(ref bytes)
            | CarrierDownCount(ref bytes)
            | NewIfIndex(ref bytes)
            | Address(ref bytes)
            | Broadcast(ref bytes)
            | PermAddress(ref bytes)
            | AfSpecUnknown(ref bytes)
            | ProtoDownReason(ref bytes) => bytes.len(),

            // strings: +1 because we need to append a nul byte
            IfName(ref string)
            | Qdisc(ref string)
            | IfAlias(ref string)
            | PhysPortName(ref string) => string.as_bytes().len() + 1,

            // u8
            Mode(_) | Carrier(_) | ProtoDown(_) => 1,

            // u32 and i32
            Mtu(_) | Link(_) | Master(_) | TxQueueLen(_) | NetNsPid(_)
            | NumVf(_) | Group(_) | NetNsFd(_) | ExtMask(_)
            | Promiscuity(_) | NumTxQueues(_) | NumRxQueues(_)
            | CarrierChanges(_) | GsoMaxSegs(_) | GsoMaxSize(_)
            | NetnsId(_) | MinMtu(_) | MaxMtu(_) => 4,

            OperState(_) => 1,
            Stats(_) => LINK_STATS_LEN,
            Stats64(_) => LINK_STATS64_LEN,
            Map(ref nla) => nla.buffer_len(),
            LinkInfo(ref nlas) => nlas.as_slice().buffer_len(),
            Xdp(ref nlas) => nlas.as_slice().buffer_len(),
            PropList(ref nlas) => nlas.as_slice().buffer_len(),
            AfSpecUnspec(ref nlas) => nlas.as_slice().buffer_len(),
            AfSpecBridge(ref nlas) => nlas.as_slice().buffer_len(),
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::LinkAttribute::*;
        match *self {
            // Vec<u8>
                Priority(ref bytes)
                | Weight(ref bytes)
                | VfInfoList(ref bytes)
                | VfPorts(ref bytes)
                | PortSelf(ref bytes)
                | PhysPortId(ref bytes)
                | PhysSwitchId(ref bytes)
                | Wireless(ref bytes)
                | ProtoInfo(ref bytes)
                | Pad(ref bytes)
                | Event(ref bytes)
                | NewNetnsId(ref bytes)
                | IfNetnsId(ref bytes)
                | CarrierUpCount(ref bytes)
                | CarrierDownCount(ref bytes)
                | NewIfIndex(ref bytes)
                // mac address (could be [u8; 6] or [u8; 4] for example. Not
                // sure if we should have a separate type for them
                | Address(ref bytes)
                | Broadcast(ref bytes)
                | PermAddress(ref bytes)
                | AfSpecUnknown(ref bytes)
                | ProtoDownReason(ref bytes)
                => buffer.copy_from_slice(bytes.as_slice()),

            // String
            IfName(ref string)
                | Qdisc(ref string)
                | IfAlias(ref string)
                | PhysPortName(ref string)
                => {
                    buffer[..string.len()].copy_from_slice(string.as_bytes());
                    buffer[string.len()] = 0;
                }

            // u8
            Mode(ref val)
                | Carrier(ref val)
                | ProtoDown(ref val)
                => buffer[0] = *val,

            // u32
            Mtu(ref value)
                | Link(ref value)
                | Master(ref value)
                | TxQueueLen(ref value)
                | NetNsPid(ref value)
                | NumVf(ref value)
                | Group(ref value)
                | ExtMask(ref value)
                | Promiscuity(ref value)
                | NumTxQueues(ref value)
                | NumRxQueues(ref value)
                | CarrierChanges(ref value)
                | GsoMaxSegs(ref value)
                | GsoMaxSize(ref value)
                | MinMtu(ref value)
                | MaxMtu(ref value)
                => NativeEndian::write_u32(buffer, *value),

            NetnsId(ref value)
                | NetNsFd(ref value)
                => NativeEndian::write_i32(buffer, *value),
            Stats(ref nla) => nla.emit(buffer),
            Map(ref nla) => nla.emit(buffer),
            Stats64(ref nla) => nla.emit(buffer),
            OperState(state) => buffer[0] = state.into(),
            LinkInfo(ref nlas) => nlas.as_slice().emit(buffer),
            Xdp(ref nlas) => nlas.as_slice().emit(buffer),
            PropList(ref nlas) => nlas.as_slice().emit(buffer),
            AfSpecUnspec(ref nlas) => nlas.as_slice().emit(buffer),
            AfSpecBridge(ref nlas) => nlas.as_slice().emit(buffer),
            // default nlas
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::LinkAttribute::*;
        match *self {
            Priority(_) => IFLA_PRIORITY,
            Weight(_) => IFLA_WEIGHT,
            VfInfoList(_) => IFLA_VFINFO_LIST,
            VfPorts(_) => IFLA_VF_PORTS,
            PortSelf(_) => IFLA_PORT_SELF,
            PhysPortId(_) => IFLA_PHYS_PORT_ID,
            PhysSwitchId(_) => IFLA_PHYS_SWITCH_ID,
            LinkInfo(_) => IFLA_LINKINFO,
            Wireless(_) => IFLA_WIRELESS,
            ProtoInfo(_) => IFLA_PROTINFO,
            Pad(_) => IFLA_PAD,
            Xdp(_) => IFLA_XDP,
            Event(_) => IFLA_EVENT,
            NewNetnsId(_) => IFLA_NEW_NETNSID,
            IfNetnsId(_) => IFLA_IF_NETNSID,
            CarrierUpCount(_) => IFLA_CARRIER_UP_COUNT,
            CarrierDownCount(_) => IFLA_CARRIER_DOWN_COUNT,
            NewIfIndex(_) => IFLA_NEW_IFINDEX,
            PropList(_) => IFLA_PROP_LIST | NLA_F_NESTED,
            ProtoDownReason(_) => IFLA_PROTO_DOWN_REASON,
            // Mac address
            Address(_) => IFLA_ADDRESS,
            Broadcast(_) => IFLA_BROADCAST,
            PermAddress(_) => IFLA_PERM_ADDRESS,
            // String
            IfName(_) => IFLA_IFNAME,
            Qdisc(_) => IFLA_QDISC,
            IfAlias(_) => IFLA_IFALIAS,
            PhysPortName(_) => IFLA_PHYS_PORT_NAME,
            // u8
            Mode(_) => IFLA_LINKMODE,
            Carrier(_) => IFLA_CARRIER,
            ProtoDown(_) => IFLA_PROTO_DOWN,
            // u32
            Mtu(_) => IFLA_MTU,
            Link(_) => IFLA_LINK,
            Master(_) => IFLA_MASTER,
            TxQueueLen(_) => IFLA_TXQLEN,
            NetNsPid(_) => IFLA_NET_NS_PID,
            NumVf(_) => IFLA_NUM_VF,
            Group(_) => IFLA_GROUP,
            NetNsFd(_) => IFLA_NET_NS_FD,
            ExtMask(_) => IFLA_EXT_MASK,
            Promiscuity(_) => IFLA_PROMISCUITY,
            NumTxQueues(_) => IFLA_NUM_TX_QUEUES,
            NumRxQueues(_) => IFLA_NUM_RX_QUEUES,
            CarrierChanges(_) => IFLA_CARRIER_CHANGES,
            GsoMaxSegs(_) => IFLA_GSO_MAX_SEGS,
            GsoMaxSize(_) => IFLA_GSO_MAX_SIZE,
            MinMtu(_) => IFLA_MIN_MTU,
            MaxMtu(_) => IFLA_MAX_MTU,
            // i32
            NetnsId(_) => IFLA_LINK_NETNSID,
            // custom
            OperState(_) => IFLA_OPERSTATE,
            Map(_) => IFLA_MAP,
            Stats(_) => IFLA_STATS,
            Stats64(_) => IFLA_STATS64,
            AfSpecUnspec(_) | AfSpecBridge(_) | AfSpecUnknown(_) => {
                IFLA_AF_SPEC
            }
            Other(ref attr) => attr.kind(),
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
        use self::LinkAttribute::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_PRIORITY => Priority(payload.to_vec()),
            IFLA_WEIGHT => Weight(payload.to_vec()),
            IFLA_VFINFO_LIST => VfInfoList(payload.to_vec()),
            IFLA_VF_PORTS => VfPorts(payload.to_vec()),
            IFLA_PORT_SELF => PortSelf(payload.to_vec()),
            IFLA_PHYS_PORT_ID => PhysPortId(payload.to_vec()),
            IFLA_PHYS_SWITCH_ID => PhysSwitchId(payload.to_vec()),
            IFLA_WIRELESS => Wireless(payload.to_vec()),
            IFLA_PROTINFO => ProtoInfo(payload.to_vec()),
            IFLA_PAD => Pad(payload.to_vec()),
            IFLA_EVENT => Event(payload.to_vec()),
            IFLA_NEW_NETNSID => NewNetnsId(payload.to_vec()),
            IFLA_IF_NETNSID => IfNetnsId(payload.to_vec()),
            IFLA_CARRIER_UP_COUNT => CarrierUpCount(payload.to_vec()),
            IFLA_CARRIER_DOWN_COUNT => CarrierDownCount(payload.to_vec()),
            IFLA_NEW_IFINDEX => NewIfIndex(payload.to_vec()),
            IFLA_PROP_LIST => {
                let error_msg = "invalid IFLA_PROP_LIST value";
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(error_msg)?;
                    let parsed = Prop::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                PropList(nlas)
            }
            IFLA_PROTO_DOWN_REASON => ProtoDownReason(payload.to_vec()),
            // HW address (we parse them as Vec for now, because for IP over
            // GRE, the HW address is an IP instead of a MAC for
            // example
            IFLA_ADDRESS => Address(payload.to_vec()),
            IFLA_BROADCAST => Broadcast(payload.to_vec()),
            IFLA_PERM_ADDRESS => PermAddress(payload.to_vec()),
            // String
            IFLA_IFNAME => IfName(
                parse_string(payload).context("invalid IFLA_IFNAME value")?,
            ),
            IFLA_QDISC => Qdisc(
                parse_string(payload).context("invalid IFLA_QDISC value")?,
            ),
            IFLA_IFALIAS => IfAlias(
                parse_string(payload).context("invalid IFLA_IFALIAS value")?,
            ),
            IFLA_PHYS_PORT_NAME => PhysPortName(
                parse_string(payload)
                    .context("invalid IFLA_PHYS_PORT_NAME value")?,
            ),
            // u8
            IFLA_LINKMODE => {
                Mode(parse_u8(payload).context("invalid IFLA_LINKMODE value")?)
            }
            IFLA_CARRIER => Carrier(
                parse_u8(payload).context("invalid IFLA_CARRIER value")?,
            ),
            IFLA_PROTO_DOWN => ProtoDown(
                parse_u8(payload).context("invalid IFLA_PROTO_DOWN value")?,
            ),

            IFLA_MTU => {
                Mtu(parse_u32(payload).context("invalid IFLA_MTU value")?)
            }
            IFLA_LINK => {
                Link(parse_u32(payload).context("invalid IFLA_LINK value")?)
            }
            IFLA_MASTER => {
                Master(parse_u32(payload).context("invalid IFLA_MASTER value")?)
            }
            IFLA_TXQLEN => TxQueueLen(
                parse_u32(payload).context("invalid IFLA_TXQLEN value")?,
            ),
            IFLA_NET_NS_PID => NetNsPid(
                parse_u32(payload).context("invalid IFLA_NET_NS_PID value")?,
            ),
            IFLA_NUM_VF => {
                NumVf(parse_u32(payload).context("invalid IFLA_NUM_VF value")?)
            }
            IFLA_GROUP => {
                Group(parse_u32(payload).context("invalid IFLA_GROUP value")?)
            }
            IFLA_NET_NS_FD => NetNsFd(
                parse_i32(payload).context("invalid IFLA_NET_NS_FD value")?,
            ),
            IFLA_EXT_MASK => ExtMask(
                parse_u32(payload).context("invalid IFLA_EXT_MASK value")?,
            ),
            IFLA_PROMISCUITY => Promiscuity(
                parse_u32(payload).context("invalid IFLA_PROMISCUITY value")?,
            ),
            IFLA_NUM_TX_QUEUES => NumTxQueues(
                parse_u32(payload)
                    .context("invalid IFLA_NUM_TX_QUEUES value")?,
            ),
            IFLA_NUM_RX_QUEUES => NumRxQueues(
                parse_u32(payload)
                    .context("invalid IFLA_NUM_RX_QUEUES value")?,
            ),
            IFLA_CARRIER_CHANGES => CarrierChanges(
                parse_u32(payload)
                    .context("invalid IFLA_CARRIER_CHANGES value")?,
            ),
            IFLA_GSO_MAX_SEGS => GsoMaxSegs(
                parse_u32(payload)
                    .context("invalid IFLA_GSO_MAX_SEGS value")?,
            ),
            IFLA_GSO_MAX_SIZE => GsoMaxSize(
                parse_u32(payload)
                    .context("invalid IFLA_GSO_MAX_SIZE value")?,
            ),
            IFLA_MIN_MTU => MinMtu(
                parse_u32(payload).context("invalid IFLA_MIN_MTU value")?,
            ),
            IFLA_MAX_MTU => MaxMtu(
                parse_u32(payload).context("invalid IFLA_MAX_MTU value")?,
            ),
            IFLA_LINK_NETNSID => NetnsId(
                parse_i32(payload)
                    .context("invalid IFLA_LINK_NETNSID value")?,
            ),
            IFLA_OPERSTATE => OperState(
                parse_u8(payload)
                    .context("invalid IFLA_OPERSTATE value")?
                    .into(),
            ),
            IFLA_MAP => Map(super::Map::parse(&MapBuffer::new(payload))
                .context(format!("Invalid IFLA_MAP value {:?}", payload))?),
            IFLA_STATS => {
                Stats(super::Stats::parse(&StatsBuffer::new(payload)).context(
                    format!("Invalid IFLA_STATS value {:?}", payload),
                )?)
            }
            IFLA_STATS64 => {
                let payload = expand_buffer_if_small(
                    payload,
                    LINK_STATS64_LEN,
                    "IFLA_STATS64",
                );
                Stats64(
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
                AddressFamily::Unspec => AfSpecUnspec(
                    VecAfSpecUnspec::parse(&NlaBuffer::new(&buf.value()))
                        .context("invalid IFLA_AF_SPEC value for AF_UNSPEC")?
                        .0,
                ),
                #[cfg(any(target_os = "linux", target_os = "fuchsia",))]
                AddressFamily::Bridge => AfSpecBridge(
                    VecAfSpecBridge::parse(&NlaBuffer::new(&buf.value()))
                        .context("invalid IFLA_AF_SPEC value for AF_BRIDGE")?
                        .0,
                ),
                _ => AfSpecUnknown(payload.to_vec()),
            },
            IFLA_LINKINFO => LinkInfo(
                VecLinkInfo::parse(&NlaBuffer::new(&buf.value()))
                    .context("invalid IFLA_LINKINFO value")?
                    .0,
            ),
            IFLA_XDP => {
                let err = "invalid IFLA_XDP value";
                let buf = NlaBuffer::new_checked(payload).context(err)?;
                Xdp(VecXdp::parse(&buf).context(err)?.0)
            }
            kind => Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
