// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use netlink_packet_utils::{nla::DefaultNla, Emitable, Parseable};

use crate::link::link_flag::LinkFlags;
use crate::link::{
    AfSpecInet, AfSpecInet6, AfSpecUnspec, Inet6CacheInfo, Inet6DevConf,
    Inet6IfaceFlags, InetDevConf, InfoData, InfoKind, InfoVxlan, LinkAttribute,
    LinkHeader, LinkInfo, LinkLayerType, LinkMessage, LinkMessageBuffer,
    LinkXdp, Map, State, Stats, Stats64, XdpAttached,
};
use crate::AddressFamily;

#[test]
fn test_parsing_link_vxlan() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x43, 0x10, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x76, 0x78, 0x6c, 0x61,
        0x6e, 0x30, 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x11, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0xaa, 0x05, 0x00, 0x00,
        0x08, 0x00, 0x32, 0x00, 0x44, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x3d, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x28, 0x00, 0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x29, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x08, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x3b, 0x00, 0xf8, 0xff, 0x07, 0x00,
        0x08, 0x00, 0x3c, 0x00, 0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x6e, 0x6f, 0x71, 0x75, 0x65, 0x75, 0x65, 0x00,
        0x08, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x0e, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00,
        0x00, 0x23, 0x45, 0x67, 0x89, 0x1c, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xcc, 0x00, 0x17, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x2b, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xdc, 0x00, 0x12, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x76, 0x78, 0x6c, 0x61,
        0x6e, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x65, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x00, 0x03, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
        0x01, 0x01, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0d, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
        0x2c, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x0f, 0x00, 0x12, 0xb5, 0x00, 0x00, 0x05, 0x00, 0x12, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x15, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x1a, 0x00, 0x8c, 0x00, 0x02, 0x00,
        0x88, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x27, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x10, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x10, 0x00, 0x00, 0x80, 0x14, 0x00, 0x05, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xb0, 0x1c, 0x00, 0x00, 0x0e, 0x8c, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0xf0, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0xaa, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xa0, 0x0f, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x3a, 0x09, 0x00, 0x80, 0x51, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x58, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x60, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xee, 0x36, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x3e, 0x80,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 16,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Broadcast
                | LinkFlags::LowerUp
                | LinkFlags::Multicast
                | LinkFlags::Running
                | LinkFlags::Up,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![
            LinkAttribute::IfName("vxlan0".into()),
            LinkAttribute::TxQueueLen(1000),
            LinkAttribute::OperState(State::Unknown),
            LinkAttribute::Mode(0),
            LinkAttribute::Mtu(1450),
            LinkAttribute::MinMtu(68),
            LinkAttribute::MaxMtu(65535),
            LinkAttribute::Group(0),
            LinkAttribute::Promiscuity(0),
            LinkAttribute::Other(DefaultNla::new(61, vec![0, 0, 0, 0])),
            LinkAttribute::NumTxQueues(1),
            LinkAttribute::GsoMaxSegs(65535),
            LinkAttribute::GsoMaxSize(65536),
            LinkAttribute::Other(DefaultNla::new(58, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(63, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(64, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(59, vec![248, 255, 7, 0])),
            LinkAttribute::Other(DefaultNla::new(60, vec![255, 255, 0, 0])),
            LinkAttribute::NumRxQueues(1),
            LinkAttribute::Carrier(1),
            LinkAttribute::Qdisc("noqueue".to_string()),
            LinkAttribute::CarrierChanges(0),
            LinkAttribute::CarrierUpCount(0),
            LinkAttribute::CarrierDownCount(0),
            LinkAttribute::ProtoDown(0),
            LinkAttribute::Map(Map {
                memory_start: 0,
                memory_end: 0,
                base_address: 0,
                irq: 0,
                dma: 0,
                port: 0,
            }),
            LinkAttribute::Address(vec![0x00, 0x23, 0x45, 0x67, 0x89, 0x1c]),
            LinkAttribute::Broadcast(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            LinkAttribute::Stats64(Stats64 {
                rx_packets: 0,
                tx_packets: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_errors: 0,
                tx_errors: 698,
                rx_dropped: 0,
                tx_dropped: 0,
                multicast: 0,
                collisions: 0,
                rx_length_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                rx_frame_errors: 0,
                rx_fifo_errors: 0,
                rx_missed_errors: 0,
                tx_aborted_errors: 0,
                tx_carrier_errors: 698,
                tx_fifo_errors: 0,
                tx_heartbeat_errors: 0,
                tx_window_errors: 0,
                rx_compressed: 0,
                tx_compressed: 0,
                rx_nohandler: 0,
                rx_otherhost_dropped: 0,
            }),
            LinkAttribute::Stats(Stats {
                rx_packets: 0,
                tx_packets: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_errors: 0,
                tx_errors: 698,
                rx_dropped: 0,
                tx_dropped: 0,
                multicast: 0,
                collisions: 0,
                rx_length_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                rx_frame_errors: 0,
                rx_fifo_errors: 0,
                rx_missed_errors: 0,
                tx_aborted_errors: 0,
                tx_carrier_errors: 698,
                tx_fifo_errors: 0,
                tx_heartbeat_errors: 0,
                tx_window_errors: 0,
                rx_compressed: 0,
                tx_compressed: 0,
                rx_nohandler: 0,
            }),
            LinkAttribute::Xdp(vec![LinkXdp::Attached(XdpAttached::None)]),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Vxlan),
                LinkInfo::Data(InfoData::Vxlan(vec![
                    InfoVxlan::Id(101),
                    InfoVxlan::Group(
                        Ipv4Addr::from_str("8.8.8.8").unwrap().into(),
                    ),
                    InfoVxlan::Link(13),
                    InfoVxlan::Local(
                        Ipv4Addr::from_str("1.1.1.1").unwrap().into(),
                    ),
                    InfoVxlan::Ttl(0),
                    InfoVxlan::TtlInherit(false),
                    InfoVxlan::Tos(0),
                    InfoVxlan::Df(0),
                    InfoVxlan::Label(0),
                    InfoVxlan::Learning(true),
                    InfoVxlan::Proxy(false),
                    InfoVxlan::Rsc(false),
                    InfoVxlan::L2Miss(false),
                    InfoVxlan::L3Miss(false),
                    InfoVxlan::CollectMetadata(false),
                    InfoVxlan::Ageing(300),
                    InfoVxlan::Limit(0),
                    InfoVxlan::Port(4789),
                    InfoVxlan::UDPCsum(true),
                    InfoVxlan::UDPZeroCsumTX(false),
                    InfoVxlan::UDPZeroCsumRX(false),
                    InfoVxlan::RemCsumTX(false),
                    InfoVxlan::RemCsumRX(false),
                    InfoVxlan::Localbypass(true),
                    InfoVxlan::PortRange((0, 0)),
                ])),
            ]),
            LinkAttribute::AfSpecUnspec(vec![
                AfSpecUnspec::Inet(vec![AfSpecInet::DevConf(InetDevConf {
                    forwarding: 1,
                    mc_forwarding: 0,
                    proxy_arp: 0,
                    accept_redirects: 1,
                    secure_redirects: 1,
                    send_redirects: 1,
                    shared_media: 1,
                    rp_filter: 2,
                    accept_source_route: 0,
                    bootp_relay: 0,
                    log_martians: 0,
                    tag: 0,
                    arpfilter: 0,
                    medium_id: 0,
                    noxfrm: 0,
                    nopolicy: 0,
                    force_igmp_version: 0,
                    arp_announce: 0,
                    arp_ignore: 0,
                    promote_secondaries: 1,
                    arp_accept: 0,
                    arp_notify: 0,
                    accept_local: 0,
                    src_vmark: 0,
                    proxy_arp_pvlan: 0,
                    route_localnet: 0,
                    igmpv2_unsolicited_report_interval: 10000,
                    igmpv3_unsolicited_report_interval: 1000,
                    ignore_routes_with_linkdown: 0,
                    drop_unicast_in_l2_multicast: 0,
                    drop_gratuitous_arp: 0,
                    bc_forwarding: 0,
                    arp_evict_nocarrier: 1,
                })]),
                AfSpecUnspec::Inet6(vec![
                    AfSpecInet6::Flags(
                        Inet6IfaceFlags::RsSent | Inet6IfaceFlags::Ready,
                    ),
                    AfSpecInet6::CacheInfo(Inet6CacheInfo {
                        max_reasm_len: 65535,
                        tstamp: 7344,
                        reachable_time: 35854,
                        retrans_time: 1000,
                    }),
                    AfSpecInet6::DevConf(Inet6DevConf {
                        forwarding: 0,
                        hoplimit: 64,
                        mtu6: 1450,
                        accept_ra: 1,
                        accept_redirects: 1,
                        autoconf: 1,
                        dad_transmits: 1,
                        rtr_solicits: -1,
                        rtr_solicit_interval: 4000,
                        rtr_solicit_delay: 1000,
                        use_tempaddr: 0,
                        temp_valid_lft: 604800,
                        temp_prefered_lft: 86400,
                        regen_max_retry: 3,
                        max_desync_factor: 600,
                        max_addresses: 16,
                        force_mld_version: 0,
                        accept_ra_defrtr: 1,
                        accept_ra_pinfo: 1,
                        accept_ra_rtr_pref: 1,
                        rtr_probe_interval: 60000,
                        accept_ra_rt_info_max_plen: 0,
                        proxy_ndp: 0,
                        optimistic_dad: 0,
                        accept_source_route: 0,
                        mc_forwarding: 0,
                        disable_ipv6: 0,
                        accept_dad: 1,
                        force_tllao: 0,
                        ndisc_notify: 0,
                        mldv1_unsolicited_report_interval: 10000,
                        mldv2_unsolicited_report_interval: 1000,
                        suppress_frag_ndisc: 1,
                        accept_ra_from_local: 0,
                        use_optimistic: 0,
                        accept_ra_mtu: 1,
                        stable_secret: 0,
                        use_oif_addrs_only: 0,
                        accept_ra_min_hop_limit: 1,
                        ignore_routes_with_linkdown: 0,
                        drop_unicast_in_l2_multicast: 0,
                        drop_unsolicited_na: 0,
                        keep_addr_on_down: 0,
                        rtr_solicit_max_interval: 3600000,
                        seg6_enabled: 0,
                        seg6_require_hmac: 0,
                        enhanced_dad: 1,
                        addr_gen_mode: 0,
                        disable_policy: 0,
                        accept_ra_rt_info_min_plen: 0,
                        ndisc_tclass: 0,
                        rpl_seg_enabled: 0,
                        ra_defrtr_metric: 1024,
                        ioam6_enabled: 0,
                        ioam6_id: 65535,
                        ioam6_id_wide: -1,
                        ndisc_evict_nocarrier: 1,
                        accept_untracked_na: 0,
                        accept_ra_min_lft: 0,
                    }),
                ]),
            ]),
            LinkAttribute::Other(DefaultNla::new(32830, vec![])),
        ],
    };

    assert_eq!(
        expected,
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

#[test]
fn test_parsing_link_vxlan_ipv6() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0xbe, 0x69, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x76, 0x78, 0x6c, 0x61,
        0x6e, 0x31, 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x11, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x96, 0x05, 0x00, 0x00,
        0x08, 0x00, 0x32, 0x00, 0x44, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1f, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x28, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x08, 0x00, 0x29, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x20, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x06, 0x00, 0x6e, 0x6f, 0x6f, 0x70, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x0c, 0x00, 0x2b, 0x00,
        0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x12, 0x00,
        0x0a, 0x00, 0x01, 0x00, 0x76, 0x78, 0x6c, 0x61, 0x6e, 0x00, 0x00, 0x00,
        0xec, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x10, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x03, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x11, 0x00, 0xfd, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0b, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0e, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x08, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x0f, 0x00, 0x21, 0x18, 0x00, 0x00,
        0x05, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x13, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x16, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 27070,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Broadcast | LinkFlags::Multicast,
            change_mask: LinkFlags::empty(),
        },
        attributes: vec![
            LinkAttribute::IfName("vxlan1".into()),
            LinkAttribute::TxQueueLen(1000),
            LinkAttribute::OperState(State::Down),
            LinkAttribute::Mode(0),
            LinkAttribute::Mtu(1430),
            LinkAttribute::MinMtu(68),
            LinkAttribute::MaxMtu(65535),
            LinkAttribute::Group(0),
            LinkAttribute::Promiscuity(0),
            LinkAttribute::NumTxQueues(1),
            LinkAttribute::GsoMaxSegs(65535),
            LinkAttribute::GsoMaxSize(65536),
            LinkAttribute::NumRxQueues(1),
            LinkAttribute::Carrier(1),
            LinkAttribute::Qdisc("noop".to_string()),
            LinkAttribute::CarrierChanges(0),
            LinkAttribute::CarrierUpCount(0),
            LinkAttribute::CarrierDownCount(0),
            LinkAttribute::ProtoDown(0),
            LinkAttribute::Address(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            LinkAttribute::Broadcast(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            LinkAttribute::Xdp(vec![LinkXdp::Attached(XdpAttached::None)]),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Vxlan),
                LinkInfo::Data(InfoData::Vxlan(vec![
                    InfoVxlan::Id(12),
                    InfoVxlan::Group6(
                        Ipv6Addr::from_str("ff00::1").unwrap().into(),
                    ),
                    InfoVxlan::Link(2),
                    InfoVxlan::Local6(
                        Ipv6Addr::from_str("fd01::2").unwrap().into(),
                    ),
                    InfoVxlan::Ttl(0),
                    InfoVxlan::TtlInherit(false),
                    InfoVxlan::Tos(0),
                    InfoVxlan::Df(0),
                    InfoVxlan::Label(0),
                    InfoVxlan::Other(DefaultNla::new(32, vec![0, 0, 0, 0])),
                    InfoVxlan::Learning(true),
                    InfoVxlan::Proxy(false),
                    InfoVxlan::Rsc(false),
                    InfoVxlan::L2Miss(false),
                    InfoVxlan::L3Miss(false),
                    InfoVxlan::CollectMetadata(false),
                    InfoVxlan::Ageing(300),
                    InfoVxlan::Limit(0),
                    InfoVxlan::Port(8472),
                    InfoVxlan::UDPCsum(true),
                    InfoVxlan::UDPZeroCsumTX(false),
                    InfoVxlan::UDPZeroCsumRX(false),
                    InfoVxlan::RemCsumTX(false),
                    InfoVxlan::RemCsumRX(false),
                    InfoVxlan::Localbypass(true),
                    InfoVxlan::PortRange((0, 0)),
                ])),
            ]),
        ],
    };

    assert_eq!(
        expected,
        LinkMessage::parse(&LinkMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
