// SPDX-License-Identifier: MIT

use netlink_packet_utils::{nla::DefaultNla, Emitable, Parseable};

use crate::{
    link::{
        link_flag::LinkFlags, LinkAttribute, LinkHeader, LinkLayerType,
        LinkMessage, LinkMessageBuffer, LinkMode, LinkXdp, Map, State, Stats,
        Stats64, XdpAttached,
    },
    AddressFamily,
};

#[test]
fn test_empty_af_spec() {
    let raw = vec![
        0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x0d, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x11, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0xdc, 0x05, 0x00, 0x00,
        0x08, 0x00, 0x32, 0x00, 0x44, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x00,
        0xdc, 0x05, 0x00, 0x00, 0x08, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x3d, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1f, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x28, 0x00, 0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x29, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x08, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x40, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x08, 0x00, 0x3c, 0x00, 0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x23, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2f, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xcc, 0x00, 0x17, 0x00,
        0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x37, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4a, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x07, 0x00,
        0x26, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x37, 0x10, 0x00, 0x00,
        0x4a, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x2b, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x06, 0x00, 0x6e, 0x6f, 0x6f, 0x70, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x1a, 0x00, 0x24, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let expected = LinkMessage {
        header: LinkHeader {
            interface_family: AddressFamily::Unspec,
            index: 4,
            link_layer_type: LinkLayerType::Ether,
            flags: LinkFlags::Broadcast | LinkFlags::Multicast,
            change_mask: LinkFlags::Up
                | LinkFlags::Broadcast
                | LinkFlags::Debug
                | LinkFlags::Loopback
                | LinkFlags::Pointopoint
                | LinkFlags::Notrailers
                | LinkFlags::Running
                | LinkFlags::Noarp
                | LinkFlags::Promisc
                | LinkFlags::Allmulti
                | LinkFlags::Controller
                | LinkFlags::Port
                | LinkFlags::Multicast
                | LinkFlags::Portsel
                | LinkFlags::Automedia
                | LinkFlags::Dynamic
                | LinkFlags::LowerUp
                | LinkFlags::Dormant
                | LinkFlags::Echo
                | LinkFlags::from_bits_retain(0xfff80000),
        },
        attributes: vec![
            LinkAttribute::TxQueueLen(1000),
            LinkAttribute::OperState(State::Down),
            LinkAttribute::Mode(LinkMode::Default),
            LinkAttribute::Mtu(1500),
            LinkAttribute::MinMtu(68),
            LinkAttribute::MaxMtu(1500),
            LinkAttribute::Group(0),
            LinkAttribute::Promiscuity(0),
            LinkAttribute::Other(DefaultNla::new(61, vec![0, 0, 0, 0])),
            LinkAttribute::NumTxQueues(4),
            LinkAttribute::GsoMaxSegs(65535),
            LinkAttribute::GsoMaxSize(65536),
            LinkAttribute::Other(DefaultNla::new(58, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(63, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(64, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(59, vec![0, 0, 1, 0])),
            LinkAttribute::Other(DefaultNla::new(60, vec![255, 255, 0, 0])),
            LinkAttribute::NumRxQueues(4),
            LinkAttribute::Carrier(0),
            LinkAttribute::CarrierChanges(6),
            LinkAttribute::CarrierUpCount(3),
            LinkAttribute::CarrierDownCount(3),
            LinkAttribute::ProtoDown(0),
            LinkAttribute::Broadcast(vec![255, 255, 255, 255, 255, 255]),
            LinkAttribute::Stats64(Stats64 {
                rx_packets: 38,
                tx_packets: 32,
                rx_bytes: 4151,
                tx_bytes: 3914,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 3,
                tx_dropped: 11,
                multicast: 0,
                collisions: 0,
                rx_length_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                rx_frame_errors: 0,
                rx_fifo_errors: 0,
                rx_missed_errors: 0,
                tx_aborted_errors: 0,
                tx_carrier_errors: 0,
                tx_fifo_errors: 0,
                tx_heartbeat_errors: 0,
                tx_window_errors: 0,
                rx_compressed: 0,
                tx_compressed: 0,
                rx_nohandler: 0,
                rx_otherhost_dropped: 0,
            }),
            LinkAttribute::Stats(Stats {
                rx_packets: 38,
                tx_packets: 32,
                rx_bytes: 4151,
                tx_bytes: 3914,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 3,
                tx_dropped: 11,
                multicast: 0,
                collisions: 0,
                rx_length_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                rx_frame_errors: 0,
                rx_fifo_errors: 0,
                rx_missed_errors: 0,
                tx_aborted_errors: 0,
                tx_carrier_errors: 0,
                tx_fifo_errors: 0,
                tx_heartbeat_errors: 0,
                tx_window_errors: 0,
                rx_compressed: 0,
                tx_compressed: 0,
                rx_nohandler: 0,
            }),
            LinkAttribute::Xdp(vec![LinkXdp::Attached(XdpAttached::None)]),
            LinkAttribute::Qdisc("noop".into()),
            LinkAttribute::AfSpecUnspec(vec![]), // empty
            LinkAttribute::Map(Map {
                memory_start: 0,
                memory_end: 0,
                base_address: 0,
                irq: 0,
                dma: 0,
                port: 0,
            }),
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
