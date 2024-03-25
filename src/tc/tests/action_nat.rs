// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use netlink_packet_utils::{Emitable, Parseable};

use crate::{
    tc::{
        filters::{TcU32OptionFlags, TcU32SelectorFlags},
        TcAction, TcActionAttribute, TcActionGeneric, TcActionNatOption,
        TcActionOption, TcActionType, TcAttribute, TcFilterU32Option, TcHandle,
        TcHeader, TcMessage, TcMessageBuffer, TcNat, TcNatFlags, TcOption,
        TcStats2, TcStatsBasic, TcStatsQueue, TcU32Key, TcU32Selector,
    },
    AddressFamily,
};

// Setup:
//      ip link add dummy1 type dummy
//      ip link set dummy1 up
//      tc qdisc add dev dummy1 root handle 1: prio bands 4
//      tc filter add dev dummy1 parent ffff: \
//          protocol ip prio 10 u32 \
//              match ip dst 192.0.2.1/32 \
//              action nat ingress 192.0.2.1/32 203.0.113.1
//
// Capture nlmon of this command:
//
//      tc -s filter show dev dummy1
//
// Raw packet modification:
//   * rtnetlink header removed.
#[test]
fn test_get_filter_nat() {
    let raw = vec![
        0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x80,
        0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x75, 0x33, 0x32, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x00, 0x24, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x02, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x08, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x00, 0x00, 0xac, 0x00, 0x07, 0x00,
        0xa8, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x6e, 0x61, 0x74, 0x00,
        0x44, 0x00, 0x04, 0x00, 0x14, 0x00, 0x01, 0x00, 0x62, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x02, 0x00, 0x28, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x02,
        0xcb, 0x00, 0x71, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x02, 0x00, 0x87, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x78, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x09, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let expected = TcMessage {
        header: TcHeader {
            family: AddressFamily::Unspec,
            index: 53,
            handle: TcHandle {
                major: 0x8000,
                minor: 0x800,
            },
            parent: TcHandle { major: 1, minor: 0 },
            info: 262152, // TODO(Gris Ge)
        },
        attributes: vec![
            TcAttribute::Kind("u32".to_string()),
            TcAttribute::Chain(0),
            TcAttribute::Options(vec![
                TcOption::U32(TcFilterU32Option::Selector(TcU32Selector {
                    flags: TcU32SelectorFlags::Terminal,
                    offshift: 0,
                    nkeys: 1,
                    offmask: 0,
                    off: 0,
                    offoff: 0,
                    hoff: 0,
                    hmask: 0,
                    keys: vec![TcU32Key {
                        mask: 0xffffffff,
                        val: u32::from_ne_bytes(
                            Ipv4Addr::new(192, 0, 2, 2).octets(),
                        ),
                        off: 16,
                        offmask: 0,
                    }],
                })),
                TcOption::U32(TcFilterU32Option::Hash(u32::from_be(0x80))),
                TcOption::U32(TcFilterU32Option::Flags(
                    TcU32OptionFlags::NotInHw,
                )),
                TcOption::U32(TcFilterU32Option::Action(vec![TcAction {
                    tab: 1,
                    attributes: vec![
                        TcActionAttribute::Kind("nat".to_string()),
                        TcActionAttribute::Stats(vec![
                            TcStats2::Basic(TcStatsBasic {
                                bytes: 98,
                                packets: 1,
                            }),
                            TcStats2::BasicHw(TcStatsBasic {
                                bytes: 0,
                                packets: 0,
                            }),
                            TcStats2::Queue(TcStatsQueue {
                                qlen: 0,
                                backlog: 0,
                                drops: 0,
                                requeues: 0,
                                overlimits: 0,
                            }),
                        ]),
                        TcActionAttribute::InHwCount(0),
                        TcActionAttribute::Options(vec![
                            TcActionOption::Nat(TcActionNatOption::Parms(
                                TcNat {
                                    generic: TcActionGeneric {
                                        index: 1,
                                        capab: 0,
                                        action: TcActionType::Ok,
                                        refcnt: 1,
                                        bindcnt: 1,
                                    },
                                    old_addr: Ipv4Addr::new(192, 0, 2, 2),
                                    new_addr: Ipv4Addr::new(203, 0, 113, 1),
                                    mask: Ipv4Addr::new(255, 255, 255, 255),
                                    flags: TcNatFlags::empty(),
                                },
                            )),
                            TcActionOption::Nat(TcActionNatOption::Tm(vec![
                                135, 20, 0, 0, 0, 0, 0, 0, 120, 7, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 7, 0, 0, 0,
                                0, 0, 0,
                            ])),
                        ]),
                    ],
                }])),
                TcOption::U32(TcFilterU32Option::Pnct(vec![
                    4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
                    0, 0, 0, 0,
                ])),
            ]),
        ],
    };

    assert_eq!(
        expected,
        TcMessage::parse(&TcMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
