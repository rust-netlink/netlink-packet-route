// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::{Emitable, Parseable};

use crate::tc::actions::message::TcActionMessage;
use crate::tc::actions::message::TcActionMessageAttribute::Actions;
use crate::tc::actions::{TcActionMessageBuffer, TcActionMessageHeader};
use crate::tc::TcActionAttribute::{InHwCount, Kind, Options, Stats};
use crate::tc::TcActionNatOption::{Parms, Tm};
use crate::tc::TcActionOption::Nat;
use crate::tc::TcStats2::{Basic, BasicHw, Queue};
use crate::tc::{
    TcAction, TcActionGeneric, TcActionNatOption, TcActionType, TcNat,
    TcNatFlags, TcStatsBasic, TcStatsQueue,
};
use crate::AddressFamily;

/// Capture of request for
///
/// ```bash
/// tc actions add action nat ingress 1.2.3.4/32 5.6.7.0 index 1
/// ```
const TC_ACTION_NAT_EXAMPLE1: &str = "000000003c00010038000100080001006e6174002c0002802800010001000000000000000000000000000000000000000102030405060700ffffffff00000000";

fn tc_action_message_nat_example1() -> TcActionMessage {
    TcActionMessage {
        header: TcActionMessageHeader {
            family: AddressFamily::Unspec,
        },
        attributes: vec![Actions(vec![TcAction {
            tab: 1,
            attributes: vec![
                Kind("nat".into()),
                Options(vec![Nat(TcActionNatOption::Parms(TcNat {
                    generic: TcActionGeneric {
                        index: 1,
                        capab: 0,
                        action: TcActionType::Ok,
                        refcnt: 0,
                        bindcnt: 0,
                    },
                    old_addr: Ipv4Addr::new(1, 2, 3, 4),
                    new_addr: Ipv4Addr::new(5, 6, 7, 0),
                    mask: Ipv4Addr::new(255, 255, 255, 255),
                    flags: TcNatFlags::empty(),
                }))]),
            ],
        }])],
    }
}

#[test]
fn parse_tc_action_nat_example1() {
    let buf = hex::decode(TC_ACTION_NAT_EXAMPLE1).unwrap();
    let parsed = TcActionMessage::parse(
        &TcActionMessageBuffer::new_checked(&buf).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed, tc_action_message_nat_example1());
}

#[test]
fn emit_tc_action_nat_example1() {
    let example = tc_action_message_nat_example1();
    let mut buf = vec![0; example.buffer_len()];
    example.emit(&mut buf);
    assert_eq!(buf, hex::decode(TC_ACTION_NAT_EXAMPLE1).unwrap());
}

/// Capture of request for
///
/// ```bash
/// tc actions add action nat ingress 1.2.3.0/24 5.6.7.9 index 2
/// ```
const TC_ACTION_NAT_EXAMPLE2: &str = "000000003c00010038000100080001006e6174002c0002802800010002000000000000000000000000000000000000000102030005060709ffffff0000000000";

fn tc_action_message_nat_example2() -> TcActionMessage {
    TcActionMessage {
        header: TcActionMessageHeader {
            family: AddressFamily::Unspec,
        },
        attributes: vec![Actions(vec![TcAction {
            tab: 1,
            attributes: vec![
                Kind("nat".into()),
                Options(vec![Nat(TcActionNatOption::Parms(TcNat {
                    generic: TcActionGeneric {
                        index: 2,
                        capab: 0,
                        action: TcActionType::Ok,
                        refcnt: 0,
                        bindcnt: 0,
                    },
                    old_addr: Ipv4Addr::new(1, 2, 3, 0),
                    new_addr: Ipv4Addr::new(5, 6, 7, 9),
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    flags: TcNatFlags::empty(),
                }))]),
            ],
        }])],
    }
}

#[test]
fn parse_tc_action_nat_example2() {
    let buf = hex::decode(TC_ACTION_NAT_EXAMPLE2).unwrap();
    let parsed = TcActionMessage::parse(
        &TcActionMessageBuffer::new_checked(&buf).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed, tc_action_message_nat_example2());
}

#[test]
fn emit_tc_action_nat_example2() {
    let example = tc_action_message_nat_example2();
    let mut buf = vec![0; example.buffer_len()];
    example.emit(&mut buf);
    assert_eq!(buf, hex::decode(TC_ACTION_NAT_EXAMPLE2).unwrap());
}

/// Capture of request for
///
/// ```bash
/// tc actions add action nat egress 2.3.4.0/24 5.6.7.9 index 3
/// ```
const TC_ACTION_NAT_EXAMPLE3: &str = "000000003c00010038000100080001006e6174002c0002802800010003000000000000000000000000000000000000000203040005060709ffffff0001000000";

fn tc_action_message_nat_example3() -> TcActionMessage {
    TcActionMessage {
        header: TcActionMessageHeader {
            family: AddressFamily::Unspec,
        },
        attributes: vec![Actions(vec![TcAction {
            tab: 1,
            attributes: vec![
                Kind("nat".into()),
                Options(vec![Nat(TcActionNatOption::Parms(TcNat {
                    generic: TcActionGeneric {
                        index: 3,
                        capab: 0,
                        action: TcActionType::Ok,
                        refcnt: 0,
                        bindcnt: 0,
                    },
                    old_addr: Ipv4Addr::new(2, 3, 4, 0),
                    new_addr: Ipv4Addr::new(5, 6, 7, 9),
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    flags: TcNatFlags::Egress,
                }))]),
            ],
        }])],
    }
}

#[test]
fn parse_tc_action_nat_example3() {
    let buf = hex::decode(TC_ACTION_NAT_EXAMPLE3).unwrap();
    let parsed = TcActionMessage::parse(
        &TcActionMessageBuffer::new_checked(&buf).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed, tc_action_message_nat_example3());
}

#[test]
fn emit_tc_action_nat_example3() {
    let example = tc_action_message_nat_example3();
    let mut buf = vec![0x00; example.buffer_len()];
    example.emit(&mut buf);
    assert_eq!(buf, hex::decode(TC_ACTION_NAT_EXAMPLE3).unwrap());
}

const TC_ACTION_NAT_OPTION_PARAMS_EXAMPLES: [TcActionNatOption; 2] = [
    TcActionNatOption::Parms(TcNat {
        flags: TcNatFlags::empty(),
        generic: TcActionGeneric {
            action: TcActionType::Reclassify,
            bindcnt: 1,
            capab: 2,
            index: 3,
            refcnt: 4,
        },
        mask: Ipv4Addr::BROADCAST,
        new_addr: Ipv4Addr::new(1, 2, 3, 4),
        old_addr: Ipv4Addr::new(5, 6, 7, 8),
    }),
    TcActionNatOption::Parms(TcNat {
        flags: TcNatFlags::empty(),
        generic: TcActionGeneric {
            action: TcActionType::Pipe,
            bindcnt: 5,
            capab: 6,
            index: 7,
            refcnt: 8,
        },
        mask: Ipv4Addr::new(255, 255, 255, 254),
        new_addr: Ipv4Addr::new(2, 1, 255, 0),
        old_addr: Ipv4Addr::new(7, 2, 88, 44),
    }),
];

#[test]
fn tc_action_nat_option_parse_back_example_params() {
    for example in TC_ACTION_NAT_OPTION_PARAMS_EXAMPLES {
        let mut buffer = vec![0; example.buffer_len()];
        example.emit(&mut buffer);
        let parsed = TcActionNatOption::parse(
            &NlaBuffer::new_checked(buffer.as_slice()).unwrap(),
        )
        .unwrap();
        assert_eq!(example, parsed);
    }
}

#[test]
fn tc_action_nat_option_emit_uses_whole_buffer() {
    for example in TC_ACTION_NAT_OPTION_PARAMS_EXAMPLES {
        let mut buffer1 = vec![0x00; example.buffer_len()];
        let mut buffer2 = vec![0xff; example.buffer_len()];
        example.emit(&mut buffer1);
        example.emit(&mut buffer2);
        assert_eq!(buffer1, buffer2);
    }
}

fn tc_action_nat_option_tm_examples() -> [TcActionNatOption; 4] {
    [
        TcActionNatOption::Tm(vec![]),
        TcActionNatOption::Tm(vec![1]),
        TcActionNatOption::Tm(vec![1, 2, 3, 4]),
        TcActionNatOption::Tm(vec![99; 10]),
    ]
}

#[test]
fn tc_action_nat_option_parse_back_example_tm() {
    for example in tc_action_nat_option_tm_examples().iter() {
        let mut buffer = vec![0; example.buffer_len()];
        example.emit(&mut buffer);
        let parsed = TcActionNatOption::parse(
            &NlaBuffer::new_checked(buffer.as_slice()).unwrap(),
        )
        .unwrap();
        assert_eq!(example, &parsed);
    }
}

#[test]
fn tc_action_nat_option_emit_tm_uses_whole_buffer() {
    for example in tc_action_nat_option_tm_examples().iter() {
        let mut buffer1 = vec![0x00; example.buffer_len()];
        let mut buffer2 = vec![0xff; example.buffer_len()];
        example.emit(&mut buffer1);
        example.emit(&mut buffer2);
        assert_eq!(buffer1, buffer2);
    }
}

/// Setup:
///
/// ```bash
/// tc actions flush action nat
/// tc actions add action nat ingress 192.0.2.1/32 203.0.113.1 index 1
/// ```
///
/// Then capture netlink response message of this command:
///
/// ```bash
/// tc -statistics actions get action nat index 1
/// ```
///
/// Raw packet modification:
///   * cooked header removed (16 bytes).
///   * rtnetlink header removed (16 bytes).
#[test]
fn test_get_filter_nat() {
    const RAW: &str = "00000000ac000100a8000100080001006e617400440004001400010000000000000000000000000000000000140007000000000000000000000000000000000018000300000000000000000000000000000000000000000008000a000000000050000200280001000100000000000000000000000100000000000000c0000201cb007101ffffffff00000000240002000000000000000000000000000000000000000000000000000000000000000000";
    let raw = hex::decode(RAW).unwrap();

    let expected = TcActionMessage {
        header: TcActionMessageHeader {
            family: AddressFamily::Unspec,
        },
        attributes: vec![Actions(vec![TcAction {
            tab: 1,
            attributes: vec![
                Kind("nat".into()),
                Stats(vec![
                    Basic(TcStatsBasic {
                        bytes: 0,
                        packets: 0,
                    }),
                    BasicHw(TcStatsBasic {
                        bytes: 0,
                        packets: 0,
                    }),
                    Queue(TcStatsQueue {
                        qlen: 0,
                        backlog: 0,
                        drops: 0,
                        requeues: 0,
                        overlimits: 0,
                    }),
                ]),
                InHwCount(0),
                Options(vec![
                    Nat(Parms(TcNat {
                        generic: TcActionGeneric {
                            index: 1,
                            capab: 0,
                            action: TcActionType::Ok,
                            refcnt: 1,
                            bindcnt: 0,
                        },
                        old_addr: [192, 0, 2, 1].into(),
                        new_addr: [203, 0, 113, 1].into(),
                        mask: Ipv4Addr::BROADCAST,
                        flags: TcNatFlags::empty(),
                    })),
                    Nat(Tm(vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ])),
                ]),
            ],
        }])],
    };

    assert_eq!(
        expected,
        TcActionMessage::parse(&TcActionMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
