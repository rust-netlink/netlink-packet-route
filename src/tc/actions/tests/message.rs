// SPDX-License-Identifier: MIT

use netlink_packet_utils::nla::{DefaultNla, NlaBuffer};
use netlink_packet_utils::{Emitable, Parseable};

use crate::tc::actions::message::TcActionMessageAttribute::{
    Actions, Flags, RootCount, RootExtWarnMsg, RootTimeDelta,
};
use crate::tc::actions::message::{
    TcActionMessage, TcActionMessageAttribute, TcActionMessageFlags,
    TcActionMessageFlagsWithSelector,
};
use crate::tc::actions::{TcActionMessageBuffer, TcActionMessageHeader};
use crate::tc::TcAction;
use crate::tc::TcActionAttribute::{Cookie, Index, Kind};
use crate::AddressFamily;

mod mirror {
    use netlink_packet_utils::nla::DefaultNla;
    use netlink_packet_utils::Parseable;

    use crate::tc::actions::message::TcActionMessage;
    use crate::tc::actions::message::TcActionMessageAttribute::{
        Actions, RootCount,
    };
    use crate::tc::actions::{TcActionMessageBuffer, TcActionMessageHeader};
    use crate::tc::TcActionAttribute::{
        InHwCount, Kind, Options, Other, Stats,
    };
    use crate::tc::TcActionMirrorOption::{Parms, Tm};
    use crate::tc::TcActionOption::Mirror;
    use crate::tc::TcActionType::{Pipe, Stolen};
    use crate::tc::TcMirrorActionType::{EgressRedir, IngressMirror};
    use crate::tc::TcStats2::{Basic, BasicHw, Queue};
    use crate::tc::{
        TcAction, TcActionGeneric, TcMirror, TcStatsBasic, TcStatsQueue,
    };
    use crate::AddressFamily;

    /// Captured `TcActionMessage` examples used for testing.
    mod message {
        /// Request
        /// ```bash
        /// tc actions add action mirred egress redirect dev lo index 1
        /// ```
        pub(super) const CREATE1: &str = "0000000038000100340001000b0001006d69727265640000240002802000020001000000000000000400000000000000000000000100000001000000";
        /// Request
        /// ```bash
        /// tc actions add action mirred ingress mirror dev lo index 2
        /// ```
        pub(super) const CREATE2: &str = "0000000038000100340001000b0001006d69727265640000240002802000020002000000000000000300000000000000000000000400000001000000";
        /// Response
        /// ```bash
        /// tc actions list action mirred
        /// ```
        pub(super) const LIST: &str = "00000000080003000200000064010100b00000000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a0000000000480002002000020001000000000000000400000001000000000000000100000001000000240001000000000000000000000000000000000000000000000000000000000000000000b00001000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a0000000000480002002000020002000000000000000300000001000000000000000400000001000000240001000000000000000000000000000000000000000000000000000000000000000000";
    }

    #[test]
    fn parse_message1_create() {
        let expected = TcActionMessage {
            header: TcActionMessageHeader {
                family: AddressFamily::Unspec,
            },
            attributes: vec![Actions(vec![TcAction {
                tab: 1,
                attributes: vec![
                    Kind("mirred".into()),
                    Options(vec![Mirror(Parms(TcMirror {
                        generic: TcActionGeneric {
                            index: 1,
                            capab: 0,
                            action: Stolen,
                            refcnt: 0,
                            bindcnt: 0,
                        },
                        eaction: EgressRedir,
                        ifindex: 1,
                    }))]),
                ],
            }])],
        };

        let buf = hex::decode(message::CREATE1).unwrap();
        let parsed = TcActionMessage::parse(
            &TcActionMessageBuffer::new_checked(&buf).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn parse_message2_create() {
        let expected = TcActionMessage {
            header: TcActionMessageHeader {
                family: AddressFamily::Unspec,
            },
            attributes: vec![Actions(vec![TcAction {
                tab: 1,
                attributes: vec![
                    Kind("mirred".into()),
                    Options(vec![Mirror(Parms(TcMirror {
                        generic: TcActionGeneric {
                            index: 2,
                            capab: 0,
                            action: Pipe,
                            refcnt: 0,
                            bindcnt: 0,
                        },
                        eaction: IngressMirror,
                        ifindex: 1,
                    }))]),
                ],
            }])],
        };

        let buf = hex::decode(message::CREATE2).unwrap();
        let parsed = TcActionMessage::parse(
            &TcActionMessageBuffer::new_checked(&buf).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn parse_message3_list() {
        let expected = TcActionMessage {
            header: TcActionMessageHeader {
                family: AddressFamily::Unspec,
            },
            attributes: vec![
                RootCount(2),
                Actions(vec![
                    TcAction {
                        tab: 0,
                        attributes: vec![
                            Kind("mirred".into()),
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
                            Other(DefaultNla::new(
                                9,
                                vec![0, 0, 0, 0, 3, 0, 0, 0],
                            )),
                            InHwCount(0),
                            Options(vec![
                                Mirror(Parms(TcMirror {
                                    generic: TcActionGeneric {
                                        index: 1,
                                        capab: 0,
                                        action: Stolen,
                                        refcnt: 1,
                                        bindcnt: 0,
                                    },
                                    eaction: EgressRedir,
                                    ifindex: 1,
                                })),
                                Mirror(Tm(vec![
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0,
                                ])),
                            ]),
                        ],
                    },
                    TcAction {
                        tab: 1,
                        attributes: vec![
                            Kind("mirred".into()),
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
                            Other(DefaultNla::new(
                                9,
                                vec![0, 0, 0, 0, 3, 0, 0, 0],
                            )),
                            InHwCount(0),
                            Options(vec![
                                Mirror(Parms(TcMirror {
                                    generic: TcActionGeneric {
                                        index: 2,
                                        capab: 0,
                                        action: Pipe,
                                        refcnt: 1,
                                        bindcnt: 0,
                                    },
                                    eaction: IngressMirror,
                                    ifindex: 1,
                                })),
                                Mirror(Tm(vec![
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0,
                                ])),
                            ]),
                        ],
                    },
                ]),
            ],
        };
        let buf = hex::decode(message::LIST).unwrap();
        let parsed = TcActionMessage::parse(
            &TcActionMessageBuffer::new_checked(&buf).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed, expected);
    }
}

#[test]
fn tc_action_message_attribute_parse_back_blank_actions() {
    let orig = Actions(vec![]);
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionMessageAttribute::parse(
        &NlaBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_action_message_attribute_parse_back_example_action() {
    let orig = Actions(vec![TcAction {
        tab: 9999,
        attributes: vec![Kind("example".into())],
    }]);
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionMessageAttribute::parse(
        &NlaBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_action_message_attribute_parse_back_multiple_example_action() {
    let orig = Actions(vec![
        TcAction {
            tab: 1111,
            attributes: vec![Kind("example1".into())],
        },
        TcAction {
            tab: 2222,
            attributes: vec![
                Kind("example2".into()),
                Index(42),
                Cookie(vec![1, 2, 3, 4, 5, 6]),
            ],
        },
    ]);
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionMessageAttribute::parse(
        &NlaBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_action_message_flags_parse_back_default() {
    let orig = TcActionMessageFlagsWithSelector::default();
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionMessageFlagsWithSelector::parse(
        &NlaBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_action_message_flags_parse_back_example_value() {
    let orig = TcActionMessageFlagsWithSelector {
        flags: TcActionMessageFlags::LargeDump
            | TcActionMessageFlags::TerseDump,
        selector: TcActionMessageFlags::LargeDump,
    };
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionMessageFlagsWithSelector::parse(
        &NlaBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_action_message_parse_back_default() {
    let orig = TcActionMessage::default();
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionMessage::parse(
        &TcActionMessageBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_action_message_parse_back_example_value() {
    let orig = TcActionMessage {
        header: TcActionMessageHeader {
            family: AddressFamily::Alg,
        },
        attributes: vec![
            Flags(TcActionMessageFlagsWithSelector {
                flags: TcActionMessageFlags::LargeDump,
                selector: TcActionMessageFlags::LargeDump,
            }),
            RootCount(42),
            RootTimeDelta(43),
            RootExtWarnMsg("hello".to_string()),
            TcActionMessageAttribute::Other(DefaultNla::new(
                99,
                vec![1, 2, 3, 4],
            )),
        ],
    };
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionMessage::parse(
        &TcActionMessageBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}
