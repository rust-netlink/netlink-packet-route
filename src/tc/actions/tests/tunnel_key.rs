use crate::tc::actions::tunnel_key::{Tcft, TcftBuffer, TunnelParamsBuffer};
use crate::tc::actions::TcTunnelKeyAction::{Release, Set};
use crate::tc::actions::{TcTunnelKeyAction, TcTunnelParams};
use crate::tc::flower::encap::Options;
use crate::tc::TcActionAttribute::Kind;
use crate::tc::TcActionMessageAttribute::Actions;
use crate::tc::{
    TcAction, TcActionGeneric, TcActionMessage, TcActionMessageAttribute,
    TcActionMessageBuffer, TcActionMessageFlags,
    TcActionMessageFlagsWithSelector, TcActionMessageHeader,
    TcActionTunnelKeyOption, TcActionType,
};
use crate::{AddressFamily, EncKeyId};
use netlink_packet_utils::nla::{DefaultNla, Nla, NlaBuffer};
use netlink_packet_utils::{Emitable, Parseable};
use std::net::{Ipv4Addr, Ipv6Addr};

mod list {
    use crate::tc::actions::TcTunnelKeyAction::Set;
    use crate::tc::TcActionAttribute::{InHwCount, Options, Stats};
    use crate::tc::TcActionMessageAttribute::RootCount;
    use crate::tc::TcActionTunnelKeyOption::{
        KeyEncDstPort, KeyEncIpv4Dst, KeyEncIpv4Src, KeyEncKeyId,
        KeyNoChecksum, Params, Tm,
    };
    use crate::tc::TcStats2::{Basic, BasicHw, Queue};
    use crate::tc::{TcActionAttribute, TcStatsBasic, TcStatsQueue};
    use netlink_packet_utils::Parseable;

    use super::*;

    struct EquivalentMessage<T> {
        pub serialized: Vec<u8>,
        pub deserialized: T,
    }

    impl EquivalentMessage<TcActionMessage> {
        pub fn assert_serialized_parses_to_deserialized(&self) {
            let parsed = TcActionMessage::parse(
                &TcActionMessageBuffer::new_checked(&self.serialized).unwrap(),
            )
            .unwrap();
            assert_eq!(parsed, self.deserialized);
        }

        pub fn assert_deserialized_serializes_to_serialized(&self) {
            let mut buf = vec![0; self.serialized.len()];
            self.deserialized.emit(&mut buf);
            assert_eq!(self.serialized, buf);
        }
    }

    fn reference_message_list_request() -> EquivalentMessage<TcActionMessage> {
        const LIST_REQUEST: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x14, 0x00, 0x01,
            0x00, 0x0f, 0x00, 0x01, 0x00, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c,
            0x5f, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let deserialized = TcActionMessage {
            header: TcActionMessageHeader {
                family: AddressFamily::Unspec,
            },
            attributes: vec![
                Actions(vec![TcAction {
                    tab: 1,
                    attributes: vec![Kind("tunnel_key".to_string())],
                }]),
                TcActionMessageAttribute::Flags(
                    TcActionMessageFlagsWithSelector {
                        flags: TcActionMessageFlags::LargeDump,
                        selector: TcActionMessageFlags::LargeDump,
                    },
                ),
            ],
        };
        EquivalentMessage {
            serialized: Vec::from(LIST_REQUEST),
            deserialized,
        }
    }

    fn reference_message_list_response() -> EquivalentMessage<TcActionMessage> {
        const LIST_RESPONSE: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xdc, 0x00, 0x01, 0x00, 0xd8, 0x00, 0x00, 0x00, 0x0f, 0x00,
            0x01, 0x00, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x6b, 0x65,
            0x79, 0x00, 0x00, 0x44, 0x00, 0x04, 0x00, 0x14, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x18, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x6c, 0x00, 0x02, 0x80, 0x1c, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x0b, 0xb8, 0x08,
            0x00, 0x03, 0x00, 0xac, 0x12, 0x01, 0x01, 0x08, 0x00, 0x04, 0x00,
            0xac, 0x12, 0x01, 0x04, 0x06, 0x00, 0x09, 0x00, 0x12, 0xb5, 0x00,
            0x00, 0x05, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00,
            0x01, 0x00, 0xe3, 0xa5, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe3,
            0xa5, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let deserialized = TcActionMessage {
            header: TcActionMessageHeader {
                family: AddressFamily::Unspec,
            },
            attributes: vec![
                RootCount(1),
                Actions(vec![TcAction {
                    tab: 0,
                    attributes: vec![
                        Kind("tunnel_key".to_string()),
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
                        // TODO: properly parse whatever this is
                        TcActionAttribute::Other(DefaultNla::new(
                            9,
                            vec![0, 0, 0, 0, 3, 0, 0, 0],
                        )),
                        InHwCount(0),
                        Options(vec![
                            crate::tc::TcActionOption::TunnelKey(Params(
                                TcTunnelParams {
                                    generic: TcActionGeneric {
                                        index: 1,
                                        capab: 0,
                                        action: TcActionType::Pipe,
                                        refcnt: 1,
                                        bindcnt: 0,
                                    },
                                    tunnel_key_action: Set,
                                },
                            )),
                            crate::tc::TcActionOption::TunnelKey(KeyEncKeyId(
                                EncKeyId::new_unchecked(3000),
                            )),
                            crate::tc::TcActionOption::TunnelKey(
                                KeyEncIpv4Src([172, 18, 1, 1].into()),
                            ),
                            crate::tc::TcActionOption::TunnelKey(
                                KeyEncIpv4Dst([172, 18, 1, 4].into()),
                            ),
                            crate::tc::TcActionOption::TunnelKey(
                                KeyEncDstPort(4789),
                            ),
                            crate::tc::TcActionOption::TunnelKey(
                                KeyNoChecksum(true),
                            ),
                            crate::tc::TcActionOption::TunnelKey(Tm(Tcft {
                                install: 8431075,
                                last_use: 8431075,
                                expires: 0,
                                first_use: 0,
                            })),
                        ]),
                    ],
                }]),
            ],
        };
        EquivalentMessage {
            serialized: Vec::from(LIST_RESPONSE),
            deserialized,
        }
    }

    #[test]
    fn parses_reference_request() {
        reference_message_list_request()
            .assert_serialized_parses_to_deserialized();
    }

    #[test]
    fn serializes_to_reference_request() {
        reference_message_list_request()
            .assert_deserialized_serializes_to_serialized();
    }

    #[test]
    fn parses_reference_response() {
        reference_message_list_response()
            .assert_serialized_parses_to_deserialized();
    }

    #[test]
    fn serializes_to_reference_response() {
        reference_message_list_response()
            .assert_deserialized_serializes_to_serialized();
    }
}

#[test]
fn u32_from_tunnel_key_action_is_faithful_to_spec() {
    assert_eq!(
        crate::tc::actions::tunnel_key::TCA_TUNNEL_KEY_ACT_SET,
        u32::from(Set)
    );
    assert_eq!(
        crate::tc::actions::tunnel_key::TCA_TUNNEL_KEY_ACT_RELEASE,
        u32::from(Release)
    );
    let arbitrary_value = 42;
    assert_eq!(
        arbitrary_value,
        u32::from(TcTunnelKeyAction::Other(arbitrary_value))
    );
}

#[test]
fn tunnel_key_action_to_from_u32_is_identity() {
    assert_eq!(Set, TcTunnelKeyAction::from(u32::from(Set)));
    assert_eq!(Release, TcTunnelKeyAction::from(u32::from(Release)));
    let arbitrary_value = 42;
    assert_eq!(
        TcTunnelKeyAction::Other(arbitrary_value),
        TcTunnelKeyAction::from(u32::from(TcTunnelKeyAction::Other(
            arbitrary_value
        )))
    );
}

#[test]
fn tunnel_params_buffer_length_is_as_specified() {
    let params = TcTunnelParams::default();
    assert_eq!(
        crate::tc::actions::tunnel_key::TUNNEL_PARAMS_BUF_LEN,
        params.buffer_len()
    );
}

#[test]
fn default_tunnel_params_emit_and_parse_is_identity() {
    let params = TcTunnelParams::default();
    let mut bytes = vec![0; params.buffer_len()];
    params.emit(&mut bytes);
    let parsed = TcTunnelParams::parse(
        &TunnelParamsBuffer::new_checked(&bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(params, parsed);
}

#[test]
fn arbitrary_tunnel_params_emit_and_parse_is_identity() {
    let params = TcTunnelParams {
        generic: TcActionGeneric {
            action: TcActionType::Queued,
            bindcnt: 2,
            capab: 3,
            index: 4,
            refcnt: 5,
        },
        tunnel_key_action: Release,
    };
    let mut bytes = vec![0; params.buffer_len()];
    params.emit(&mut bytes);
    let parsed =
        TcTunnelParams::parse(&TunnelParamsBuffer::new(&bytes)).unwrap();
    assert_eq!(params, parsed);
}

#[test]
fn tcft_buffer_length_is_as_specified() {
    let tcft = Tcft::default();
    assert_eq!(
        crate::tc::actions::tunnel_key::TCFT_BUF_LEN,
        tcft.buffer_len()
    );
}

#[test]
fn default_tcft_emit_and_parse_is_identity() {
    let tcft = Tcft::default();
    let mut bytes = vec![0; tcft.buffer_len()];
    tcft.emit(&mut bytes);
    let parsed =
        Tcft::parse(&TcftBuffer::new_checked(&bytes).unwrap()).unwrap();
    assert_eq!(tcft, parsed);
}

#[test]
fn arbitrary_tcft_emit_and_parse_is_identity() {
    let tcft = Tcft {
        install: 1,
        last_use: 2,
        expires: 3,
        first_use: 4,
    };
    let mut bytes = vec![0; tcft.buffer_len()];
    tcft.emit(&mut bytes);
    let parsed = Tcft::parse(&TcftBuffer::new(&bytes)).unwrap();
    assert_eq!(tcft, parsed);
}

#[test]
fn tunnel_key_option_value_length_is_as_specified() {
    let option =
        TcActionTunnelKeyOption::KeyEncKeyId(EncKeyId::new_unchecked(1));
    assert_eq!(4, option.value_len());
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_key_id() {
    let option =
        TcActionTunnelKeyOption::KeyEncKeyId(EncKeyId::new_unchecked(1));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_ipv4_dst() {
    let option =
        TcActionTunnelKeyOption::KeyEncIpv4Dst(Ipv4Addr::new(1, 2, 3, 4));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_ipv4_src() {
    let option =
        TcActionTunnelKeyOption::KeyEncIpv4Src(Ipv4Addr::new(1, 2, 3, 4));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_ipv6_dst() {
    let option = TcActionTunnelKeyOption::KeyEncIpv6Dst(Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
    ));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_ipv6_src() {
    let option = TcActionTunnelKeyOption::KeyEncIpv6Src(Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
    ));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_dst_port() {
    let option = TcActionTunnelKeyOption::KeyEncDstPort(1);
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_no_checksum() {
    let option = TcActionTunnelKeyOption::KeyNoChecksum(true);
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_opts_empty_geneve() {
    let option = TcActionTunnelKeyOption::KeyEncOpts(Options::Geneve(vec![]));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_opts_empty_vxlan() {
    let option = TcActionTunnelKeyOption::KeyEncOpts(Options::Vxlan(vec![]));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_opts_empty_erspan() {
    let option = TcActionTunnelKeyOption::KeyEncOpts(Options::Erspan(vec![]));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_option_emit_and_parse_is_identity_enc_opts_empty_gtp() {
    let option = TcActionTunnelKeyOption::KeyEncOpts(Options::Gtp(vec![]));
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_options_emit_and_parse_is_identity_enc_tos() {
    let option = TcActionTunnelKeyOption::KeyEncTos(1);
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_options_emit_and_parse_is_identity_enc_ttl() {
    let option = TcActionTunnelKeyOption::KeyEncTtl(1);
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}

#[test]
fn tunnel_key_options_emit_and_parse_is_identity_no_frag() {
    let option = TcActionTunnelKeyOption::KeyNoFrag;
    let mut bytes = vec![0; option.buffer_len()];
    option.emit(&mut bytes);
    let parsed =
        TcActionTunnelKeyOption::parse(&NlaBuffer::new(&bytes)).unwrap();
    assert_eq!(option, parsed);
}
