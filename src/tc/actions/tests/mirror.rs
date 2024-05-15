// SPDX-License-Identifier: MIT

use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::{Emitable, Parseable};

use crate::tc::{
    TcActionGeneric, TcActionGenericBuffer, TcActionMirrorOption, TcActionType,
    TcMirror, TcMirrorActionType, TcMirrorBuffer,
};

#[test]
fn tc_action_generic_parse_back() {
    let orig = TcActionGeneric {
        index: 1,
        capab: 2,
        action: TcActionType::Reclassify,
        refcnt: 3,
        bindcnt: 4,
    };
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcActionGeneric::parse(
        &TcActionGenericBuffer::new_checked(buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_mirror_default_parse_back() {
    let orig = TcMirror {
        generic: Default::default(),
        eaction: Default::default(),
        ifindex: 111,
    };
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcMirror::parse(
        &TcMirrorBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_mirror_example_parse_back() {
    let orig = TcMirror {
        generic: TcActionGeneric {
            index: 1,
            capab: 2,
            action: TcActionType::Ok,
            refcnt: 3,
            bindcnt: 4,
        },
        eaction: TcMirrorActionType::IngressMirror,
        ifindex: 99,
    };
    let mut buffer = vec![0; orig.buffer_len()];
    orig.emit(&mut buffer);
    let parsed = TcMirror::parse(
        &TcMirrorBuffer::new_checked(buffer.as_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn tc_mirror_tm_default_parse_back() {
    let mirror_option = TcActionMirrorOption::Tm(vec![]);
    let mut buffer = vec![0; mirror_option.buffer_len()];
    mirror_option.emit(&mut buffer);
    let nla_buf = NlaBuffer::new_checked(&buffer).unwrap();
    let parsed = TcActionMirrorOption::parse(&nla_buf).unwrap();
    assert_eq!(mirror_option, parsed);
}

#[test]
fn tc_mirror_tm_example_parse_back() {
    let mirror_option = TcActionMirrorOption::Tm(vec![1, 2, 3]);
    let mut buffer = vec![0; mirror_option.buffer_len()];
    mirror_option.emit(&mut buffer);
    let nla_buf = NlaBuffer::new_checked(&buffer).unwrap();
    let parsed = TcActionMirrorOption::parse(&nla_buf).unwrap();
    assert_eq!(mirror_option, parsed);
}
