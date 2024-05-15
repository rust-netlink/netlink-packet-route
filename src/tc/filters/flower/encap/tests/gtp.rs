use crate::tc::flower::encap;
use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::{Emitable, Parseable};

use crate::tc::flower::encap::gtp::Options;

#[test]
fn parse_back_options_pdu_type_zero() {
    let example = Options::PduType(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_pdu_type_example() {
    let example = Options::PduType(0xab);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_qfi_zero() {
    let example = Options::Qfi(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_qfi_example() {
    let example = Options::Qfi(0xab);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_gtp_empty() {
    let example = encap::Options::Gtp(vec![]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_gtp_example() {
    let example =
        encap::Options::Gtp(vec![Options::PduType(0xab), Options::Qfi(0xcd)]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}
