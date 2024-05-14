use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::{Emitable, Parseable};

use crate::tc::flower::encap;
use crate::tc::flower::encap::erspan::{
    Direction, ErspanHwid, Index, Options, Version,
};

#[test]
fn parse_back_version_zero() {
    let example = Version::new(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Version::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_version_example() {
    let example = Version::new(0x12);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Version::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_index_zero() {
    let example = Index::new(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Index::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_index_example() {
    let example = Index::new(0x12345678);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Index::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_direction_ingress() {
    let example = Direction::Ingress;
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Direction::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_direction_egress() {
    let example = Direction::Egress;
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Direction::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_hwid_zero() {
    let example = ErspanHwid::new(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        ErspanHwid::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_hwid_example() {
    let example = ErspanHwid::new(0x12);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        ErspanHwid::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_version_zero() {
    let example = Options::Version(Version::new(0));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_version_example() {
    let example = Options::Version(Version::new(0x12));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_index_zero() {
    let example = Options::Index(Index::new(0));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_index_example() {
    let example = Options::Index(Index::new(0x12345678));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_direction_ingress() {
    let example = Options::Direction(Direction::Ingress);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_direction_egress() {
    let example = Options::Direction(Direction::Egress);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_hwid_zero() {
    let example = Options::Hwid(ErspanHwid::new(0));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_hwid_example() {
    let example = Options::Hwid(ErspanHwid::new(0x12));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_erspan_empty() {
    let example = encap::Options::Erspan(vec![]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_erspan_example() {
    let example = encap::Options::Erspan(vec![
        Options::Version(Version::new(0xab)),
        Options::Direction(Direction::Ingress),
        Options::Index(Index::new(0x12_34_56_78)),
    ]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}
