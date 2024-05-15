use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::{Emitable, Parseable};

use crate::net::ethernet::Ethertype;
use crate::tc::flower::encap;
use crate::tc::flower::encap::geneve::{Class, Data, Options, Type};
use crate::tc::flower::encap::Options::Geneve;
use crate::tc::flower::encap::OptionsList;
use crate::tc::TcAttribute;
use crate::tc::TcFilterFlowerOption::{KeyEncOpts, KeyEncOptsMask, KeyEthType};
use crate::tc::TcOption::Flower;
use crate::tc::{
    TcFilterFlowerOption, TcFlowerOptionFlags, TcHandle, TcHeader, TcMessage,
    TcMessageBuffer,
};
use crate::AddressFamily;

#[test]
fn class_parse_back_zero() {
    let example = Class::new(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Class::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn class_parse_back_example() {
    let example = Class::new(0x1234);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Class::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn type_parse_back_zero() {
    let example = Type::new(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Type::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn type_parse_back_example() {
    let example = Type::new(0x12);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Type::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn data_parse_back_zero() {
    let example = Data::new(vec![0]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Data::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn data_parse_back_example() {
    let example = Data::new(vec![0x12_34_56_78, 0x9a_bc_de_f0]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(buffer.as_mut_slice());
    let parsed =
        Data::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn options_parse_back_class() {
    let example = Options::Class(Class::new(0x1234));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn options_parse_back_type() {
    let example = Options::Type(Type::new(0x12));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(buffer.as_mut_slice());
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn options_parse_back_data() {
    let example = Options::Data(Data::new(vec![0x1234_5678, 0x9abc_def0]));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

/// Setup
///
/// Create a scratch network interface and add a qdisc to it.
///
/// ```bash
/// ip link add dev dummy type dummy
/// tc qdisc add dev dummy clsact
/// ```
///
/// Then capture the netlink request for
///
/// ```bash
/// tc filter add dev vtep ingress protocol ip \
///      flower \
///      geneve_opts 1:1:abcdef01
/// ```
///
/// # Modifications
///
/// * Removed cooked header (16 bytes)
/// * Removed rtnetlink header (16 bytes)
const RAW_CAP: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf2, 0xff, 0xff, 0xff, 0x08, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00,
    0x66, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x00, 0x00, 0x54, 0x00, 0x02, 0x00,
    0x20, 0x00, 0x54, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x03, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x20, 0x00, 0x55, 0x00,
    0x1c, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x05, 0x00, 0x02, 0x00, 0xff, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
];

/// Returns the message we expected to parse from [`RAW_CAP`].
fn expected_message() -> TcMessage {
    TcMessage {
        header: TcHeader {
            family: AddressFamily::Unspec,
            index: 57,
            handle: TcHandle { major: 0, minor: 0 },
            parent: TcHandle {
                major: 65535,
                minor: 65522,
            },
            info: 8,
        },
        attributes: vec![
            TcAttribute::Kind("flower".to_string()),
            TcAttribute::Options(vec![
                Flower(KeyEncOpts(OptionsList(Geneve(vec![
                    Options::Class(Class::new(1)),
                    Options::Type(Type::new(1)),
                    Options::Data(Data::new(vec![0xabcd_ef01])),
                ])))),
                Flower(KeyEncOptsMask(OptionsList(Geneve(vec![
                    Options::Class(Class::new(65535)),
                    Options::Type(Type::new(255)),
                    Options::Data(Data::new(vec![0xffff_ffff])),
                ])))),
                Flower(TcFilterFlowerOption::Flags(
                    TcFlowerOptionFlags::empty(),
                )),
                Flower(KeyEthType(Ethertype::IPv4)),
            ]),
        ],
    }
}

#[test]
fn captured_parses_as_expected() {
    let expected = expected_message();
    let parsed =
        TcMessage::parse(&TcMessageBuffer::new_checked(&RAW_CAP).unwrap())
            .unwrap();
    assert_eq!(expected, parsed);
}

#[test]
fn expected_emits_as_captured() {
    let expected = expected_message();
    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);
    assert_eq!(RAW_CAP, buffer);
}

#[test]
fn parse_back_options_geneve_empty() {
    let example = Geneve(vec![]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_geneve_example() {
    let example = Geneve(vec![
        Options::Class(Class::new(0xabcd)),
        Options::Data(Data::new(vec![1, 2, 3, 4])),
        Options::Type(Type::new(0xab)),
    ]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}
