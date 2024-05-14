use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::Emitable;
use netlink_packet_utils::Parseable;

use crate::net::ethernet::Ethertype;
use crate::tc::flower::encap;
use crate::tc::flower::encap::vxlan::{Gpb, Options};
use crate::tc::flower::encap::Options::Vxlan;
use crate::tc::flower::encap::OptionsList;
use crate::tc::TcFilterFlowerOption::{KeyEncOpts, KeyEncOptsMask, KeyEthType};
use crate::tc::TcOption::Flower;
use crate::tc::{
    TcAttribute, TcFilterFlowerOption, TcFlowerOptionFlags, TcHandle, TcHeader,
    TcMessage, TcMessageBuffer,
};
use crate::AddressFamily;

#[test]
fn parse_back_gpb_zero() {
    let example = Gpb::new(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = Gpb::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_gpb_example() {
    let example = Gpb::new(0x12_34_56_78);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = Gpb::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_zero() {
    let example = Options::Gpb(Gpb::new(0));
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        Options::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_example() {
    let example = Options::Gpb(Gpb::new(0x12_34_56_78));
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
///      vxlan_opts 112
/// ```
///
/// # Modifications
///
/// * Removed cooked header (16 bytes)
/// * Removed rtnetlink header (16 bytes)
const RAW_CAP: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf2, 0xff, 0xff, 0xff, 0x08, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00,
    0x66, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x00, 0x00, 0x34, 0x00, 0x02, 0x00,
    0x10, 0x00, 0x54, 0x80, 0x0c, 0x00, 0x02, 0x80, 0x08, 0x00, 0x01, 0x00,
    0x70, 0x00, 0x00, 0x00, 0x10, 0x00, 0x55, 0x80, 0x0c, 0x00, 0x02, 0x80,
    0x08, 0x00, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x16, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
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
                Flower(KeyEncOpts(OptionsList(Vxlan(vec![Options::Gpb(
                    Gpb::new(112),
                )])))),
                Flower(KeyEncOptsMask(OptionsList(Vxlan(vec![Options::Gpb(
                    Gpb::new(0xff_ff_ff_ff),
                )])))),
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
fn parse_back_options_vxlan_empty() {
    let example = Vxlan(vec![]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_options_vxlan_example() {
    let example = Vxlan(vec![Options::Gpb(Gpb::new(0xab_cd))]);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        encap::Options::parse(&NlaBuffer::new_checked(&buffer).unwrap())
            .unwrap();
    assert_eq!(example, parsed);
}
