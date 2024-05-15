use crate::net::mpls;
use crate::tc::flower::mpls::{LseFilter, LseOptions};
use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::{Emitable, Parseable};

#[test]
fn parse_back_lse_options_depth_zero() {
    let example = LseOptions::Depth(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_depth_example() {
    let example = LseOptions::Depth(0xab);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_label_zero() {
    let example = LseOptions::Label(
        mpls::Label::new(0).unwrap(),
    );
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_label_example() {
    let example = LseOptions::Label(
        mpls::Label::new(0x01_23_45).unwrap(),
    );
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_tc_zero() {
    let example = LseOptions::TrafficClass(
        mpls::TrafficClass::new(0).unwrap(),
    );
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_tc_example() {
    let example = LseOptions::TrafficClass(
        mpls::TrafficClass::new(0x3).unwrap(),
    );
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_bos_unset() {
    let example = LseOptions::BottomOfStack(
        mpls::BottomOfStack::Unset,
    );
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_bos_set() {
    let example = LseOptions::BottomOfStack(
        mpls::BottomOfStack::Set,
    );
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_ttl_zero() {
    let example = LseOptions::Ttl(0);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_options_ttl_example() {
    let example = LseOptions::Ttl(0x34);
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed = crate::tc::filters::flower::mpls::LseOptions::parse(
        &NlaBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_filter_default() {
    let example = LseFilter::default();
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        LseFilter::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}

#[test]
fn parse_back_lse_filter_example() {
    let example = LseFilter {
        depth: 1,
        label: Some(mpls::Label::new(0x01_23_45).unwrap()),
        traffic_class: Some(mpls::TrafficClass::new(0x3).unwrap()),
        bottom_of_stack: Some(mpls::BottomOfStack::Set),
        ttl: Some(0x34),
    };
    let mut buffer = vec![0; example.buffer_len()];
    example.emit(&mut buffer);
    let parsed =
        LseFilter::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
    assert_eq!(example, parsed);
}
