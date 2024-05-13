use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::nla::{DefaultNla, Nla, NlaBuffer};
use netlink_packet_utils::parsers::parse_u32;
use netlink_packet_utils::{DecodeError, Parseable};

const TCA_TUNNEL_KEY_ENC_OPT_VXLAN_GPB: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Options {
    Gpb(Gpb),
    Other(DefaultNla),
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Options {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            TCA_TUNNEL_KEY_ENC_OPT_VXLAN_GPB => {
                Self::Gpb(Gpb::new(parse_u32(buf.value())?))
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

impl Nla for Options {
    fn value_len(&self) -> usize {
        match self {
            Self::Gpb(gpb) => gpb.value_len(),
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Gpb(g) => g.kind(),
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Gpb(gpb) => gpb.emit_value(buffer),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Gpb(u32);

impl Gpb {
    #[must_use]
    pub fn new(gpb: u32) -> Self {
        Self(gpb)
    }
}

impl From<u32> for Gpb {
    fn from(gpb: u32) -> Self {
        Self(gpb)
    }
}

impl From<Gpb> for u32 {
    fn from(gpb: Gpb) -> Self {
        gpb.0
    }
}

impl Nla for Gpb {
    fn value_len(&self) -> usize {
        4
    }

    fn kind(&self) -> u16 {
        TCA_TUNNEL_KEY_ENC_OPT_VXLAN_GPB
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        NativeEndian::write_u32(buffer, self.0);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Gpb {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self(parse_u32(buf.value())?))
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_utils::Emitable;

    use crate::net::ethernet::Ethertype;
    use crate::tc::flower::encap::{OptionsList, vxlan};
    use crate::tc::TcFilterFlowerOption::{
        KeyEncOpts, KeyEncOptsMask, KeyEthType,
    };
    use crate::tc::TcOption::Flower;
    use crate::tc::{TcAttribute, TcFilterFlowerOption, TcFlowerOptionFlags, TcHandle, TcHeader, TcMessage, TcMessageBuffer};
    use crate::AddressFamily;
    use crate::tc::flower::encap::Options::Vxlan;

    use super::*;

    #[test]
    fn parse_back_gpb_zero() {
        let example = Gpb::new(0);
        let mut buffer = vec![0; example.buffer_len()];
        example.emit(&mut buffer);
        let parsed =
            Gpb::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
        assert_eq!(example, parsed);
    }

    #[test]
    fn parse_back_gpb_example() {
        let example = Gpb::new(0x12_34_56_78);
        let mut buffer = vec![0; example.buffer_len()];
        example.emit(&mut buffer);
        let parsed =
            Gpb::parse(&NlaBuffer::new_checked(&buffer).unwrap()).unwrap();
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
    const RAW_CAP: &str = "000000003900000000000000f2ffffff080000000b000100666c6f776572000034000200100054800c0002800800010070000000100055800c00028008000100ffffffff08001600000000000600080008000000";

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
                    Flower(KeyEncOpts(OptionsList(Vxlan(vec![
                        Options::Gpb(Gpb::new(112))
                    ])))),
                    Flower(KeyEncOptsMask(OptionsList(Vxlan(vec![
                        Options::Gpb(Gpb::new(0xff_ff_ff_ff))
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
        let raw_cap = hex::decode(RAW_CAP).unwrap();
        let expected = expected_message();
        let parsed =
            TcMessage::parse(&TcMessageBuffer::new_checked(&raw_cap).unwrap())
                .unwrap();
        assert_eq!(expected, parsed);
    }

    #[test]
    fn expected_emits_as_captured() {
        let raw_cap = hex::decode(RAW_CAP).unwrap();
        let expected = expected_message();
        let mut buffer = vec![0; expected.buffer_len()];
        expected.emit(&mut buffer);
        assert_eq!(raw_cap, buffer);
    }
}
