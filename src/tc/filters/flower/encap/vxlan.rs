use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::nla::{DefaultNla, Nla, NlaBuffer};
use netlink_packet_utils::parsers::parse_u32;
use netlink_packet_utils::{DecodeError, Parseable};

const TCA_TUNNEL_KEY_ENC_OPT_VXLAN_GPB: u16 = 1; /* u32 */

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
