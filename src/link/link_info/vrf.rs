// SPDX-License-Identifier: MIT

use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32,
    traits::Parseable,
    DecodeError,
};

const IFLA_VRF_TABLE: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoVrf {
    TableId(u32),
    Other(DefaultNla),
}

impl Nla for InfoVrf {
    fn value_len(&self) -> usize {
        use self::InfoVrf::*;
        match self {
            TableId(_) => 4,
            Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoVrf::*;
        match self {
            TableId(value) => NativeEndian::write_u32(buffer, *value),
            Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoVrf::*;
        match self {
            TableId(_) => IFLA_VRF_TABLE,
            Other(nla) => nla.kind(),
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>> for InfoVrf {
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        use self::InfoVrf::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VRF_TABLE => TableId(parse_u32(payload)?),
            _ => Other(DefaultNla::parse(buf)?),
        })
    }
}
