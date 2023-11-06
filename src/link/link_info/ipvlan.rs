// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u16,
    traits::Parseable,
    DecodeError,
};

const IFLA_IPVLAN_MODE: u16 = 1;
const IFLA_IPVLAN_FLAGS: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoIpVlan {
    Mode(u16),
    Flags(u16),
    Other(DefaultNla),
}

impl Nla for InfoIpVlan {
    fn value_len(&self) -> usize {
        use self::InfoIpVlan::*;
        match self {
            Mode(_) | Flags(_) => 2,
            Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoIpVlan::*;
        match self {
            Mode(value) => NativeEndian::write_u16(buffer, *value),
            Flags(value) => NativeEndian::write_u16(buffer, *value),
            Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoIpVlan::*;
        match self {
            Mode(_) => IFLA_IPVLAN_MODE,
            Flags(_) => IFLA_IPVLAN_FLAGS,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoIpVlan {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoIpVlan::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_IPVLAN_MODE => Mode(
                parse_u16(payload).context("invalid IFLA_IPVLAN_MODE value")?,
            ),
            IFLA_IPVLAN_FLAGS => Flags(
                parse_u16(payload)
                    .context("invalid IFLA_IPVLAN_FLAGS value")?,
            ),
            kind => Other(DefaultNla::parse(buf).context(format!(
                "unknown NLA type {kind} for IFLA_INFO_DATA(ipvlan)"
            ))?),
        })
    }
}
