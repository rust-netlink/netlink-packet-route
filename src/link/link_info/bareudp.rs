// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u16, append_u16_be, parse_u16_be, DecodeError,
    DefaultNla, EncodeError, ErrorContext, EthernetProtocol, Nla, NlaBuffer,
    Parseable,
};

const IFLA_BAREUDP_PORT: u16 = 1;
const IFLA_BAREUDP_ETHERTYPE: u16 = 2;
const IFLA_BAREUDP_SRCPORT_MIN: u16 = 3;
const IFLA_BAREUDP_MULTIPROTO_MODE: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoBareUdp {
    Port(u16),
    Ethertype(EthernetProtocol),
    SrcPortMin(u16),
    MultiprotoMode,
    Other(DefaultNla),
}

impl Nla for InfoBareUdp {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Port(value) => append_u16_be(out, *value),
            Self::Ethertype(value) => append_u16_be(out, u16::from(*value)),
            Self::SrcPortMin(value) => append_u16(out, *value),
            Self::MultiprotoMode => {}
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Port(_) => IFLA_BAREUDP_PORT,
            Self::Ethertype(_) => IFLA_BAREUDP_ETHERTYPE,
            Self::SrcPortMin(_) => IFLA_BAREUDP_SRCPORT_MIN,
            Self::MultiprotoMode => IFLA_BAREUDP_MULTIPROTO_MODE,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoBareUdp {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BAREUDP_PORT => Self::Port(
                parse_u16_be(payload)
                    .context("invalid IFLA_BAREUDP_PORT value")?,
            ),
            IFLA_BAREUDP_ETHERTYPE => Self::Ethertype(EthernetProtocol::from(
                parse_u16_be(payload)
                    .context("invalid IFLA_BAREUDP_ETHERTYPE value")?,
            )),
            IFLA_BAREUDP_SRCPORT_MIN => {
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(payload);
                Self::SrcPortMin(u16::from_ne_bytes(bytes))
            }
            IFLA_BAREUDP_MULTIPROTO_MODE => Self::MultiprotoMode,
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for IFLA_INFO_DATA(bareudp)")
            })?),
        })
    }
}
