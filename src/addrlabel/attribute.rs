// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

const IFAL_ADDRESS: u16 = 1;
const IFAL_LABEL: u16 = 2;

const IPV4_ADDR_LEN: usize = 4;
const IPV6_ADDR_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum AddrLabelAttribute {
    /// `IFAL_ADDRESS`
    Address(IpAddr),
    /// `IFAL_LABEL`
    Label(u32),
    Other(DefaultNla),
}

impl Nla for AddrLabelAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Address(IpAddr::V4(_)) => IPV4_ADDR_LEN,
            Self::Address(IpAddr::V6(_)) => IPV6_ADDR_LEN,
            Self::Label(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Address(IpAddr::V4(addr)) => {
                buffer.copy_from_slice(&addr.octets())
            }
            Self::Address(IpAddr::V6(addr)) => {
                buffer.copy_from_slice(&addr.octets())
            }
            Self::Label(label) => emit_u32(buffer, *label).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Address(_) => IFAL_ADDRESS,
            Self::Label(_) => IFAL_LABEL,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for AddrLabelAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFAL_ADDRESS => {
                if payload.len() == IPV4_ADDR_LEN {
                    let mut data = [0u8; IPV4_ADDR_LEN];
                    data.copy_from_slice(&payload[0..IPV4_ADDR_LEN]);
                    Self::Address(IpAddr::from(data))
                } else if payload.len() == IPV6_ADDR_LEN {
                    let mut data = [0u8; IPV6_ADDR_LEN];
                    data.copy_from_slice(&payload[0..IPV6_ADDR_LEN]);
                    Self::Address(IpAddr::from(data))
                } else {
                    return Err(DecodeError::from(format!(
                        "Invalid IFAL_ADDRESS, got unexpected length of \
                         payload {payload:?}"
                    )));
                }
            }
            IFAL_LABEL => Self::Label(
                parse_u32(payload).context("invalid IFAL_LABEL value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}

pub(crate) struct VecAddrLabelAttribute(pub(crate) Vec<AddrLabelAttribute>);

impl Parseable<[u8]> for VecAddrLabelAttribute {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        for nla_buf in NlasIterator::new(buf) {
            attributes.push(AddrLabelAttribute::parse(&nla_buf?)?);
        }
        Ok(Self(attributes))
    }
}
