// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
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
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Address(IpAddr::V4(addr)) => {
                append_bytes(out, &addr.octets())
            }
            Self::Address(IpAddr::V6(addr)) => {
                append_bytes(out, &addr.octets())
            }
            Self::Label(label) => append_u32(out, *label),
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <Self>::kind(self)
    }
}

impl AddrLabelAttribute {
    pub(crate) fn kind(&self) -> u16 {
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
                    .with_context(|| format!("unknown NLA type {kind}"))?,
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
