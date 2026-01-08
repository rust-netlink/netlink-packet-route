// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

const IFLA_MCTP_NET: u16 = 1;

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum AfSpecMctp {
    Net(u32),
    Other(DefaultNla),
}

// Not construted on non-Linux targets
#[allow(unused)]
pub(crate) struct VecAfSpecMctp(pub(crate) Vec<AfSpecMctp>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for VecAfSpecMctp
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        let err = "Invalid AF_MCTP NLA for IFLA_AF_SPEC(AF_UNSPEC)";
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = nla.context(err)?;
            nlas.push(AfSpecMctp::parse(&nla).context(err)?);
        }
        Ok(Self(nlas))
    }
}

impl Nla for AfSpecMctp {
    fn value_len(&self) -> usize {
        match *self {
            Self::Net(_) => 4,
            Self::Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Net(ref value) => emit_u32(buffer, *value).unwrap(),
            Self::Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Net(_) => IFLA_MCTP_NET,
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for AfSpecMctp {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_MCTP_NET => Self::Net(
                parse_u32(payload).context("invalid IFLA_MCTP_NET value")?,
            ),
            kind => Self::Other(DefaultNla::parse(buf).context(format!(
                "unknown AF_MCTP NLA type {kind} for IFLA_AF_SPEC(AF_UNSPEC)"
            ))?),
        })
    }
}
