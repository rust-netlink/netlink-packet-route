// SPDX-License-Identifier: MIT

use netlink_packet_core::ErrorContext;
// Currently, the qdisc ingress does not have any attribute, kernel
// just start a empty nla_nest. This is just a place holder
use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, EncodeError, Nla, NlaBuffer,
    Parseable,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcQdiscIngress {}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcQdiscIngressOption {
    Other(DefaultNla),
}

impl TcQdiscIngress {
    pub(crate) const KIND: &'static str = "ingress";
}

impl Nla for TcQdiscIngressOption {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Other(attr) => {
                append_bytes(out, attr.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        <TcQdiscIngressOption>::kind(self)
    }
}

impl TcQdiscIngressOption {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TcQdiscIngressOption
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self::Other(
            DefaultNla::parse(buf).context("failed to parse ingress nla")?,
        ))
    }
}
