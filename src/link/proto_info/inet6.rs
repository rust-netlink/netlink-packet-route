// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, EncodeError, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable,
};

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum LinkProtoInfoInet6 {
    Other(DefaultNla),
}

pub(crate) struct VecLinkProtoInfoInet6(pub(crate) Vec<LinkProtoInfoInet6>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for VecLinkProtoInfoInet6
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = nla.with_context(|| {
                format!("invalid inet6 IFLA_PROTINFO {:?}", buf.value())
            })?;
            nlas.push(LinkProtoInfoInet6::parse(&nla)?);
        }
        Ok(Self(nlas))
    }
}

impl Nla for LinkProtoInfoInet6 {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match *self {
            Self::Other(ref nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <LinkProtoInfoInet6>::kind(self)
    }
}

impl LinkProtoInfoInet6 {
    pub(crate) fn kind(&self) -> u16 {
        match *self {
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for LinkProtoInfoInet6
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self::Other(DefaultNla::parse(buf).with_context(|| {
            format!("invalid inet6 IFLA_PROTINFO {:?}", buf.value())
        })?))
    }
}
