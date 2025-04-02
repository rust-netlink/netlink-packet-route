// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    traits::Parseable,
    DecodeError,
};

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum LinkProtoInfoInet6 {
    Other(DefaultNla),
}

pub(crate) struct VecLinkProtoInfoInet6(pub(crate) Vec<LinkProtoInfoInet6>);

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>>
    for VecLinkProtoInfoInet6
{
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf.into_inner()) {
            nlas.push(LinkProtoInfoInet6::parse(&nla?)?);
        }
        Ok(Self(nlas))
    }
}

impl Nla for LinkProtoInfoInet6 {
    fn value_len(&self) -> usize {
        match *self {
            Self::Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>> for LinkProtoInfoInet6 {
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        Ok(Self::Other(DefaultNla::parse(buf)?))
    }
}
