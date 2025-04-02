// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    traits::Parseable,
    DecodeError,
};

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum LinkProtoInfoBridge {
    Other(DefaultNla),
}

pub(crate) struct VecLinkProtoInfoBridge(pub(crate) Vec<LinkProtoInfoBridge>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for VecLinkProtoInfoBridge
{
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf.into_inner()) {
            nlas.push(LinkProtoInfoBridge::parse(&nla?)?);
        }
        Ok(Self(nlas))
    }
}

impl Nla for LinkProtoInfoBridge {
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

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>> for LinkProtoInfoBridge {
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        Ok(Self::Other(DefaultNla::parse(buf)?))
    }
}
