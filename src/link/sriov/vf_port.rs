// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, emit_nlas_into, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VecLinkVfPort(pub(crate) Vec<LinkVfPort>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for VecLinkVfPort
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = &nla.with_context(|| {
                format!("invalid IFLA_VF_PORTS value: {:?}", buf.value())
            })?;
            if nla.kind() == IFLA_VF_PORT {
                nlas.push(LinkVfPort::parse(&NlaBuffer::new_checked(
                    nla.value(),
                )?)?);
            } else {
                log::warn!(
                    "BUG: Expecting IFLA_VF_PORT in IFLA_VF_PORTS, but got {}",
                    nla.kind()
                );
            }
        }
        Ok(Self(nlas))
    }
}

const IFLA_VF_PORT: u16 = 1;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct LinkVfPort(pub Vec<VfPort>);

impl Nla for LinkVfPort {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        emit_nlas_into(&self.0, out)
    }

    fn kind(&self) -> u16 {
        <LinkVfPort>::kind(self)
    }
}

impl LinkVfPort {
    pub(crate) fn kind(&self) -> u16 {
        IFLA_VF_PORT
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for LinkVfPort {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = &nla.with_context(|| {
                format!("invalid IFLA_VF_PORT value {:?}", buf.value())
            })?;
            nlas.push(VfPort::parse(nla)?);
        }
        Ok(Self(nlas))
    }
}

/*
const IFLA_PORT_VF: u16 = 1;
const IFLA_PORT_PROFILE: u16 = 2;
// No kernel code is accepting or generating IFLA_PORT_VSI_TYPE.
// const IFLA_PORT_VSI_TYPE: u16 = 3;
const IFLA_PORT_INSTANCE_UUID: u16 = 4;
const IFLA_PORT_HOST_UUID: u16 = 5;
const IFLA_PORT_REQUEST: u16 = 6;
const IFLA_PORT_RESPONSE: u16 = 7;

const UUID_LEN: usize = 16;
*/

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum VfPort {
    //    Vf(u32),
    //    Profile(String),
    //    InstanceUuid([u8; UUID_LEN]),
    //    HostUuid([u8; UUID_LEN]),
    //    Request(u8),
    Other(DefaultNla),
}

impl Nla for VfPort {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        <VfPort>::kind(self)
    }
}

impl VfPort {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::Other(v) => v.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for VfPort {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        #[allow(clippy::match_single_binding)]
        Ok(match buf.kind() {
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("failed to parse {kind} as DefaultNla: {payload:?}")
            })?),
        })
    }
}
