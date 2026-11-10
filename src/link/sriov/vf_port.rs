// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VecLinkVfPort(pub(crate) Vec<LinkVfPort>);

impl<'a> Parseable<NlaBuffer<'a>> for VecLinkVfPort {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self(buf.parse_nlas_with(|nla| {
            if nla.kind() == IFLA_VF_PORT {
                Ok(Some(LinkVfPort::parse(&nla)?))
            } else {
                log::warn!(
                    "BUG: Expecting IFLA_VF_PORT in IFLA_VF_PORTS, but got {}",
                    nla.kind()
                );
                Ok(None)
            }
        })?))
    }
}

const IFLA_VF_PORT: u16 = 1;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct LinkVfPort(pub Vec<VfPort>);

impl Nla for LinkVfPort {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.0.emit(out)
    }

    fn kind(&self) -> u16 {
        IFLA_VF_PORT
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for LinkVfPort {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in buf.nlas() {
            let nla = nla.with_context(|| {
                format!("invalid IFLA_VF_PORT value {:?}", buf.value())
            })?;
            nlas.push(VfPort::parse(&nla)?);
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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Other(v) => v.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for VfPort {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        #[allow(clippy::match_single_binding)]
        Ok(match buf.kind() {
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("failed to parse {kind} as DefaultNla: {payload:?}")
            })?),
        })
    }
}
