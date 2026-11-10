// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_string, parse_u32, DecodeError, DefaultNla,
    EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};

const DEVLINK_ATTR_BUS_NAME: u16 = 1;
const DEVLINK_ATTR_DEV_NAME: u16 = 2;
const DEVLINK_ATTR_PORT_INDEX: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum DevlinkPort {
    BusName(String),
    DevName(String),
    PortIndex(u32),
    Other(DefaultNla),
}

impl Nla for DevlinkPort {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::BusName(s) | Self::DevName(s) => {
                append_bytes(out, s.as_bytes());
                out.push(0);
            }
            Self::PortIndex(v) => append_u32(out, *v),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::BusName(_) => DEVLINK_ATTR_BUS_NAME,
            Self::DevName(_) => DEVLINK_ATTR_DEV_NAME,
            Self::PortIndex(_) => DEVLINK_ATTR_PORT_INDEX,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for DevlinkPort {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            DEVLINK_ATTR_BUS_NAME => Self::BusName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_BUS_NAME value")?,
            ),
            DEVLINK_ATTR_DEV_NAME => Self::DevName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_DEV_NAME value")?,
            ),
            DEVLINK_ATTR_PORT_INDEX => Self::PortIndex(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_INDEX value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown DEVLINK_ATTR type {}", buf.kind())
            })?),
        })
    }
}
