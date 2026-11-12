// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_i32, parse_i32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_PPP_UNSPEC: u16 = 0;
const IFLA_PPP_DEV_FD: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoPpp {
    DevFd(i32),
    Other(DefaultNla),
}

impl Nla for InfoPpp {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::DevFd(value) => append_i32(out, *value),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::DevFd(_) => IFLA_PPP_DEV_FD,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoPpp {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_PPP_UNSPEC => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid IFLA_PPP_UNSPEC value")?,
            ),
            IFLA_PPP_DEV_FD => Self::DevFd(
                parse_i32(payload).context("invalid IFLA_PPP_DEV_FD value")?,
            ),
            kind => {
                Self::Other(DefaultNla::parse(buf).with_context(|| {
                    format!("unknown NLA type {kind} for ppp")
                })?)
            }
        })
    }
}
