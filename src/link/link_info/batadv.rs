// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, parse_string, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_BATADV_ALGO_NAME: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoBatAdv {
    AlgoName(String),
    Other(DefaultNla),
}

impl Nla for InfoBatAdv {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::AlgoName(v) => {
                append_bytes(out, v.as_bytes());
                out.push(0);
            }
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::AlgoName(_) => IFLA_BATADV_ALGO_NAME,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoBatAdv {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BATADV_ALGO_NAME => Self::AlgoName(
                parse_string(payload)
                    .context("invalid IFLA_BATADV_ALGO_NAME value")?,
            ),
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for IFLA_INFO_DATA(batadv)")
            })?),
        })
    }
}
