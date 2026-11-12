// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u8, parse_u8, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_OVPN_UNSPEC: u16 = 0;
const IFLA_OVPN_MODE: u16 = 1;

const OVPN_MODE_P2P: u8 = 0;
const OVPN_MODE_MP: u8 = 1;

/// OVPN device mode.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum OvpnMode {
    #[default]
    P2P,
    Mp,
    Other(u8),
}

impl From<u8> for OvpnMode {
    fn from(value: u8) -> Self {
        match value {
            OVPN_MODE_P2P => Self::P2P,
            OVPN_MODE_MP => Self::Mp,
            other => Self::Other(other),
        }
    }
}

impl From<OvpnMode> for u8 {
    fn from(value: OvpnMode) -> Self {
        match value {
            OvpnMode::P2P => OVPN_MODE_P2P,
            OvpnMode::Mp => OVPN_MODE_MP,
            OvpnMode::Other(other) => other,
        }
    }
}

impl std::fmt::Display for OvpnMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P2P => f.write_str("p2p"),
            Self::Mp => f.write_str("mp"),
            Self::Other(value) => write!(f, "{value}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoOvpn {
    Mode(OvpnMode),
    Other(DefaultNla),
}

impl Nla for InfoOvpn {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Mode(value) => append_u8(out, u8::from(*value)),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Mode(_) => IFLA_OVPN_MODE,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoOvpn {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_OVPN_UNSPEC => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid IFLA_OVPN_UNSPEC value")?,
            ),
            IFLA_OVPN_MODE => Self::Mode(
                parse_u8(payload)
                    .context("invalid IFLA_OVPN_MODE value")?
                    .into(),
            ),
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for ovpn")
            })?),
        })
    }
}
