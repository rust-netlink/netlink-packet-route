// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{
    emit_u16_be, emit_u32, parse_ip, parse_u16_be, parse_u32, DecodeError,
    DefaultNla, ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_AMT_MODE: u16 = 1;
const IFLA_AMT_RELAY_PORT: u16 = 2;
const IFLA_AMT_GATEWAY_PORT: u16 = 3;
const IFLA_AMT_LINK: u16 = 4;
const IFLA_AMT_LOCAL_IP: u16 = 5;
const IFLA_AMT_REMOTE_IP: u16 = 6;
const IFLA_AMT_DISCOVERY_IP: u16 = 7;
const IFLA_AMT_MAX_TUNNELS: u16 = 8;

const AMT_MODE_GATEWAY: u32 = 0;
const AMT_MODE_RELAY: u32 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[repr(u32)]
pub enum AmtMode {
    Gateway = AMT_MODE_GATEWAY,
    Relay = AMT_MODE_RELAY,
    Other(u32),
}

impl From<u32> for AmtMode {
    fn from(d: u32) -> Self {
        match d {
            AMT_MODE_GATEWAY => Self::Gateway,
            AMT_MODE_RELAY => Self::Relay,
            _ => Self::Other(d),
        }
    }
}

impl From<AmtMode> for u32 {
    fn from(d: AmtMode) -> Self {
        match d {
            AmtMode::Gateway => AMT_MODE_GATEWAY,
            AmtMode::Relay => AMT_MODE_RELAY,
            AmtMode::Other(value) => value,
        }
    }
}

impl std::fmt::Display for AmtMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gateway => write!(f, "gateway"),
            Self::Relay => write!(f, "relay"),
            Self::Other(d) => write!(f, "{d}"),
        }
    }
}

impl std::str::FromStr for AmtMode {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gateway" => Ok(Self::Gateway),
            "relay" => Ok(Self::Relay),
            _ => Err(DecodeError::from(format!("unknown AMT mode: {s}"))),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoAmt {
    Mode(AmtMode),
    RelayPort(u16),
    GatewayPort(u16),
    Link(u32),
    LocalIp(IpAddr),
    RemoteIp(IpAddr),
    DiscoveryIp(IpAddr),
    MaxTunnels(u32),
    Other(DefaultNla),
}

impl Nla for InfoAmt {
    fn value_len(&self) -> usize {
        use self::InfoAmt::*;
        match self {
            Mode(_) | MaxTunnels(_) | Link(_) => 4,
            RelayPort(_) | GatewayPort(_) => 2,
            LocalIp(ip) | RemoteIp(ip) | DiscoveryIp(ip) => match ip {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            },
            Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoAmt::*;
        match self {
            Mode(value) => emit_u32(buffer, (*value).into()).unwrap(),
            Link(value) | MaxTunnels(value) => {
                emit_u32(buffer, *value).unwrap()
            }
            RelayPort(value) | GatewayPort(value) => {
                emit_u16_be(buffer, *value).unwrap()
            }
            LocalIp(ip) | RemoteIp(ip) | DiscoveryIp(ip) => match ip {
                IpAddr::V4(ipv4) => buffer.copy_from_slice(&ipv4.octets()),
                IpAddr::V6(ipv6) => buffer.copy_from_slice(&ipv6.octets()),
            },
            Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoAmt::*;
        match self {
            Mode(_) => IFLA_AMT_MODE,
            RelayPort(_) => IFLA_AMT_RELAY_PORT,
            GatewayPort(_) => IFLA_AMT_GATEWAY_PORT,
            Link(_) => IFLA_AMT_LINK,
            LocalIp(_) => IFLA_AMT_LOCAL_IP,
            RemoteIp(_) => IFLA_AMT_REMOTE_IP,
            DiscoveryIp(_) => IFLA_AMT_DISCOVERY_IP,
            MaxTunnels(_) => IFLA_AMT_MAX_TUNNELS,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoAmt {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoAmt::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_AMT_MODE => Mode(
                parse_u32(payload)
                    .context("invalid IFLA_AMT_MODE value")?
                    .into(),
            ),
            IFLA_AMT_RELAY_PORT => RelayPort(
                parse_u16_be(payload)
                    .context("invalid IFLA_AMT_RELAY_PORT value")?,
            ),
            IFLA_AMT_GATEWAY_PORT => GatewayPort(
                parse_u16_be(payload)
                    .context("invalid IFLA_AMT_GATEWAY_PORT value")?,
            ),
            IFLA_AMT_LINK => Link(
                parse_u32(payload).context("invalid IFLA_AMT_LINK value")?,
            ),
            IFLA_AMT_LOCAL_IP => LocalIp(
                parse_ip(payload).context("invalid IFLA_AMT_LOCAL_IP value")?,
            ),
            IFLA_AMT_REMOTE_IP => RemoteIp(
                parse_ip(payload)
                    .context("invalid IFLA_AMT_REMOTE_IP value")?,
            ),
            IFLA_AMT_DISCOVERY_IP => DiscoveryIp(
                parse_ip(payload)
                    .context("invalid IFLA_AMT_DISCOVERY_IP value")?,
            ),
            IFLA_AMT_MAX_TUNNELS => MaxTunnels(
                parse_u32(payload)
                    .context("invalid IFLA_AMT_MAX_TUNNELS value")?,
            ),
            kind => Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind} for amt"))?,
            ),
        })
    }
}
