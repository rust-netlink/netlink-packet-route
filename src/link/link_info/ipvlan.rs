// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u16,
    traits::Parseable,
    DecodeError,
};

const IFLA_IPVLAN_MODE: u16 = 1;
const IFLA_IPVLAN_FLAGS: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoIpVlan {
    Mode(IpVlanMode),
    Flags(IpVlanFlag),
    Other(DefaultNla),
}

impl Nla for InfoIpVlan {
    fn value_len(&self) -> usize {
        use self::InfoIpVlan::*;
        match self {
            Mode(_) | Flags(_) => 2,
            Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoIpVlan::*;
        match self {
            Mode(value) => NativeEndian::write_u16(buffer, (*value).into()),
            Flags(value) => NativeEndian::write_u16(buffer, (*value).into()),
            Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoIpVlan::*;
        match self {
            Mode(_) => IFLA_IPVLAN_MODE,
            Flags(_) => IFLA_IPVLAN_FLAGS,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoIpVlan {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoIpVlan::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_IPVLAN_MODE => Mode(
                parse_u16(payload)
                    .context("invalid IFLA_IPVLAN_MODE value")?
                    .into(),
            ),
            IFLA_IPVLAN_FLAGS => Flags(
                parse_u16(payload)
                    .context("invalid IFLA_IPVLAN_FLAGS value")?
                    .into(),
            ),
            kind => Other(DefaultNla::parse(buf).context(format!(
                "unknown NLA type {kind} for IFLA_INFO_DATA(ipvlan)"
            ))?),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoIpVtap {
    Mode(IpVtapMode),
    Flags(IpVtapFlag),
    Other(DefaultNla),
}

impl Nla for InfoIpVtap {
    fn value_len(&self) -> usize {
        use self::InfoIpVtap::*;
        match self {
            Mode(_) | Flags(_) => 2,
            Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoIpVtap::*;
        match self {
            Mode(value) => NativeEndian::write_u16(buffer, (*value).into()),
            Flags(value) => NativeEndian::write_u16(buffer, (*value).into()),
            Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoIpVtap::*;
        match self {
            Mode(_) => IFLA_IPVLAN_MODE,
            Flags(_) => IFLA_IPVLAN_FLAGS,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoIpVtap {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoIpVtap::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_IPVLAN_MODE => Mode(
                parse_u16(payload)
                    .context("invalid IFLA_IPVLAN_MODE value")?
                    .into(),
            ),
            IFLA_IPVLAN_FLAGS => Flags(
                parse_u16(payload)
                    .context("invalid IFLA_IPVLAN_FLAGS value")?
                    .into(),
            ),
            kind => Other(DefaultNla::parse(buf).context(format!(
                "unknown NLA type {kind} for IFLA_INFO_DATA(ipvlan)"
            ))?),
        })
    }
}

const IPVLAN_MODE_L2: u16 = 0;
const IPVLAN_MODE_L3: u16 = 1;
const IPVLAN_MODE_L3S: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum IpVlanMode {
    L2,
    L3,
    L3S,
    Other(u16),
}

pub type IpVtapMode = IpVlanMode;

impl From<u16> for IpVlanMode {
    fn from(d: u16) -> Self {
        match d {
            IPVLAN_MODE_L2 => Self::L2,
            IPVLAN_MODE_L3 => Self::L3,
            IPVLAN_MODE_L3S => Self::L3S,
            _ => {
                log::warn!("Unknown IP VLAN mode {}", d);
                Self::Other(d)
            }
        }
    }
}

impl From<IpVlanMode> for u16 {
    fn from(v: IpVlanMode) -> u16 {
        match v {
            IpVlanMode::L2 => IPVLAN_MODE_L2,
            IpVlanMode::L3 => IPVLAN_MODE_L3,
            IpVlanMode::L3S => IPVLAN_MODE_L3S,
            IpVlanMode::Other(d) => d,
        }
    }
}

const IPVLAN_FLAG_BRIDGE: u16 = 0;
const IPVLAN_FLAG_PRIVATE: u16 = 1;
const IPVLAN_FLAG_VEPA: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum IpVlanFlag {
    Bridge,
    Private,
    Vepa,
    Other(u16),
}

pub type IpVtapFlag = IpVlanFlag;

impl From<u16> for IpVlanFlag {
    fn from(d: u16) -> Self {
        match d {
            IPVLAN_FLAG_BRIDGE => Self::Bridge,
            IPVLAN_FLAG_PRIVATE => Self::Private,
            IPVLAN_FLAG_VEPA => Self::Vepa,
            _ => {
                log::warn!("Unknown IP VLAN flag {}", d);
                Self::Other(d)
            }
        }
    }
}

impl From<IpVlanFlag> for u16 {
    fn from(v: IpVlanFlag) -> u16 {
        match v {
            IpVlanFlag::Bridge => IPVLAN_FLAG_BRIDGE,
            IpVlanFlag::Private => IPVLAN_FLAG_PRIVATE,
            IpVlanFlag::Vepa => IPVLAN_FLAG_VEPA,
            IpVlanFlag::Other(d) => d,
        }
    }
}
