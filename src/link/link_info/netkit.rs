// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32, parse_u32, parse_u8, DecodeError, DefaultNla, Emitable,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

use super::super::{LinkMessage, LinkMessageBuffer};

const NETKIT_L2: u32 = 0;
const NETKIT_L3: u32 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum NetkitMode {
    L2,
    L3,
    Other(u32),
}

impl From<NetkitMode> for u32 {
    fn from(mode: NetkitMode) -> Self {
        match mode {
            NetkitMode::L2 => NETKIT_L2,
            NetkitMode::L3 => NETKIT_L3,
            NetkitMode::Other(value) => value,
        }
    }
}

impl From<u32> for NetkitMode {
    fn from(value: u32) -> Self {
        match value {
            NETKIT_L2 => NetkitMode::L2,
            NETKIT_L3 => NetkitMode::L3,
            _ => NetkitMode::Other(value),
        }
    }
}

const NETKIT_PASS: u32 = 0;
const NETKIT_DROP: u32 = 2;
const NETKIT_REDIRECT: u32 = 7;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum NetkitPolicy {
    Pass,
    Drop,
    Redirect,
    Other(u32),
}

impl NetkitPolicy {
    /// Alias for the `Pass` policy
    #[allow(non_upper_case_globals)]
    pub const Forward: NetkitPolicy = Self::Pass;
}

impl From<NetkitPolicy> for u32 {
    fn from(policy: NetkitPolicy) -> Self {
        match policy {
            NetkitPolicy::Pass => NETKIT_PASS,
            NetkitPolicy::Drop => NETKIT_DROP,
            NetkitPolicy::Redirect => NETKIT_REDIRECT,
            NetkitPolicy::Other(value) => value,
        }
    }
}

impl From<u32> for NetkitPolicy {
    fn from(value: u32) -> Self {
        match value {
            NETKIT_PASS => NetkitPolicy::Pass,
            NETKIT_DROP => NetkitPolicy::Drop,
            _ => NetkitPolicy::Other(value),
        }
    }
}

const IFLA_NETKIT_PEER_INFO: u16 = 1;
const IFLA_NETKIT_PRIMARY: u16 = 2;
const IFLA_NETKIT_POLICY: u16 = 3;
const IFLA_NETKIT_PEER_POLICY: u16 = 4;
const IFLA_NETKIT_MODE: u16 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoNetkit {
    Peer(LinkMessage),
    Primary(bool),
    Policy(NetkitPolicy),
    PeerPolicy(NetkitPolicy),
    Mode(NetkitMode),
    Other(DefaultNla),
}

impl Nla for InfoNetkit {
    fn value_len(&self) -> usize {
        match *self {
            Self::Peer(ref message) => message.buffer_len(),
            Self::Primary(_) => 1,
            Self::Policy(_) | Self::PeerPolicy(_) | Self::Mode(_) => 4,
            Self::Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Peer(ref message) => message.emit(buffer),
            Self::Primary(value) => {
                buffer[0] = value as u8;
            }
            Self::Policy(value) | Self::PeerPolicy(value) => {
                emit_u32(buffer, value.into()).unwrap();
            }
            Self::Mode(value) => {
                emit_u32(buffer, value.into()).unwrap();
            }
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Peer(_) => IFLA_NETKIT_PEER_INFO,
            Self::Primary(_) => IFLA_NETKIT_PRIMARY,
            Self::Policy(_) => IFLA_NETKIT_POLICY,
            Self::PeerPolicy(_) => IFLA_NETKIT_PEER_POLICY,
            Self::Mode(_) => IFLA_NETKIT_MODE,
            Self::Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoNetkit {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_NETKIT_PEER_INFO => {
                let err = "failed to parse netkit peer info";
                let buffer =
                    LinkMessageBuffer::new_checked(&payload).context(err)?;
                Self::Peer(LinkMessage::parse(&buffer).context(err)?)
            }
            IFLA_NETKIT_PRIMARY => {
                let value = parse_u8(payload)? != 0;
                Self::Primary(value)
            }
            IFLA_NETKIT_POLICY => Self::Policy(parse_u32(payload)?.into()),
            IFLA_NETKIT_PEER_POLICY => {
                Self::PeerPolicy(parse_u32(payload)?.into())
            }
            IFLA_NETKIT_MODE => Self::Mode(parse_u32(payload)?.into()),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind} for netkit"))?,
            ),
        })
    }
}
