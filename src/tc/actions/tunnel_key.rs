// SPDX-License-Identifier: MIT

/// Tunnel key action
use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_packet_utils::nla::{Nla, NlaBuffer, NLA_F_NESTED};
use netlink_packet_utils::parsers::{parse_u16_be, parse_u32_be};
use netlink_packet_utils::{
    nla::DefaultNla,
    traits::{Emitable, Parseable},
    DecodeError,
};

use crate::tc::filters::flower::encap::{parse_enc_opts, Options};
use crate::tc::TcActionGenericBuffer;
use crate::EncKeyId;

use super::TcActionGeneric;

pub(crate) const TCA_TUNNEL_KEY_ACT_SET: u32 = 1;
pub(crate) const TCA_TUNNEL_KEY_ACT_RELEASE: u32 = 2;

/// Tunnel key action.
///
/// The tunnel key action is used to set or release a tunnel key.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[allow(clippy::module_name_repetitions)]
pub struct TcActionTunnelKey {}

impl TcActionTunnelKey {
    /// The `TcActionAttribute::Kind` of this action.
    pub const KIND: &'static str = "tunnel_key";
}

/// Tunnel key action options.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[repr(u32)]
pub enum TcTunnelKeyAction {
    /// Set the tunnel key (encap).
    Set = TCA_TUNNEL_KEY_ACT_SET,
    /// Release the tunnel key (decap).
    Release = TCA_TUNNEL_KEY_ACT_RELEASE,
    /// Other action unknown at the time of writing.
    Other(u32),
}

impl From<u32> for TcTunnelKeyAction {
    fn from(value: u32) -> Self {
        match value {
            TCA_TUNNEL_KEY_ACT_SET => Self::Set,
            TCA_TUNNEL_KEY_ACT_RELEASE => Self::Release,
            _ => Self::Other(value),
        }
    }
}

impl From<TcTunnelKeyAction> for u32 {
    fn from(value: TcTunnelKeyAction) -> Self {
        match value {
            TcTunnelKeyAction::Set => TCA_TUNNEL_KEY_ACT_SET,
            TcTunnelKeyAction::Release => TCA_TUNNEL_KEY_ACT_RELEASE,
            TcTunnelKeyAction::Other(x) => x,
        }
    }
}

/// Tunnel key parameters.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcTunnelParams {
    /// Generic action parameters.
    pub generic: TcActionGeneric,
    /// Tunnel key action parameters.
    pub tunnel_key_action: TcTunnelKeyAction,
}

impl Default for TcTunnelParams {
    fn default() -> Self {
        Self {
            generic: TcActionGeneric::default(),
            tunnel_key_action: TcTunnelKeyAction::Set,
        }
    }
}

pub(crate) const TUNNEL_PARAMS_BUF_LEN: usize = TcActionGeneric::BUF_LEN + 4;

buffer!(TunnelParamsBuffer(TUNNEL_PARAMS_BUF_LEN) {
    generic: (slice, 0..TcActionGeneric::BUF_LEN),
    tunnel_key_action: (u32, TcActionGeneric::BUF_LEN..TUNNEL_PARAMS_BUF_LEN),
});

impl Emitable for TcTunnelParams {
    fn buffer_len(&self) -> usize {
        TUNNEL_PARAMS_BUF_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TunnelParamsBuffer::new(buffer);
        self.generic.emit(buffer.generic_mut());
        buffer.set_tunnel_key_action(u32::from(self.tunnel_key_action.clone()));
    }
}

impl<'a, T: AsRef<[u8]> + 'a + ?Sized> Parseable<TunnelParamsBuffer<&'a T>>
    for TcTunnelParams
{
    fn parse(buf: &TunnelParamsBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            generic: TcActionGeneric::parse(&TcActionGenericBuffer::new(
                buf.generic(),
            ))?,
            tunnel_key_action: buf.tunnel_key_action().into(),
        })
    }
}

pub type TimeCode = u64;

/// Tracks times in which a filter was installed, last used, expires, and first
/// used.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub struct Tcft {
    pub install: TimeCode,
    pub last_use: TimeCode,
    pub expires: TimeCode,
    pub first_use: TimeCode,
}

pub(crate) const TCFT_BUF_LEN: usize = 32;

buffer!(TcftBuffer(TCFT_BUF_LEN) {
    install: (u64, 0..8),
    last_use: (u64, 8..16),
    expires: (u64, 16..24),
    first_use: (u64, 24..TCFT_BUF_LEN),
});

impl Emitable for Tcft {
    fn buffer_len(&self) -> usize {
        TCFT_BUF_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TcftBuffer::new(buffer);
        buffer.set_install(self.install);
        buffer.set_last_use(self.last_use);
        buffer.set_expires(self.expires);
        buffer.set_first_use(self.first_use);
    }
}

impl<'a, T: AsRef<[u8]> + 'a + ?Sized> Parseable<TcftBuffer<&'a T>> for Tcft {
    fn parse(buf: &TcftBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            install: buf.install(),
            last_use: buf.last_use(),
            expires: buf.expires(),
            first_use: buf.first_use(),
        })
    }
}

/// Tunnel key options.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcActionTunnelKeyOption {
    /// Tunnel key parameters.
    Params(TcTunnelParams),
    /// Action hit time info.
    Tm(Tcft),
    /// Encapsulation key ID.
    KeyEncKeyId(EncKeyId),
    /// Encapsulation IPv4 destination address.
    KeyEncIpv4Dst(Ipv4Addr),
    /// Encapsulation IPv4 source address.
    KeyEncIpv4Src(Ipv4Addr),
    /// Encapsulation IPv6 destination address.
    KeyEncIpv6Dst(Ipv6Addr),
    /// Encapsulation IPv6 source address.
    KeyEncIpv6Src(Ipv6Addr),
    /// Encapsulation destination port.
    KeyEncDstPort(u16),
    /// If true, do not compute the checksum of the encapsulating packet.
    KeyNoChecksum(bool),
    /// Encapsulation options.
    KeyEncOpts(Options),
    /// Encapsulation TOS.
    KeyEncTos(u8),
    /// Encapsulation TTL.
    KeyEncTtl(u8),
    /// Flag which indicates that the "do not fragment" bit should be set in
    /// the outer header.
    KeyNoFrag,
    /// Other option unknown at the time of writing.
    Other(DefaultNla),
}

const TCA_TUNNEL_KEY_TM: u16 = 1;
const TCA_TUNNEL_KEY_PARMS: u16 = 2;
const TCA_TUNNEL_KEY_ENC_IPV4_SRC: u16 = 3; /* be32 */
const TCA_TUNNEL_KEY_ENC_IPV4_DST: u16 = 4; /* be32 */
const TCA_TUNNEL_KEY_ENC_IPV6_SRC: u16 = 5; /* struct in6_addr */
const TCA_TUNNEL_KEY_ENC_IPV6_DST: u16 = 6; /* struct in6_addr */
const TCA_TUNNEL_KEY_ENC_KEY_ID: u16 = 7; /* be64 */
const TCA_TUNNEL_KEY_ENC_DST_PORT: u16 = 9; /* be16 */
const TCA_TUNNEL_KEY_NO_CSUM: u16 = 10; /* u8 */
const TCA_TUNNEL_KEY_ENC_OPTS: u16 = 11; /* Nested TCA_TUNNEL_KEY_ENC_OPTS_ */
const TCA_TUNNEL_KEY_ENC_TOS: u16 = 12; /* u8 */
const TCA_TUNNEL_KEY_ENC_TTL: u16 = 13; /* u8 */
const TCA_TUNNEL_KEY_NO_FRAG: u16 = 14; /* flag */

impl Nla for TcActionTunnelKeyOption {
    fn value_len(&self) -> usize {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Params(p) => p.buffer_len(),
            Self::Tm(t) => t.buffer_len(),
            Self::KeyEncKeyId(_) => 4,
            Self::KeyEncIpv4Dst(_) => 4,
            Self::KeyEncIpv4Src(_) => 4,
            Self::KeyEncIpv6Dst(_) => 16,
            Self::KeyEncIpv6Src(_) => 16,
            Self::KeyEncDstPort(_) => 2,
            Self::KeyNoChecksum(_) => 1,
            Self::KeyEncOpts(opts) => opts.buffer_len(),
            Self::KeyEncTos(_) => 1,
            Self::KeyEncTtl(_) => 1,
            Self::KeyNoFrag => 0,
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Params(_) => TCA_TUNNEL_KEY_PARMS,
            Self::Tm(_) => TCA_TUNNEL_KEY_TM,
            Self::KeyEncKeyId(_) => TCA_TUNNEL_KEY_ENC_KEY_ID,
            Self::KeyEncIpv4Dst(_) => TCA_TUNNEL_KEY_ENC_IPV4_DST,
            Self::KeyEncIpv4Src(_) => TCA_TUNNEL_KEY_ENC_IPV4_SRC,
            Self::KeyEncIpv6Dst(_) => TCA_TUNNEL_KEY_ENC_IPV6_DST,
            Self::KeyEncIpv6Src(_) => TCA_TUNNEL_KEY_ENC_IPV6_SRC,
            Self::KeyEncDstPort(_) => TCA_TUNNEL_KEY_ENC_DST_PORT,
            Self::KeyNoChecksum(_) => TCA_TUNNEL_KEY_NO_CSUM,
            Self::KeyEncOpts(_) => TCA_TUNNEL_KEY_ENC_OPTS | NLA_F_NESTED,
            Self::KeyEncTos(_) => TCA_TUNNEL_KEY_ENC_TOS,
            Self::KeyEncTtl(_) => TCA_TUNNEL_KEY_ENC_TTL,
            Self::KeyNoFrag => TCA_TUNNEL_KEY_NO_FRAG,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Params(p) => p.emit(buffer),
            Self::Tm(t) => t.emit(buffer),
            Self::KeyEncKeyId(id) => {
                buffer.copy_from_slice(&id.as_ref().to_be_bytes());
            }
            Self::KeyEncIpv4Dst(addr) => buffer.copy_from_slice(&addr.octets()),
            Self::KeyEncIpv4Src(addr) => buffer.copy_from_slice(&addr.octets()),
            Self::KeyEncIpv6Dst(addr) => buffer.copy_from_slice(&addr.octets()),
            Self::KeyEncIpv6Src(addr) => buffer.copy_from_slice(&addr.octets()),
            Self::KeyEncDstPort(port) => {
                buffer.copy_from_slice(&port.to_be_bytes());
            }
            Self::KeyNoChecksum(b) => buffer[0] = u8::from(*b),
            Self::KeyEncOpts(opts) => opts.emit(buffer),
            Self::KeyEncTos(tos) => buffer[0] = *tos,
            Self::KeyEncTtl(ttl) => buffer[0] = *ttl,
            Self::KeyNoFrag => (),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TcActionTunnelKeyOption
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            TCA_TUNNEL_KEY_PARMS => Self::Params(TcTunnelParams::parse(
                &TunnelParamsBuffer::new_checked(buf.value())?,
            )?),
            TCA_TUNNEL_KEY_TM => {
                Self::Tm(Tcft::parse(&TcftBuffer::new_checked(buf.value())?)?)
            }
            TCA_TUNNEL_KEY_ENC_KEY_ID => Self::KeyEncKeyId(
                EncKeyId::new_unchecked(parse_u32_be(buf.value())?),
            ),
            TCA_TUNNEL_KEY_ENC_IPV4_DST => {
                Self::KeyEncIpv4Dst(parse_ipv4(buf.value())?)
            }
            TCA_TUNNEL_KEY_ENC_IPV4_SRC => {
                Self::KeyEncIpv4Src(parse_ipv4(buf.value())?)
            }
            TCA_TUNNEL_KEY_ENC_IPV6_DST => {
                Self::KeyEncIpv6Dst(parse_ipv6(buf.value())?)
            }
            TCA_TUNNEL_KEY_ENC_IPV6_SRC => {
                Self::KeyEncIpv6Src(parse_ipv6(buf.value())?)
            }
            TCA_TUNNEL_KEY_ENC_DST_PORT => {
                Self::KeyEncDstPort(parse_u16_be(buf.value())?)
            }
            TCA_TUNNEL_KEY_NO_CSUM => Self::KeyNoChecksum(buf.value()[0] != 0),
            TCA_TUNNEL_KEY_ENC_OPTS => {
                let nested = NlaBuffer::new_checked(buf.value())?;
                Self::KeyEncOpts(parse_enc_opts(&nested)?)
            }
            TCA_TUNNEL_KEY_ENC_TOS => {
                if buf.value().len() != 1 {
                    return Err(DecodeError::from(format!(
                        "Invalid length of TOS, expecting 1 byte, but got {:?}",
                        buf.value()
                    )));
                }
                Self::KeyEncTos(buf.value()[0])
            }
            TCA_TUNNEL_KEY_ENC_TTL => {
                if buf.value().len() != 1 {
                    return Err(DecodeError::from(format!(
                        "Invalid length of TTL, expecting 1 byte, but got {:?}",
                        buf.value()
                    )));
                }
                Self::KeyEncTtl(buf.value()[0])
            }
            TCA_TUNNEL_KEY_NO_FRAG => Self::KeyNoFrag,
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

// TODO: de-duplicate
fn parse_ipv4(data: &[u8]) -> Result<Ipv4Addr, DecodeError> {
    if data.len() == 4 {
        Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
    } else {
        Err(DecodeError::from(format!(
            "Invalid length of IPv4 Address, expecting 4 bytes, but got {data:?}"
        )))
    }
}

fn parse_ipv6(data: &[u8]) -> Result<Ipv6Addr, DecodeError> {
    if data.len() == 16 {
        let data: [u8; 16] = data.try_into().map_err(|err| {
            // This should be unreachable
            DecodeError::from(format!("Failed to parse IPv6 address: {err}"))
        })?;
        Ok(Ipv6Addr::from(data))
    } else {
        Err(DecodeError::from(format!(
            "Invalid length of IPv6 Address, expecting 16 bytes, but got {data:?}",
        )))
    }
}

#[cfg(test)]
mod tests {
}
