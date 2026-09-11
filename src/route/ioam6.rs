// SPDX-License-Identifier: MIT

use std::{fmt::Debug, net::Ipv6Addr};

use netlink_packet_core::{
    emit_u16_be, emit_u32, emit_u32_be, parse_u16_be, parse_u32, parse_u32_be,
    parse_u8, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer, Parseable,
};

use crate::ip::parse_ipv6_addr;

const IOAM6_IPTUNNEL_UNSPEC: u16 = 0;
const IOAM6_IPTUNNEL_MODE: u16 = 1;
const IOAM6_IPTUNNEL_DST: u16 = 2;
const IOAM6_IPTUNNEL_TRACE: u16 = 3;
const IOAM6_IPTUNNEL_FREQ_K: u16 = 4;
const IOAM6_IPTUNNEL_FREQ_N: u16 = 5;
const IOAM6_IPTUNNEL_SRC: u16 = 6;

const IOAM6_IPTUNNEL_MODE_INLINE: u8 = 1;
const IOAM6_IPTUNNEL_MODE_ENCAP: u8 = 2;
const IOAM6_IPTUNNEL_MODE_AUTO: u8 = 3;

/// Encapsulation mode of `IOAM6_IPTUNNEL_MODE` attribute, the string
/// representation follows `iproute2`.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum Ioam6Mode {
    #[default]
    Inline,
    Encap,
    Auto,
    Other(u8),
}

impl From<u8> for Ioam6Mode {
    fn from(d: u8) -> Self {
        match d {
            IOAM6_IPTUNNEL_MODE_INLINE => Self::Inline,
            IOAM6_IPTUNNEL_MODE_ENCAP => Self::Encap,
            IOAM6_IPTUNNEL_MODE_AUTO => Self::Auto,
            d => Self::Other(d),
        }
    }
}

impl From<Ioam6Mode> for u8 {
    fn from(v: Ioam6Mode) -> Self {
        match v {
            Ioam6Mode::Inline => IOAM6_IPTUNNEL_MODE_INLINE,
            Ioam6Mode::Encap => IOAM6_IPTUNNEL_MODE_ENCAP,
            Ioam6Mode::Auto => IOAM6_IPTUNNEL_MODE_AUTO,
            Ioam6Mode::Other(d) => d,
        }
    }
}

impl std::fmt::Display for Ioam6Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline => write!(f, "inline"),
            Self::Encap => write!(f, "encap"),
            Self::Auto => write!(f, "auto"),
            Self::Other(d) => write!(f, "other({d})"),
        }
    }
}

/// The IOAM trace header of `IOAM6_IPTUNNEL_TRACE` attribute.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct Ioam6TraceHdr {
    pub namespace_id: u16,
    pub nodelen: u8,
    pub overflow: bool,
    /// Trace data size in 4 octet words.
    pub remlen: u8,
    /// The trace type as shown by `iproute2`, the low 8 bits of the on wire
    /// `type_be32` are not included.
    pub trace_type: u32,
}

impl Nla for Ioam6TraceHdr {
    fn value_len(&self) -> usize {
        8
    }

    fn kind(&self) -> u16 {
        IOAM6_IPTUNNEL_TRACE
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        emit_u16_be(&mut buffer[0..2], self.namespace_id).unwrap();
        buffer[2] =
            ((self.nodelen & 0x1f) << 3) | (u8::from(self.overflow) << 2);
        buffer[3] = self.remlen & 0x7f;
        emit_u32_be(&mut buffer[4..8], self.trace_type << 8).unwrap();
    }
}

impl<'a, T> Parseable<NlaBuffer<&'a T>> for Ioam6TraceHdr
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        if payload.len() != 8 {
            return Err(DecodeError::from(format!(
                "Invalid IOAM6_IPTUNNEL_TRACE value {payload:?}"
            )));
        }
        Ok(Self {
            namespace_id: parse_u16_be(&payload[0..2])
                .context("Invalid IOAM6_IPTUNNEL_TRACE namespace_id")?,
            nodelen: (payload[2] >> 3) & 0x1f,
            overflow: payload[2] & 0x04 != 0,
            remlen: payload[3] & 0x7f,
            trace_type: parse_u32_be(&payload[4..8])
                .context("Invalid IOAM6_IPTUNNEL_TRACE type")?
                >> 8,
        })
    }
}

/// Netlink attributes for `RTA_ENCAP` with `RTA_ENCAP_TYPE` set to
/// `LWTUNNEL_ENCAP_IOAM6`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub enum RouteIoam6Tunnel {
    #[default]
    Unspecified,
    Mode(Ioam6Mode),
    Dst(Ipv6Addr),
    Trace(Ioam6TraceHdr),
    FreqK(u32),
    FreqN(u32),
    Src(Ipv6Addr),
    Other(DefaultNla),
}

impl std::fmt::Display for RouteIoam6Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::Mode(mode) => write!(f, "mode {mode}"),
            Self::Dst(addr) => write!(f, "tundst {addr}"),
            Self::Trace(trace) => write!(
                f,
                "trace prealloc type {:#08x} ns {} size {}",
                trace.trace_type,
                trace.namespace_id,
                trace.remlen * 4
            ),
            Self::FreqK(freq) => write!(f, "freq {freq}"),
            Self::FreqN(freq) => write!(f, "/{freq}"),
            Self::Src(addr) => write!(f, "tunsrc {addr}"),
            Self::Other(other) => other.fmt(f),
        }
    }
}

impl Nla for RouteIoam6Tunnel {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Mode(_) => 1,
            Self::Dst(_) | Self::Src(_) => 16,
            Self::Trace(trace) => trace.value_len(),
            Self::FreqK(_) | Self::FreqN(_) => 4,
            Self::Other(other) => other.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => IOAM6_IPTUNNEL_UNSPEC,
            Self::Mode(_) => IOAM6_IPTUNNEL_MODE,
            Self::Dst(_) => IOAM6_IPTUNNEL_DST,
            Self::Trace(_) => IOAM6_IPTUNNEL_TRACE,
            Self::FreqK(_) => IOAM6_IPTUNNEL_FREQ_K,
            Self::FreqN(_) => IOAM6_IPTUNNEL_FREQ_N,
            Self::Src(_) => IOAM6_IPTUNNEL_SRC,
            Self::Other(other) => other.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Mode(mode) => buffer[0] = u8::from(*mode),
            Self::Dst(addr) | Self::Src(addr) => {
                buffer.copy_from_slice(&addr.octets())
            }
            Self::Trace(trace) => trace.emit_value(buffer),
            Self::FreqK(freq) | Self::FreqN(freq) => {
                emit_u32(buffer, *freq).unwrap()
            }
            Self::Other(other) => other.emit_value(buffer),
        }
    }
}

impl<'a, T> Parseable<NlaBuffer<&'a T>> for RouteIoam6Tunnel
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IOAM6_IPTUNNEL_UNSPEC => Self::Unspecified,
            IOAM6_IPTUNNEL_MODE => Self::Mode(Ioam6Mode::from(
                parse_u8(payload).context("invalid IOAM6_IPTUNNEL_MODE")?,
            )),
            IOAM6_IPTUNNEL_DST => Self::Dst(
                parse_ipv6_addr(payload)
                    .context("invalid IOAM6_IPTUNNEL_DST")?,
            ),
            IOAM6_IPTUNNEL_TRACE => match Ioam6TraceHdr::parse(buf) {
                Ok(trace) => Self::Trace(trace),
                Err(_) => Self::Other(DefaultNla::parse(buf)?),
            },
            IOAM6_IPTUNNEL_FREQ_K => Self::FreqK(
                parse_u32(payload).context("invalid IOAM6_IPTUNNEL_FREQ_K")?,
            ),
            IOAM6_IPTUNNEL_FREQ_N => Self::FreqN(
                parse_u32(payload).context("invalid IOAM6_IPTUNNEL_FREQ_N")?,
            ),
            IOAM6_IPTUNNEL_SRC => Self::Src(
                parse_ipv6_addr(payload)
                    .context("invalid IOAM6_IPTUNNEL_SRC")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
