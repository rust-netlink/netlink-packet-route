// SPDX-License-Identifier: MIT

/// Mirror action
///
/// The mirred action allows packet mirroring (copying) or
/// redirecting (stealing) the packet it receives. Mirroring is what
/// is sometimes referred to as Switch Port Analyzer (SPAN) and is
/// commonly used to analyze and/or debug flows.
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    traits::{Emitable, Parseable},
    DecodeError,
};

use super::{TcActionGeneric, TcActionGenericBuffer};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcActionMirror {}
impl TcActionMirror {
    pub(crate) const KIND: &'static str = "mirred";
}

const TCA_MIRRED_TM: u16 = 1;
const TCA_MIRRED_PARMS: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcActionMirrorOption {
    Tm(Vec<u8>),
    Parms(TcMirror),
    Other(DefaultNla),
}

impl Nla for TcActionMirrorOption {
    fn value_len(&self) -> usize {
        match self {
            Self::Tm(bytes) => bytes.len(),
            Self::Parms(_) => TC_MIRRED_BUF_LEN,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Tm(bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Self::Parms(p) => p.emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn kind(&self) -> u16 {
        match self {
            Self::Tm(_) => TCA_MIRRED_TM,
            Self::Parms(_) => TCA_MIRRED_PARMS,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TcActionMirrorOption
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_MIRRED_TM => Self::Tm(payload.to_vec()),
            TCA_MIRRED_PARMS => Self::Parms(TcMirror::parse(
                &TcMirrorBuffer::new_checked(payload)?,
            )?),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

const TC_MIRRED_BUF_LEN: usize = TcActionGeneric::BUF_LEN + 8;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcMirror {
    pub generic: TcActionGeneric,
    pub eaction: i32,
    pub ifindex: u32,
}

// kernel struct `tc_mirred`
buffer!(TcMirrorBuffer(TC_MIRRED_BUF_LEN) {
    generic: (slice, 0..20),
    eaction: (i32, 20..24),
    ifindex: (u32, 24..28),
});

impl Emitable for TcMirror {
    fn buffer_len(&self) -> usize {
        TC_MIRRED_BUF_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = TcMirrorBuffer::new(buffer);
        self.generic.emit(packet.generic_mut());
        packet.set_eaction(self.eaction);
        packet.set_ifindex(self.ifindex);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<TcMirrorBuffer<&'a T>>
    for TcMirror
{
    fn parse(buf: &TcMirrorBuffer<&T>) -> Result<Self, DecodeError> {
        Ok(Self {
            generic: TcActionGeneric::parse(&TcActionGenericBuffer::new(
                buf.generic(),
            ))?,
            eaction: buf.eaction(),
            ifindex: buf.ifindex(),
        })
    }
}
