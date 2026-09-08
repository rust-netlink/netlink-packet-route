// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u32, DecodeError, DefaultNla, ErrorContext, Nla, Parseable,
};

use crate::buffer_freebsd::FreeBSDBuffer;

const IN6_IFF_ANYCAST: u32 = 0x01;
const IN6_IFF_TENTATIVE: u32 = 0x02;
const IN6_IFF_DUPLICATED: u32 = 0x04;
const IN6_IFF_DETACHED: u32 = 0x08;
const IN6_IFF_DEPRECATED: u32 = 0x10;
const IN6_IFF_NODAD: u32 = 0x20;
const IN6_IFF_AUTOCONF: u32 = 0x40;
const IN6_IFF_TEMPORARY: u32 = 0x80;
const IN6_IFF_PREFER_SOURCE: u32 = 0x100;
const IN6_IFF_NOTREADY: u32 = IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED;

const IFAF_VHID: u16 = 1;
const IFAF_FLAGS: u16 = 2;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IfaFlags : u32 {
        const Anycast = IN6_IFF_ANYCAST;
        const Tentative = IN6_IFF_TENTATIVE;
        const Duplicated = IN6_IFF_DUPLICATED;
        const Detached = IN6_IFF_DETACHED;
        const Deprecated = IN6_IFF_DEPRECATED;
        const Nodad = IN6_IFF_NODAD;
        const Autoconf = IN6_IFF_AUTOCONF;
        const Temporary = IN6_IFF_TEMPORARY;
        const PreferSource = IN6_IFF_PREFER_SOURCE;
        const Notready = IN6_IFF_NOTREADY;
        const _ = !0;
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FreeBsdAddressAttribute {
    Vhid(u32),
    IfaFlags(IfaFlags),
    Other(DefaultNla),
}

impl Nla for FreeBsdAddressAttribute {
    fn kind(&self) -> u16 {
        match self {
            FreeBsdAddressAttribute::Vhid(_) => IFAF_VHID,
            FreeBsdAddressAttribute::IfaFlags(_) => IFAF_FLAGS,
            FreeBsdAddressAttribute::Other(nla) => nla.kind(),
        }
    }

    fn value_len(&self) -> usize {
        match self {
            FreeBsdAddressAttribute::Vhid(_) => 4,
            FreeBsdAddressAttribute::IfaFlags(_) => 4,
            FreeBsdAddressAttribute::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            FreeBsdAddressAttribute::Vhid(vhid) => {
                buffer.copy_from_slice(&vhid.to_ne_bytes());
            }
            FreeBsdAddressAttribute::IfaFlags(ifa_flags) => {
                buffer.copy_from_slice(&ifa_flags.bits().to_ne_bytes());
            }
            FreeBsdAddressAttribute::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<FreeBSDBuffer<&'buffer T>>
    for FreeBsdAddressAttribute
{
    fn parse(buf: &FreeBSDBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        if buf.inner().len() < buf.length() as usize {
            return Err(DecodeError::from(
                "Buffer length is smaller than indicated length",
            ));
        }

        let value = parse_u32(buf.value())
            .context("failed to parse IFA_FREEBSD attribute value")?;
        match buf.value_type() {
            IFAF_VHID => Ok(FreeBsdAddressAttribute::Vhid(value)),
            IFAF_FLAGS => Ok(FreeBsdAddressAttribute::IfaFlags(
                IfaFlags::from_bits(value).ok_or_else(|| {
                    DecodeError::from("invalid IFA_FLAGS value")
                })?,
            )),
            kind => Ok(FreeBsdAddressAttribute::Other(DefaultNla::new(
                kind,
                buf.value().to_vec(),
            ))),
        }
    }
}
