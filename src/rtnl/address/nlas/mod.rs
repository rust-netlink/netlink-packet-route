// SPDX-License-Identifier: MIT

mod cache_info;
#[cfg(test)]
mod test;

pub use self::cache_info::*;

use std::mem::size_of;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{self, DefaultNla, NlaBuffer},
    parsers::{parse_string, parse_u32},
    traits::Parseable,
    DecodeError,
};

use crate::constants::*;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Nla {
    Unspec(Vec<u8>),
    Address(Vec<u8>),
    Local(Vec<u8>),
    Label(String),
    Broadcast(Vec<u8>),
    Anycast(Vec<u8>),
    CacheInfo(Vec<u8>),
    Multicast(Vec<u8>),
    Flags(Vec<Inet6AddrFlag>),
    Other(DefaultNla),
}

impl nla::Nla for Nla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Address(ref bytes)
                | Local(ref bytes)
                | Broadcast(ref bytes)
                | Anycast(ref bytes)
                | Multicast(ref bytes) => bytes.len(),

            // strings: +1 because we need to append a nul byte
            Label(ref string) => string.as_bytes().len() + 1,

            // u32
            Flags(_) => size_of::<u32>(),

            // Native
            CacheInfo(ref buffer) => buffer.len(),

            // Defaults
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Address(ref bytes)
                | Local(ref bytes)
                | Broadcast(ref bytes)
                | Anycast(ref bytes)
                | CacheInfo(ref bytes)
                | Multicast(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            // String
            Label(ref string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }

            // u32
            Flags(ref value) => NativeEndian::write_u32(
                buffer,
                u32::from(&_Inet6AddrFlags(value.to_vec()))),

            // Default
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Unspec(_) => IFA_UNSPEC,
            Address(_) => IFA_ADDRESS,
            Local(_) => IFA_LOCAL,
            Label(_) => IFA_LABEL,
            Broadcast(_) => IFA_BROADCAST,
            Anycast(_) => IFA_ANYCAST,
            CacheInfo(_) => IFA_CACHEINFO,
            Multicast(_) => IFA_MULTICAST,
            Flags(_) => IFA_FLAGS,
            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::Nla::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFA_UNSPEC => Unspec(payload.to_vec()),
            IFA_ADDRESS => Address(payload.to_vec()),
            IFA_LOCAL => Local(payload.to_vec()),
            IFA_LABEL => {
                Label(parse_string(payload).context("invalid IFA_LABEL value")?)
            }
            IFA_BROADCAST => Broadcast(payload.to_vec()),
            IFA_ANYCAST => Anycast(payload.to_vec()),
            IFA_CACHEINFO => CacheInfo(payload.to_vec()),
            IFA_MULTICAST => Multicast(payload.to_vec()),
            IFA_FLAGS => Flags(
                _Inet6AddrFlags::from(
                    parse_u32(payload).context("invalid IFA_FLAGS value")?,
                )
                .0,
            ),
            kind => Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}

const IFA_F_SECONDARY: u32 = 0x01;
const IFA_F_NODAD: u32 = 0x02;
const IFA_F_OPTIMISTIC: u32 = 0x04;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_HOMEADDRESS: u32 = 0x10;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_F_MANAGETEMPADDR: u32 = 0x100;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;
const IFA_F_MCAUTOJOIN: u32 = 0x400;
const IFA_F_STABLE_PRIVACY: u32 = 0x800;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
#[repr(u32)]
pub enum Inet6AddrFlag {
    Secondary = IFA_F_SECONDARY,
    Nodad = IFA_F_NODAD,
    Optimistic = IFA_F_OPTIMISTIC,
    Dadfailed = IFA_F_DADFAILED,
    Homeaddress = IFA_F_HOMEADDRESS,
    Deprecated = IFA_F_DEPRECATED,
    Tentative = IFA_F_TENTATIVE,
    Permanent = IFA_F_PERMANENT,
    Managetempaddr = IFA_F_MANAGETEMPADDR,
    Noprefixroute = IFA_F_NOPREFIXROUTE,
    Mcautojoin = IFA_F_MCAUTOJOIN,
    StablePrivacy = IFA_F_STABLE_PRIVACY,
}

const ALL_INET6_FLAGS: [Inet6AddrFlag; 12] = [
    Inet6AddrFlag::Secondary,
    Inet6AddrFlag::Nodad,
    Inet6AddrFlag::Optimistic,
    Inet6AddrFlag::Dadfailed,
    Inet6AddrFlag::Homeaddress,
    Inet6AddrFlag::Deprecated,
    Inet6AddrFlag::Tentative,
    Inet6AddrFlag::Permanent,
    Inet6AddrFlag::Managetempaddr,
    Inet6AddrFlag::Noprefixroute,
    Inet6AddrFlag::Mcautojoin,
    Inet6AddrFlag::StablePrivacy,
];

#[derive(Clone, Eq, PartialEq, Debug)]
struct _Inet6AddrFlags(Vec<Inet6AddrFlag>);

impl From<u32> for _Inet6AddrFlags {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_INET6_FLAGS {
            if (d & (flag as u32)) > 0 {
                ret.push(flag);
                got += flag as u32;
            }
        }
        if got != d {
            eprintln!("Discarded unsupported IFA_FLAGS: {}", d - got);
        }
        Self(ret)
    }
}

impl From<&_Inet6AddrFlags> for u32 {
    fn from(v: &_Inet6AddrFlags) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += *flag as u32;
        }
        d
    }
}
