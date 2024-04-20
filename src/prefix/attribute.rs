// SPDX-License-Identifier: MIT

use super::{
    cache_info::{CacheInfo, CacheInfoBuffer},
    error::PrefixError,
};
use netlink_packet_utils::{
    nla::{self, DefaultNla, NlaBuffer},
    traits::Parseable,
    Emitable,
};
use std::net::Ipv6Addr;

const PREFIX_ADDRESS: u16 = 1;
const PREFIX_CACHEINFO: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrefixAttribute {
    Address(Ipv6Addr),
    CacheInfo(CacheInfo),
    Other(DefaultNla),
}

impl nla::Nla for PrefixAttribute {
    fn value_len(&self) -> usize {
        match *self {
            Self::Address(_) => 16,
            Self::CacheInfo(ref cache_info) => cache_info.buffer_len(),
            Self::Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Address(ref addr) => buffer.copy_from_slice(&addr.octets()),
            Self::CacheInfo(ref cache_info) => cache_info.emit(buffer),
            Self::Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Address(_) => PREFIX_ADDRESS,
            Self::CacheInfo(_) => PREFIX_CACHEINFO,
            Self::Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for PrefixAttribute
{
    type Error = PrefixError;
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, PrefixError> {
        let payload = buf.value();
        match buf.kind() {
            PREFIX_ADDRESS => {
                if let Ok(payload) = TryInto::<[u8; 16]>::try_into(payload) {
                    Ok(Self::Address(Ipv6Addr::from(payload)))
                } else {
                    Err(PrefixError::InvalidPrefixAddress {
                        payload_length: payload.len(),
                    })
                }
            }
            PREFIX_CACHEINFO => Ok(Self::CacheInfo(
                CacheInfo::parse(&CacheInfoBuffer::new(payload))
                    .map_err(PrefixError::InvalidPrefixCacheInfo)?,
            )),
            _ => Ok(Self::Other(
                DefaultNla::parse(buf).map_err(PrefixError::Other)?,
            )),
        }
    }
}
