// SPDX-License-Identifier: MIT

mod addr_flags;
mod addr_scope;
mod attribute;
mod cache_info;
mod message;

#[cfg(target_os = "freebsd")]
mod freebsd;

#[cfg(test)]
mod tests;

pub use self::{
    addr_flags::{AddressFlags, AddressHeaderFlags},
    addr_scope::AddressScope,
    attribute::{AddressAttribute, AddressProtocol},
    cache_info::{CacheInfo, CacheInfoBuffer},
    message::{AddressHeader, AddressMessage, AddressMessageBuffer},
};
