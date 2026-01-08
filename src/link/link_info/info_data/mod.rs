// SPDX-License-Identifier: MIT

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(not(target_os = "freebsd"))]
mod linux;

#[cfg(target_os = "freebsd")]
pub use self::freebsd::*;
#[cfg(not(target_os = "freebsd"))]
pub use self::linux::*;

const IFLA_INFO_DATA: u16 = 2;
