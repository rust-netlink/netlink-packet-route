// SPDX-License-Identifier: MIT

mod common;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(not(target_os = "freebsd"))]
mod linux;

use std::fmt;

#[cfg(target_os = "freebsd")]
pub use freebsd::*;
#[cfg(not(target_os = "freebsd"))]
pub use linux::*;

impl fmt::Display for LinkFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}
