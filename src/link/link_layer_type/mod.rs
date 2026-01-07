// SPDX-License-Identifier: MIT

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(not(target_os = "freebsd"))]
mod linux;

#[cfg(target_os = "freebsd")]
pub use freebsd::*;
#[cfg(not(target_os = "freebsd"))]
pub use linux::*;

impl From<LinkLayerType> for u16 {
    fn from(v: LinkLayerType) -> u16 {
        v as u16
    }
}

impl LinkLayerType {
    #[allow(non_upper_case_globals)]
    pub const Cisco: LinkLayerType = LinkLayerType::Hdlc;
}
