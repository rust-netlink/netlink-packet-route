// SPDX-License-Identifier: MIT

mod bridge;
mod inet6;

#[cfg(not(target_os = "freebsd"))]
pub(crate) use self::bridge::VecLinkProtoInfoBridge;
pub(crate) use self::inet6::VecLinkProtoInfoInet6;
pub use self::{bridge::LinkProtoInfoBridge, inet6::LinkProtoInfoInet6};
