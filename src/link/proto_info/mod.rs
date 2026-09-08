// SPDX-License-Identifier: MIT

mod bridge;
mod inet6;

#[cfg(any(
    target_os = "linux",
    target_os = "fuchsia",
    target_os = "android"
))]
pub(crate) use self::bridge::VecLinkProtoInfoBridge;
pub(crate) use self::inet6::VecLinkProtoInfoInet6;
pub use self::{bridge::LinkProtoInfoBridge, inet6::LinkProtoInfoInet6};
