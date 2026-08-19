// SPDX-License-Identifier: MIT

//! The `netlink-packet-route` crate is designed to abstract Netlink route
//! protocol(`rtnetlink`) packet into Rust data types. The goal of this crate is
//! saving netlink user from reading Kernel Netlink codes.
//!
//! This crate grouped Netlink route protocol into these modules:
//!  * `link`: NIC interface, similar to `ip link` command.
//!  * `address`: IP address, similar to `ip address` command.
//!  * `addrlabel`: Address label, similar to `ip addrlabel` command.
//!  * `route`: Route, similar to `ip route` command.
//!  * `rule`: Route rule, similar to `ip rule` command.
//!  * `tc`: Traffic control, similar to `tc` command.
//!  * `neighbour`: Neighbour, similar to `ip neighbour` command.
//!  * `neighbour_table`: Neighbour table, similar to `ip ntable` command.
//!  * `nsid`: Namespace, similar to `ip netns` command.
//!
//! At the top level of this crate, we also provide:
//!  * [AddressFamily]
//!
//! # Feature flags
//!
//! Every message family above has a cargo feature of the same name, and all of
//! them are enabled by default through the `all` feature. Disabling a family
//! removes its module, its [`RouteNetlinkMessage`] variants and its parsing
//! code; messages of that family then fail to parse with `Unknown message
//! type`, exactly as message types this crate never supported do.
//!
//! The `link` module additionally splits its largest attributes into
//! `link-af-spec`, `link-info` and `link-sriov`. With one of those disabled the
//! corresponding attribute is parsed into `LinkAttribute::Other` instead of
//! being decoded.
//!
//! This only matters for binary size; the default feature set behaves exactly
//! like earlier releases.
//!
//! Normally, you should use [`rtnetlink`][rtnetlink_url] instead of using this
//! crate directly.
//!
//! [rtnetlink_url]: https://docs.rs/rtnetlink

#[cfg(feature = "address")]
pub mod address;
mod address_family;
#[cfg(feature = "addrlabel")]
pub mod addrlabel;
#[cfg(feature = "link")]
pub mod link;
#[cfg(feature = "neighbour")]
pub mod neighbour;
#[cfg(feature = "neighbour-table")]
pub mod neighbour_table;
#[cfg(feature = "nsid")]
pub mod nsid;
#[cfg(feature = "prefix")]
pub mod prefix;
#[cfg(feature = "route")]
pub mod route;
#[cfg(feature = "rule")]
pub mod rule;
#[cfg(feature = "stats")]
pub mod stats;
#[cfg(feature = "tc")]
pub mod tc;

mod message;
#[cfg(all(test, feature = "link"))]
mod tests;

// Not every message family uses every helper in here.
#[allow(dead_code)]
pub(crate) mod ip;

#[cfg(any(target_os = "linux", target_os = "fuchsia", target_os = "android"))]
mod address_family_linux;
#[cfg(any(
    target_os = "linux",
    target_os = "fuchsia",
    target_os = "android"
))]
pub use self::address_family_linux::AddressFamily;

#[cfg(target_os = "freebsd")]
mod address_family_freebsd;
#[cfg(target_os = "freebsd")]
pub use self::address_family_freebsd::AddressFamily;

#[cfg(not(any(
    target_os = "linux",
    target_os = "fuchsia",
    target_os = "freebsd",
    target_os = "android",
)))]
mod address_family_fallback;
// Re-export `EthernetProtocol` from `netlink-packet-core` 0.8.2 so that
// `netlink_packet_route::EthernetProtocol` stays available (previously
// defined locally in `mac` module).
pub use netlink_packet_core::EthernetProtocol;

#[cfg(not(any(
    target_os = "linux",
    target_os = "fuchsia",
    target_os = "freebsd",
    target_os = "android",
)))]
pub use self::address_family_fallback::AddressFamily;
pub use self::{ip::IpProtocol, message::RouteNetlinkMessage};

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[cfg(any(
    feature = "address",
    feature = "link",
    feature = "neighbour",
    feature = "route",
    feature = "rule",
    feature = "stats",
    feature = "tc"
))]
#[macro_use]
extern crate bitflags;

#[cfg(not(any(
    feature = "address",
    feature = "addrlabel",
    feature = "link",
    feature = "neighbour",
    feature = "neighbour-table",
    feature = "nsid",
    feature = "prefix",
    feature = "route",
    feature = "rule",
    feature = "stats",
    feature = "tc"
)))]
compile_error!(
    "netlink-packet-route requires at least one message family feature; see \
     the `Feature flags` section of the crate documentation"
);
