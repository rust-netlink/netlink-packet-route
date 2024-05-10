// General purpose networking abstractions.
#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
)]

pub mod arp;
pub mod ethernet;
pub mod icmpv4;
pub mod icmpv6;
pub mod mpls;
pub mod vxlan;
