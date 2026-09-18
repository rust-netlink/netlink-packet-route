// SPDX-License-Identifier: MIT

mod attribute;
mod header;
mod message;
#[cfg(test)]
mod tests;

pub use self::{
    attribute::AddrLabelAttribute,
    header::{AddrLabelHeader, AddrLabelMessageBuffer},
    message::AddrLabelMessage,
};
