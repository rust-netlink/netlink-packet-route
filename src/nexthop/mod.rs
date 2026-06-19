// SPDX-License-Identifier: MIT

mod attribute;
mod buffer;
mod header;
mod message;

pub use self::{
    attribute::{NexthopAttribute, NexthopAttributeType, NexthopGroupEntry},
    buffer::NexthopMessageBuffer,
    header::{NexthopFlags, NexthopHeader},
    message::NexthopMessage,
};
