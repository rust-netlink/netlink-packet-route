// SPDX-License-Identifier: MIT

pub mod neighbour;
pub use neighbour::{
    NeighbourHeader, NeighbourMessage, NeighbourMessageBuffer,
    NEIGHBOUR_HEADER_LEN,
};

pub mod neighbour_table;
pub use neighbour_table::{
    NeighbourTableHeader, NeighbourTableMessage, NeighbourTableMessageBuffer,
    NEIGHBOUR_TABLE_HEADER_LEN,
};

pub mod nsid;
pub use nsid::{NsidHeader, NsidMessage, NsidMessageBuffer, NSID_HEADER_LEN};

pub mod rule;
pub use rule::{RuleHeader, RuleMessage, RuleMessageBuffer, RULE_HEADER_LEN};

pub mod constants;
pub use self::constants::*;

mod buffer;
pub use self::buffer::*;

mod message;
pub use self::message::*;

pub mod nlas {
    pub use super::{
        neighbour::nlas as neighbour, neighbour_table::nlas as neighbour_table,
        nsid::nlas as nsid, rule::nlas as rule,
    };
}
