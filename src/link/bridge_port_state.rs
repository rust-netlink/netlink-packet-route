// SPDX-License-Identifier: MIT

use netlink_packet_core::DecodeError;

const BR_STATE_DISABLED: u8 = 0;
const BR_STATE_LISTENING: u8 = 1;
const BR_STATE_LEARNING: u8 = 2;
const BR_STATE_FORWARDING: u8 = 3;
const BR_STATE_BLOCKING: u8 = 4;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum BridgePortState {
    Disabled,
    Listening,
    Learning,
    Forwarding,
    Blocking,
    Other(u8),
}

impl From<u8> for BridgePortState {
    fn from(value: u8) -> Self {
        match value {
            BR_STATE_DISABLED => BridgePortState::Disabled,
            BR_STATE_LISTENING => BridgePortState::Listening,
            BR_STATE_LEARNING => BridgePortState::Learning,
            BR_STATE_FORWARDING => BridgePortState::Forwarding,
            BR_STATE_BLOCKING => BridgePortState::Blocking,
            _ => BridgePortState::Other(value),
        }
    }
}

impl From<BridgePortState> for u8 {
    fn from(value: BridgePortState) -> Self {
        match value {
            BridgePortState::Disabled => BR_STATE_DISABLED,
            BridgePortState::Listening => BR_STATE_LISTENING,
            BridgePortState::Learning => BR_STATE_LEARNING,
            BridgePortState::Forwarding => BR_STATE_FORWARDING,
            BridgePortState::Blocking => BR_STATE_BLOCKING,
            BridgePortState::Other(v) => v,
        }
    }
}

impl std::fmt::Display for BridgePortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("disabled"),
            Self::Listening => f.write_str("listening"),
            Self::Learning => f.write_str("learning"),
            Self::Forwarding => f.write_str("forwarding"),
            Self::Blocking => f.write_str("blocking"),
            Self::Other(d) => write!(f, "{d}"),
        }
    }
}

impl std::str::FromStr for BridgePortState {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "listening" => Ok(Self::Listening),
            "learning" => Ok(Self::Learning),
            "forwarding" => Ok(Self::Forwarding),
            "blocking" => Ok(Self::Blocking),
            _ => s.parse::<u8>().map(Self::from).map_err(|_| {
                DecodeError::from(format!("unknown bridge port state: {s}"))
            }),
        }
    }
}
