// SPDX-License-Identifier: MIT

use crate::route::RouteError;
use netlink_packet_utils::{nla::NlaError, DecodeError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("Invalid {kind}")]
    InvalidValue {
        kind: &'static str,
        error: DecodeError,
    },

    #[error("Unknown NLA type: {kind}")]
    UnknownNLA { kind: u16, error: DecodeError },

    #[error(transparent)]
    ParseNla(#[from] NlaError),

    #[error(transparent)]
    ParseFraFlow(#[from] RouteError),

    #[error("Invalid rule uid range data, expecting {expected} u8 array, but got {got}")]
    ParseUidRange { expected: usize, got: usize },

    #[error("Invalid rule port range data, expecting {expected} u8 array, but got {got}")]
    ParsePortRange { expected: usize, got: usize },
}
