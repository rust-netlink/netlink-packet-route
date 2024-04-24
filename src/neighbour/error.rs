// SPDX-License-Identifier: MIT

use crate::route::RouteError;
use netlink_packet_utils::{nla::NlaError, DecodeError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NeighbourError {
    #[error("Invalid {kind}")]
    InvalidValue {
        kind: &'static str,
        error: DecodeError,
    },

    #[error("Unknown NLA type: {kind}")]
    UnknownNLA { kind: u16, error: DecodeError },

    #[error(transparent)]
    ParseNdaProtocol(#[from] RouteError),

    #[error(transparent)]
    ParseNla(#[from] NlaError),
}
