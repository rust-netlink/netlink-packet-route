// SPDX-License-Identifier: MIT

use netlink_packet_utils::{nla::NlaError, DecodeError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TcError {
    #[error("Invalid {kind}")]
    InvalidValue {
        kind: &'static str,
        #[source]
        error: DecodeError,
    },

    #[error("failed to parse {kind} TCA_OPTIONS attributes")]
    ParseTcaOptionAttributes {
        kind: &'static str,
        #[source]
        error: DecodeError,
    },

    #[error("failed to parse {kind}")]
    ParseFilterMatchallOption {
        kind: &'static str,
        #[source]
        error: DecodeError,
    },

    #[error("failed to parse {kind}")]
    ParseAction {
        kind: &'static str,
        #[source]
        error: DecodeError,
    },

    #[error("failed to parse TCA_ACT_OPTIONS for kind {kind}")]
    ParseActOptions {
        kind: String,
        #[source]
        error: DecodeError,
    },

    #[error("failed to parse mirror action")]
    ParseMirrorAction(#[source] DecodeError),

    #[error("Unknown matchall option: {kind}")]
    UnknownFilterMatchAllOption {
        kind: String,
        #[source]
        error: DecodeError,
    },

    #[error("Unknown NLA type: {kind}")]
    UnknownNla {
        kind: u16,
        #[source]
        error: DecodeError,
    },

    #[error("Unknown TC_OPTIONS: {kind}")]
    UnknownOption {
        kind: String,
        #[source]
        error: DecodeError,
    },

    #[error(transparent)]
    ParseNla(#[from] NlaError),

    #[error("failed to parse TCA_STATS2 for kind {kind}")]
    ParseTcaStats2 {
        kind: String,
        #[source]
        error: DecodeError,
    },

    #[error("Invalid u32 key")]
    InvalidU32Key(#[source] DecodeError),

    #[error("Invalid TcFqCodelXstats length: {0}")]
    InvalidXstatsLength(usize),
}
