// SPDX-License-Identifier: MIT

pub use nat_flag::TcNatFlags;

pub(crate) use self::action::TcActionGenericBuffer;
pub use self::{
    action::{
        TcAction, TcActionAttribute, TcActionGeneric, TcActionOption,
        TcActionType, Tcf,
    },
    header::TcActionMessageHeader,
    message::{
        TcActionMessage, TcActionMessageAttribute, TcActionMessageFlags,
        TcActionMessageFlagsWithSelector,
    },
    mirror::{
        TcActionMirror, TcActionMirrorOption, TcMirror, TcMirrorActionType,
    },
    nat::{TcActionNat, TcActionNatOption, TcNat},
    tunnel_key::{TcActionTunnelKey, TcActionTunnelKeyOption, TcTunnelKey},
};

mod action;
mod header;
mod message;
mod mirror;
mod nat;
mod nat_flag;
mod tunnel_key;

#[cfg(test)]
pub mod tests;
