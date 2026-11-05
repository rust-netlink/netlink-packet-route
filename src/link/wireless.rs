// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u16, parse_u16, DecodeError, Emitable, EncodeError,
    Parseable,
};

const IWEVASSOCREQIE: u16 = 0x8C07;
const IWEVASSOCRESPIE: u16 = 0x8C08;

#[cfg(target_pointer_width = "32")]
const IW_HEADER_LEN: usize = 4;
#[cfg(not(target_pointer_width = "32"))]
const IW_HEADER_LEN: usize = 8;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum WirelessEvent {
    /// IEs used for association request. Please use wl_nl80211 crate to parse.
    AssociateRequest(Vec<u8>),
    /// IEs used for association response. Please use wl_nl80211 crate to
    /// parse.
    AssociateResponse(Vec<u8>),
    /// Unknown variant, holds raw payload including length and command
    Other(Vec<u8>),
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<T> for WirelessEvent {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let payload = buf.as_ref();
        if payload.len() < IW_HEADER_LEN {
            return Err(DecodeError::invalid_buffer(
                "WirelessEvent",
                payload.len(),
                IW_HEADER_LEN,
            ));
        }
        let cmd = parse_u16(&payload[2..4])?;
        let data = &payload[IW_HEADER_LEN..];
        Ok(match cmd {
            IWEVASSOCREQIE => Self::AssociateRequest(data.to_vec()),
            IWEVASSOCRESPIE => Self::AssociateResponse(data.to_vec()),
            _ => Self::Other(payload.to_vec()),
        })
    }
}

impl Emitable for WirelessEvent {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Other(v) => append_bytes(out, v),
            Self::AssociateRequest(v) => {
                append_u16(out, (IW_HEADER_LEN + v.len()) as u16);
                append_u16(out, IWEVASSOCREQIE);
                append_bytes(out, &[0u8; IW_HEADER_LEN - 4]);
                append_bytes(out, v);
            }
            Self::AssociateResponse(v) => {
                append_u16(out, (IW_HEADER_LEN + v.len()) as u16);
                append_u16(out, IWEVASSOCRESPIE);
                append_bytes(out, &[0u8; IW_HEADER_LEN - 4]);
                append_bytes(out, v);
            }
        }
        Ok(())
    }
}
