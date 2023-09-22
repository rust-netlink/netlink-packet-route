// SPDX-License-Identifier: MIT

pub mod ingress {
    pub const KIND: &str = "ingress";
}

pub mod fq_codel;

use netlink_packet_utils::DecodeError;

pub use fq_codel::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum QDisc {
    FqCodel(FqCodel),
}

pub fn unmarshal(kind: &str, data: &[u8]) -> Result<QDisc, DecodeError> {
    match kind {
        FQ_CODEL => {
            let fq = fq_codel::unmarshal_fq_codel(data)?;
            Ok(QDisc::FqCodel(fq))
        }
        _ => Err(DecodeError::from("Unknown classless kind")),
    }
}
