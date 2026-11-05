// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const VF_INFO_TRUST_LEN: usize = 8;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
#[non_exhaustive]
pub struct VfInfoTrust {
    pub vf_id: u32,
    pub enabled: bool,
}

impl VfInfoTrust {
    pub fn new(vf_id: u32, enabled: bool) -> Self {
        Self { vf_id, enabled }
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct VfInfoTrustBuffer {
    vf_id: u32,
    setting: u32,
}

#[allow(dead_code)]
impl VfInfoTrust {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            VfInfoTrustBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), VF_INFO_TRUST_LEN)
            })?;
        Ok(Self::new(
            raw.vf_id,
            raw.setting > 0 && raw.setting != u32::MAX,
        ))
    }
}

#[allow(dead_code)]
impl From<&VfInfoTrust> for VfInfoTrustBuffer {
    fn from(trust: &VfInfoTrust) -> Self {
        Self {
            vf_id: trust.vf_id,
            setting: trust.enabled as u32,
        }
    }
}

impl Emitable for VfInfoTrust {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_bytes(out, VfInfoTrustBuffer::from(self).as_bytes());
        Ok(())
    }
}
