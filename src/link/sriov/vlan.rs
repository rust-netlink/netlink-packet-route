// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const VF_INFO_VLAN_LEN: usize = 12;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
#[non_exhaustive]
pub struct VfInfoVlan {
    pub vf_id: u32,
    pub vlan_id: u32,
    pub qos: u32,
}

impl VfInfoVlan {
    pub fn new(vf_id: u32, vlan_id: u32, qos: u32) -> Self {
        Self {
            vf_id,
            vlan_id,
            qos,
        }
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
pub struct VfInfoVlanBuffer {
    vf_id: u32,
    vlan_id: u32,
    qos: u32,
}

#[allow(dead_code)]
impl VfInfoVlan {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            VfInfoVlanBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), VF_INFO_VLAN_LEN)
            })?;
        Ok(Self {
            vf_id: raw.vf_id,
            vlan_id: raw.vlan_id,
            qos: raw.qos,
        })
    }
}

#[allow(dead_code)]
impl From<&VfInfoVlan> for VfInfoVlanBuffer {
    fn from(vlan: &VfInfoVlan) -> Self {
        Self {
            vf_id: vlan.vf_id,
            vlan_id: vlan.vlan_id,
            qos: vlan.qos,
        }
    }
}

impl Emitable for VfInfoVlan {
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_bytes(out, VfInfoVlanBuffer::from(self).as_bytes());
        Ok(())
    }
}
