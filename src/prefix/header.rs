// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::super::AddressFamily;

pub(crate) const PREFIX_HEADER_LEN: usize = 12;

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
pub(crate) struct PrefixMessageBuffer {
    prefix_family: u8,
    pad1: u8,
    pad2: u16,
    ifindex: i32,
    prefix_type: u8,
    prefix_len: u8,
    flags: u8,
    pad3: u8,
}

const PREFIX_FLAG_ON_LINK: u8 = 0x80;
const PREFIX_FLAG_AUTONOMOUS: u8 = 0x40;
const PREFIX_FLAG_ROUTER_ADDRESS: u8 = 0x20;
const PREFIX_FLAG_PREFERRED: u8 = 0x10;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    /// Flags of the IPv6 Prefix Information Option carried by
    /// `RTM_NEWPREFIX`.
    ///
    /// `OnLink` and `Autonomous` are defined by RFC 4861 section 4.6.2,
    /// `RouterAddress` by RFC 6275 section 7.2 and `Preferred` by
    /// `draft-ietf-6man-pio-pflag`.
    pub struct PrefixFlags: u8 {
        /// On-link flag, the prefix can be used for on-link determination.
        const OnLink = PREFIX_FLAG_ON_LINK;
        /// Autonomous address-configuration flag.
        const Autonomous = PREFIX_FLAG_AUTONOMOUS;
        /// Router address flag, the prefix field contains the router address.
        const RouterAddress = PREFIX_FLAG_ROUTER_ADDRESS;
        /// Preferred flag, used to disable SLAAC for this prefix.
        const Preferred = PREFIX_FLAG_PREFERRED;
        const _ = !0;
    }
}

// Linux kernel code `struct prefixmsg`
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct PrefixHeader {
    pub prefix_family: AddressFamily,
    pub ifindex: i32,
    pub prefix_type: u8,
    pub prefix_len: u8,
    pub flags: PrefixFlags,
}

impl PrefixHeader {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            PrefixMessageBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), PREFIX_HEADER_LEN)
            })?;
        Ok(Self {
            prefix_family: raw.prefix_family.into(),
            ifindex: raw.ifindex,
            prefix_type: raw.prefix_type,
            prefix_len: raw.prefix_len,
            flags: PrefixFlags::from_bits_retain(raw.flags),
        })
    }
}

impl From<&PrefixHeader> for PrefixMessageBuffer {
    fn from(header: &PrefixHeader) -> Self {
        Self {
            prefix_family: header.prefix_family.into(),
            pad1: 0,
            pad2: 0,
            ifindex: header.ifindex,
            prefix_type: header.prefix_type,
            prefix_len: header.prefix_len,
            flags: header.flags.bits(),
            pad3: 0,
        }
    }
}

impl Emitable for PrefixHeader {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = PrefixMessageBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
