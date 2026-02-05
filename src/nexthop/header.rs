use netlink_packet_core::{DecodeError, Emitable, Parseable};

use super::NexthopMessageBuffer;
use crate::AddressFamily;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct NexthopHeader {
    pub family: AddressFamily,
    pub scope: u8,
    pub protocol: u8,
    pub flags: NexthopFlags,
}

impl Default for NexthopHeader {
    fn default() -> Self {
        Self {
            family: AddressFamily::Unspec,
            scope: 0,
            protocol: 0,
            flags: NexthopFlags::empty(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NexthopMessageBuffer<&'a T>>
    for NexthopHeader
{
    fn parse(buf: &NexthopMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(Self {
            family: buf.family().into(),
            scope: buf.scope(),
            protocol: buf.protocol(),
            flags: buf.flags(),
        })
    }
}

impl Emitable for NexthopHeader {
    fn buffer_len(&self) -> usize {
        8
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NexthopMessageBuffer::new(buffer);
        buffer.set_family(self.family.into());
        buffer.set_scope(self.scope);
        buffer.set_protocol(self.protocol);
        buffer.set_flags(self.flags);
        buffer.set_resvd(0);
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct NexthopFlags: u32 {
        const F_DEAD = 1;
        const F_PERVASIVE = 2;
        const F_ONLINK = 4;
        const F_OFFLOAD = 8;
        const F_LINKDOWN = 16;
        const F_UNRESOLVED = 32;
        const F_TRAP = 64;
    }
}
