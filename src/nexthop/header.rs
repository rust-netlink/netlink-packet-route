// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{NlaBuffer, NlasIterator},
    traits::{Emitable, Parseable},
    DecodeError,
};

use super::NexthopFlags;
use crate::{
    route::{RouteProtocol, RouteScope},
    AddressFamily,
};

const NEXTHOP_HEADER_LEN: usize = 8;

buffer!(NexthopMessageBuffer(NEXTHOP_HEADER_LEN) {
    address_family: (u8, 0),
    scope: (u8, 1),
    protocol: (u8, 2),
    resvd: (u8, 3),
    flags: (u32, 4..NEXTHOP_HEADER_LEN),
    payload: (slice, NEXTHOP_HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized> NexthopMessageBuffer<&'a T> {
    pub fn attributes(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct NexthopHeader {
    pub address_family: AddressFamily,
    // Nexthop scope.
    pub scope: RouteScope,
    // Protocol.
    pub protocol: RouteProtocol,
    // Reserved
    pub resvd: u8,
    // Nexthop flags.
    pub flags: NexthopFlags,
}

impl<T: AsRef<[u8]>> Parseable<NexthopMessageBuffer<T>> for NexthopHeader {
    fn parse(buf: &NexthopMessageBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            address_family: buf.address_family().into(),
            protocol: buf.protocol().into(),
            scope: buf.scope().into(),
            resvd: buf.resvd().into(),
            flags: NexthopFlags::from_bits_retain(buf.flags()),
        })
    }
}

impl Emitable for NexthopHeader {
    fn buffer_len(&self) -> usize {
        NEXTHOP_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = NexthopMessageBuffer::new(buffer);
        packet.set_address_family(self.address_family.into());
        packet.set_scope(self.scope.into());
        packet.set_protocol(self.protocol.into());
        packet.set_resvd(self.resvd.into());
        packet.set_flags(self.flags.bits());
    }
}
