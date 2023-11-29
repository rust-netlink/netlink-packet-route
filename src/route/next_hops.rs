// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    nla::{NlaBuffer, NlasIterator},
    traits::{Emitable, ParseableParametrized},
    DecodeError,
};

use super::{
    super::AddressFamily, RouteAttribute, RouteLwEnCapType, RouteType,
};

pub(crate) const RTNH_F_DEAD: u8 = 1;
pub(crate) const RTNH_F_PERVASIVE: u8 = 2;
pub(crate) const RTNH_F_ONLINK: u8 = 4;
pub(crate) const RTNH_F_OFFLOAD: u8 = 8;
pub(crate) const RTNH_F_LINKDOWN: u8 = 16;
pub(crate) const RTNH_F_UNRESOLVED: u8 = 32;
pub(crate) const RTNH_F_TRAP: u8 = 64;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
pub enum RouteNextHopFlag {
    Dead,
    Pervasive,
    Onlink,
    Offload,
    Linkdown,
    Unresolved,
    Trap,
    Other(u8),
}

impl From<RouteNextHopFlag> for u8 {
    fn from(v: RouteNextHopFlag) -> u8 {
        match v {
            RouteNextHopFlag::Dead => RTNH_F_DEAD,
            RouteNextHopFlag::Pervasive => RTNH_F_PERVASIVE,
            RouteNextHopFlag::Onlink => RTNH_F_ONLINK,
            RouteNextHopFlag::Offload => RTNH_F_OFFLOAD,
            RouteNextHopFlag::Linkdown => RTNH_F_LINKDOWN,
            RouteNextHopFlag::Unresolved => RTNH_F_UNRESOLVED,
            RouteNextHopFlag::Trap => RTNH_F_TRAP,
            RouteNextHopFlag::Other(i) => i,
        }
    }
}

const ALL_NH_FLAGS: [RouteNextHopFlag; 7] = [
    RouteNextHopFlag::Dead,
    RouteNextHopFlag::Pervasive,
    RouteNextHopFlag::Onlink,
    RouteNextHopFlag::Offload,
    RouteNextHopFlag::Linkdown,
    RouteNextHopFlag::Unresolved,
    RouteNextHopFlag::Trap,
];

#[derive(Clone, Eq, PartialEq, Debug)]
struct VecRouteNextHopFlag(Vec<RouteNextHopFlag>);

impl From<u8> for VecRouteNextHopFlag {
    fn from(d: u8) -> Self {
        let mut got: u8 = 0;
        let mut ret = Vec::new();
        for flag in ALL_NH_FLAGS {
            if (d & (u8::from(flag))) > 0 {
                ret.push(flag);
                got += u8::from(flag);
            }
        }
        if got != d {
            ret.push(RouteNextHopFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&VecRouteNextHopFlag> for u8 {
    fn from(v: &VecRouteNextHopFlag) -> u8 {
        let mut d: u8 = 0;
        for flag in &v.0 {
            d += u8::from(*flag);
        }
        d
    }
}

const PAYLOAD_OFFSET: usize = 8;

buffer!(RouteNextHopBuffer {
    length: (u16, 0..2),
    flags: (u8, 2),
    hops: (u8, 3),
    interface_index: (u32, 4..8),
    payload: (slice, PAYLOAD_OFFSET..),
});

impl<T: AsRef<[u8]>> RouteNextHopBuffer<T> {
    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let packet = Self::new(buffer);
        packet.check_buffer_length()?;
        Ok(packet)
    }

    fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < PAYLOAD_OFFSET {
            return Err(format!(
                "invalid RouteNextHopBuffer: length {len} < {PAYLOAD_OFFSET}"
            )
            .into());
        }
        if len < self.length() as usize {
            return Err(format!(
                "invalid RouteNextHopBuffer: length {} < {}",
                len,
                8 + self.length()
            )
            .into());
        }
        Ok(())
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> RouteNextHopBuffer<&'a T> {
    pub fn attributes(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(
            &self.payload()[..(self.length() as usize - PAYLOAD_OFFSET)],
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[non_exhaustive]
pub struct RouteNextHop {
    /// Next-hop flags
    pub flags: Vec<RouteNextHopFlag>,
    /// Next-hop priority
    pub hops: u8,
    /// Interface index for the next-hop
    pub interface_index: u32,
    /// Attributes
    pub attributes: Vec<RouteAttribute>,
}

impl<'a, T: AsRef<[u8]>>
    ParseableParametrized<
        RouteNextHopBuffer<&'a T>,
        (AddressFamily, RouteType, RouteLwEnCapType),
    > for RouteNextHop
{
    fn parse_with_param(
        buf: &RouteNextHopBuffer<&T>,
        (address_family, route_type, encap_type): (
            AddressFamily,
            RouteType,
            RouteLwEnCapType,
        ),
    ) -> Result<RouteNextHop, DecodeError> {
        let attributes = Vec::<RouteAttribute>::parse_with_param(
            &RouteNextHopBuffer::new_checked(buf.buffer)
                .context("cannot parse route attributes in next-hop")?,
            (address_family, route_type, encap_type),
        )
        .context("cannot parse route attributes in next-hop")?;
        Ok(RouteNextHop {
            flags: VecRouteNextHopFlag::from(buf.flags()).0,
            hops: buf.hops(),
            interface_index: buf.interface_index(),
            attributes,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a>
    ParseableParametrized<
        RouteNextHopBuffer<&'a T>,
        (AddressFamily, RouteType, RouteLwEnCapType),
    > for Vec<RouteAttribute>
{
    fn parse_with_param(
        buf: &RouteNextHopBuffer<&'a T>,
        (address_family, route_type, encap_type): (
            AddressFamily,
            RouteType,
            RouteLwEnCapType,
        ),
    ) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.attributes() {
            nlas.push(RouteAttribute::parse_with_param(
                &nla_buf?,
                (address_family, route_type, encap_type),
            )?);
        }
        Ok(nlas)
    }
}

impl Emitable for RouteNextHop {
    fn buffer_len(&self) -> usize {
        // len, flags, hops and interface id fields
        PAYLOAD_OFFSET + self.attributes.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut nh_buffer = RouteNextHopBuffer::new(buffer);
        nh_buffer.set_length(self.buffer_len() as u16);
        nh_buffer
            .set_flags(u8::from(&VecRouteNextHopFlag(self.flags.to_vec())));
        nh_buffer.set_hops(self.hops);
        nh_buffer.set_interface_index(self.interface_index);
        self.attributes.as_slice().emit(nh_buffer.payload_mut())
    }
}
