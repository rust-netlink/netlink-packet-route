// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16, parse_u32},
    DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::{
    route::{RouteAddress, RouteLwTunnelEncap},
    AddressFamily,
};

use super::NexthopGroup;

const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_GROUP_TYPE: u16 = 3;
const NHA_BLACKHOLE: u16 = 4;
const NHA_OIF: u16 = 5;
const NHA_GATEWAY: u16 = 6;
const NHA_ENCAP_TYPE: u16 = 7;
const NHA_ENCAP: u16 = 8;
const NHA_GROUPS: u16 = 9;
const NHA_MASTER: u16 = 10;
const NHA_FDB: u16 = 11;
// const NHA_RES_GROUP: u16 = 12;
// const NHA_RES_BUCKET: u16 = 13;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NexthopAttribute {
    Id(u32),
    Group(Vec<NexthopGroup>),
    GroupType(u16),
    Blackhole,
    Oif(u32),
    Gateway(RouteAddress),
    EncapType(u16),
    Encap(Vec<RouteLwTunnelEncap>),
    Groups,
    Master(u32),
    Fdb,
    Other(DefaultNla),
}

impl Nla for NexthopAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Id(_) | Self::Oif(_) | Self::Master(_) => 4,
            Self::Group(groups) => {
                groups.iter().map(|grp| grp.buffer_len()).sum()
            }
            Self::GroupType(_) | Self::EncapType(_) => 2,
            Self::Blackhole | Self::Groups | Self::Fdb => 0,
            Self::Encap(v) => v.as_slice().buffer_len(),
            Self::Gateway(addr) => addr.buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Id(value) | Self::Oif(value) | Self::Master(value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            Self::Group(groups) => {
                let mut offset = 0;
                for grp in groups {
                    let len = grp.buffer_len();
                    grp.emit(&mut buffer[offset..offset + len]);
                    offset += len
                }
            }
            Self::GroupType(value) | Self::EncapType(value) => {
                NativeEndian::write_u16(buffer, *value);
            }
            Self::Blackhole | Self::Groups | Self::Fdb => {}
            Self::Encap(nlas) => nlas.as_slice().emit(buffer),
            Self::Gateway(addr) => addr.emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => NHA_ID,
            Self::Group(_) => NHA_GROUP,
            Self::GroupType(_) => NHA_GROUP_TYPE,
            Self::Blackhole => NHA_BLACKHOLE,
            Self::Oif(_) => NHA_OIF,
            Self::Gateway(_) => NHA_GATEWAY,
            Self::EncapType(_) => NHA_ENCAP_TYPE,
            Self::Encap(_) => NHA_ENCAP,
            Self::Groups => NHA_GROUPS,
            Self::Master(_) => NHA_MASTER,
            Self::Fdb => NHA_FDB,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NlaBuffer<&'a T>, AddressFamily>
    for NexthopAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        address_family: AddressFamily,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NHA_ID => Self::Id(
                parse_u32(payload).context(format!("invalid NHA_ID value"))?,
            ),
            NHA_GROUP => {
                let mut groups = vec![];
                let mut i: usize = 0;
                while i + 8 <= payload.len() {
                    groups.push(NexthopGroup::parse(&payload[i..i + 8])?);
                    i += 8;
                }
                Self::Group(groups)
            }
            NHA_GROUP_TYPE => Self::GroupType(
                parse_u16(payload)
                    .context(format!("invalid NHA_GROUP_TYPE value"))?,
            ),
            NHA_BLACKHOLE => Self::Blackhole,
            NHA_OIF => Self::Oif(
                parse_u32(payload).context(format!("invalid NHA_OIF value"))?,
            ),
            NHA_GATEWAY => {
                Self::Gateway(RouteAddress::parse(address_family, payload)?)
            }
            NHA_ENCAP_TYPE => Self::EncapType(
                parse_u16(payload)
                    .context(format!("invalid NHA_ENCAP_TYPE value"))?,
            ),
            NHA_GROUPS => Self::Groups,
            NHA_MASTER => Self::Master(
                parse_u32(payload)
                    .context(format!("invalid NHA_MASTER value"))?,
            ),
            NHA_FDB => Self::Fdb,
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid link NLA value (unknown type)")?,
            ),
        })
    }
}
