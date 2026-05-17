// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, Nla, Parseable, ParseableParametrized,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NexthopAttribute {
    Id(u32),
    Group(Vec<NexthopGroupEntry>),
    GroupType(u16),
    Blackhole,
    Oif(u32),
    Gateway(Vec<u8>), // Can be IPv4 or IPv6
    EncapType(u16),
    Encap(Vec<u8>),    // TODO: Parse encap attributes properly
    Fdb(Vec<u8>),      // TODO: Parse FDB
    ResGroup(Vec<u8>), // TODO: Parse ResGroup
    Other(u16, Vec<u8>),
}

impl Nla for NexthopAttribute {
    fn value_len(&self) -> usize {
        use self::NexthopAttribute::*;
        match self {
            Id(_) => 4,
            Group(entries) => entries.len() * 8, // Each entry is 8 bytes
            GroupType(_) => 2,
            Blackhole => 0,
            Oif(_) => 4,
            Gateway(bytes) => bytes.len(),
            EncapType(_) => 2,
            Encap(bytes) => bytes.len(),
            Fdb(bytes) => bytes.len(),
            ResGroup(bytes) => bytes.len(),
            Other(_, bytes) => bytes.len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::NexthopAttribute::*;
        match self {
            | Id(value)
            | Oif(value)
                => buffer[0..4].copy_from_slice(&value.to_ne_bytes()),

            | GroupType(value)
            | EncapType(value)
                => buffer[0..2].copy_from_slice(&value.to_ne_bytes()),

            Group(entries) => {
                for (i, entry) in entries.iter().enumerate() {
                    entry.emit(&mut buffer[i * 8..]);
                }
            }
            Blackhole => {},
            Gateway(bytes)
            | Encap(bytes)
            | Fdb(bytes)
            | ResGroup(bytes)
            | Other(_, bytes)
                => buffer.copy_from_slice(bytes),
        }
    }

    fn kind(&self) -> u16 {
        use self::NexthopAttribute::*;
        match self {
            Id(_) => NHA_ID,
            Group(_) => NHA_GROUP,
            GroupType(_) => NHA_GROUP_TYPE,
            Blackhole => NHA_BLACKHOLE,
            Oif(_) => NHA_OIF,
            Gateway(_) => NHA_GATEWAY,
            EncapType(_) => NHA_ENCAP_TYPE,
            Encap(_) => NHA_ENCAP,
            Fdb(_) => NHA_FDB,
            ResGroup(_) => NHA_RES_GROUP,
            Other(kind, _) => *kind,
        }
    }
}

pub struct NexthopAttributeType;

impl NexthopAttributeType {
    pub const ID: u16 = NHA_ID;
    pub const GROUP: u16 = NHA_GROUP;
    pub const GROUP_TYPE: u16 = NHA_GROUP_TYPE;
    pub const BLACKHOLE: u16 = NHA_BLACKHOLE;
    pub const OIF: u16 = NHA_OIF;
    pub const GATEWAY: u16 = NHA_GATEWAY;
    pub const ENCAP_TYPE: u16 = NHA_ENCAP_TYPE;
    pub const ENCAP: u16 = NHA_ENCAP;
    pub const FDB: u16 = NHA_FDB;
    pub const RES_GROUP: u16 = NHA_RES_GROUP;
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<(&'a T, u16), ()>
    for NexthopAttribute
{
    fn parse_with_param(
        input: &(&'a T, u16),
        _params: (),
    ) -> Result<Self, DecodeError> {
        let (payload, kind) = input;
        let payload = payload.as_ref();

        Ok(match *kind {
            NHA_ID => {
                if payload.len() != 4 {
                    return Err(DecodeError::from("Invalid NHA_ID length"));
                }
                NexthopAttribute::Id(u32::from_ne_bytes(
                    payload.try_into().map_err(|_| {
                        DecodeError::from("Invalid NHA_ID length")
                    })?,
                ))
            }
            NHA_GROUP => {
                if payload.len() % 8 != 0 {
                    return Err(DecodeError::from("Invalid NHA_GROUP length"));
                }
                let mut entries = Vec::new();
                for chunk in payload.chunks(8) {
                    if let Ok(entry) = NexthopGroupEntry::parse(&chunk) {
                        entries.push(entry);
                    } else {
                        return Err(DecodeError::from(
                            "Failed to parse group entry",
                        ));
                    }
                }
                NexthopAttribute::Group(entries)
            }
            NHA_GROUP_TYPE => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "Invalid NHA_GROUP_TYPE length",
                    ));
                }
                NexthopAttribute::GroupType(u16::from_ne_bytes(
                    payload.try_into().map_err(|_| {
                        DecodeError::from("Invalid NHA_GROUP_TYPE length")
                    })?,
                ))
            }
            NHA_BLACKHOLE => NexthopAttribute::Blackhole,
            NHA_OIF => {
                if payload.len() != 4 {
                    return Err(DecodeError::from("Invalid NHA_OIF length"));
                }
                NexthopAttribute::Oif(u32::from_ne_bytes(
                    payload.try_into().map_err(|_| {
                        DecodeError::from("Invalid NHA_OIF length")
                    })?,
                ))
            }
            NHA_GATEWAY => NexthopAttribute::Gateway(payload.to_vec()),
            NHA_ENCAP_TYPE => {
                if payload.len() != 2 {
                    return Err(DecodeError::from(
                        "Invalid NHA_ENCAP_TYPE length",
                    ));
                }
                NexthopAttribute::EncapType(u16::from_ne_bytes(
                    payload.try_into().map_err(|_| {
                        DecodeError::from("Invalid NHA_ENCAP_TYPE length")
                    })?,
                ))
            }
            NHA_ENCAP => NexthopAttribute::Encap(payload.to_vec()),
            NHA_FDB => NexthopAttribute::Fdb(payload.to_vec()),
            NHA_RES_GROUP => NexthopAttribute::ResGroup(payload.to_vec()),
            _ => NexthopAttribute::Other(*kind, payload.to_vec()),
        })
    }
}

// Constants
const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_GROUP_TYPE: u16 = 3;
const NHA_BLACKHOLE: u16 = 4;
const NHA_OIF: u16 = 5;
const NHA_GATEWAY: u16 = 6;
const NHA_ENCAP_TYPE: u16 = 7;
const NHA_ENCAP: u16 = 8;
// const NHA_GROUPS: u16 = 9; // Not implementing NHA_GROUPS as it seems deprecated or complex
// const NHA_MASTER: u16 = 10;
const NHA_FDB: u16 = 11;
const NHA_RES_GROUP: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NexthopGroupEntry {
    pub id: u32,
    pub weight: u8,
    pub resvd1: u8,
    pub resvd2: u16,
}

impl Emitable for NexthopGroupEntry {
    fn buffer_len(&self) -> usize {
        8
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0..4].copy_from_slice(&self.id.to_ne_bytes());
        buffer[4] = self.weight;
        buffer[5] = self.resvd1;
        buffer[6..8].copy_from_slice(&self.resvd2.to_ne_bytes());
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<T> for NexthopGroupEntry {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let buf = buf.as_ref();
        if buf.len() < 8 {
            return Err(DecodeError::from("Invalid NexthopGroupEntry length"));
        }
        Ok(NexthopGroupEntry {
            id: u32::from_ne_bytes(buf[0..4].try_into().unwrap()),
            weight: buf[4],
            resvd1: buf[5],
            resvd2: u16::from_ne_bytes(buf[6..8].try_into().unwrap()),
        })
    }
}
