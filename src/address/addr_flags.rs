// SPDX-License-Identifier: MIT

const IFA_F_SECONDARY: u32 = 0x01;
const IFA_F_NODAD: u32 = 0x02;
const IFA_F_OPTIMISTIC: u32 = 0x04;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_HOMEADDRESS: u32 = 0x10;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_F_MANAGETEMPADDR: u32 = 0x100;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;
const IFA_F_MCAUTOJOIN: u32 = 0x400;
const IFA_F_STABLE_PRIVACY: u32 = 0x800;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
pub enum AddressFlag {
    Secondary,
    Nodad,
    Optimistic,
    Dadfailed,
    Homeaddress,
    Deprecated,
    Tentative,
    Permanent,
    Managetempaddr,
    Noprefixroute,
    Mcautojoin,
    StablePrivacy,
    Other(u32),
}

impl From<u32> for AddressFlag {
    fn from(d: u32) -> Self {
        match d {
            IFA_F_SECONDARY => Self::Secondary,
            IFA_F_NODAD => Self::Nodad,
            IFA_F_OPTIMISTIC => Self::Optimistic,
            IFA_F_DADFAILED => Self::Dadfailed,
            IFA_F_HOMEADDRESS => Self::Homeaddress,
            IFA_F_DEPRECATED => Self::Deprecated,
            IFA_F_TENTATIVE => Self::Tentative,
            IFA_F_PERMANENT => Self::Permanent,
            IFA_F_MANAGETEMPADDR => Self::Managetempaddr,
            IFA_F_NOPREFIXROUTE => Self::Noprefixroute,
            IFA_F_MCAUTOJOIN => Self::Mcautojoin,
            IFA_F_STABLE_PRIVACY => Self::StablePrivacy,
            _ => Self::Other(d),
        }
    }
}

impl From<AddressFlag> for u32 {
    fn from(v: AddressFlag) -> u32 {
        match v {
            AddressFlag::Secondary => IFA_F_SECONDARY,
            AddressFlag::Nodad => IFA_F_NODAD,
            AddressFlag::Optimistic => IFA_F_OPTIMISTIC,
            AddressFlag::Dadfailed => IFA_F_DADFAILED,
            AddressFlag::Homeaddress => IFA_F_HOMEADDRESS,
            AddressFlag::Deprecated => IFA_F_DEPRECATED,
            AddressFlag::Tentative => IFA_F_TENTATIVE,
            AddressFlag::Permanent => IFA_F_PERMANENT,
            AddressFlag::Managetempaddr => IFA_F_MANAGETEMPADDR,
            AddressFlag::Noprefixroute => IFA_F_NOPREFIXROUTE,
            AddressFlag::Mcautojoin => IFA_F_MCAUTOJOIN,
            AddressFlag::StablePrivacy => IFA_F_STABLE_PRIVACY,
            AddressFlag::Other(d) => d,
        }
    }
}

const ALL_ADDR_FLAGS: [AddressFlag; 12] = [
    AddressFlag::Secondary,
    AddressFlag::Nodad,
    AddressFlag::Optimistic,
    AddressFlag::Dadfailed,
    AddressFlag::Homeaddress,
    AddressFlag::Deprecated,
    AddressFlag::Tentative,
    AddressFlag::Permanent,
    AddressFlag::Managetempaddr,
    AddressFlag::Noprefixroute,
    AddressFlag::Mcautojoin,
    AddressFlag::StablePrivacy,
];

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AddressFlags(pub(crate) Vec<AddressFlag>);

impl From<u32> for AddressFlags {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_ADDR_FLAGS {
            if (d & u32::from(flag)) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            log::warn!("Discarded unsupported IFA_F_: {}", d - got);
        }
        Self(ret)
    }
}

impl From<&AddressFlags> for u32 {
    fn from(v: &AddressFlags) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
#[repr(u8)]
/// [AddressHeaderFlag] is only used for [super::AddressHeader] and holding
/// subset(first byte) of [AddressFlag].
pub enum AddressHeaderFlag {
    Secondary,
    Nodad,
    Optimistic,
    Dadfailed,
    Homeaddress,
    Deprecated,
    Tentative,
    Permanent,
    Other(u8),
}

impl From<u8> for AddressHeaderFlag {
    fn from(d: u8) -> Self {
        match d {
            d if d == IFA_F_SECONDARY as u8 => Self::Secondary,
            d if d == IFA_F_NODAD as u8 => Self::Nodad,
            d if d == IFA_F_OPTIMISTIC as u8 => Self::Optimistic,
            d if d == IFA_F_DADFAILED as u8 => Self::Dadfailed,
            d if d == IFA_F_HOMEADDRESS as u8 => Self::Homeaddress,
            d if d == IFA_F_DEPRECATED as u8 => Self::Deprecated,
            d if d == IFA_F_TENTATIVE as u8 => Self::Tentative,
            d if d == IFA_F_PERMANENT as u8 => Self::Permanent,
            _ => Self::Other(d),
        }
    }
}

impl From<AddressHeaderFlag> for u8 {
    fn from(v: AddressHeaderFlag) -> u8 {
        match v {
            AddressHeaderFlag::Secondary => IFA_F_SECONDARY as u8,
            AddressHeaderFlag::Nodad => IFA_F_NODAD as u8,
            AddressHeaderFlag::Optimistic => IFA_F_OPTIMISTIC as u8,
            AddressHeaderFlag::Dadfailed => IFA_F_DADFAILED as u8,
            AddressHeaderFlag::Homeaddress => IFA_F_HOMEADDRESS as u8,
            AddressHeaderFlag::Deprecated => IFA_F_DEPRECATED as u8,
            AddressHeaderFlag::Tentative => IFA_F_TENTATIVE as u8,
            AddressHeaderFlag::Permanent => IFA_F_PERMANENT as u8,
            AddressHeaderFlag::Other(d) => d,
        }
    }
}

const ALL_HDR_ADDR_FLAGS: [AddressHeaderFlag; 8] = [
    AddressHeaderFlag::Secondary,
    AddressHeaderFlag::Nodad,
    AddressHeaderFlag::Optimistic,
    AddressHeaderFlag::Dadfailed,
    AddressHeaderFlag::Homeaddress,
    AddressHeaderFlag::Deprecated,
    AddressHeaderFlag::Tentative,
    AddressHeaderFlag::Permanent,
];

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AddressHeaderFlags(pub(crate) Vec<AddressHeaderFlag>);

impl From<u8> for AddressHeaderFlags {
    fn from(d: u8) -> Self {
        let mut got: u8 = 0;
        let mut ret = Vec::new();
        for flag in ALL_HDR_ADDR_FLAGS {
            if (d & u8::from(flag)) > 0 {
                ret.push(flag);
                got += u8::from(flag);
            }
        }
        if got != d {
            log::warn!("Discarded unsupported IFA_F_: {}", d - got);
        }
        Self(ret)
    }
}

impl From<&AddressHeaderFlags> for u8 {
    fn from(v: &AddressHeaderFlags) -> u8 {
        let mut d: u8 = 0;
        for flag in &v.0 {
            d += u8::from(*flag);
        }
        d
    }
}
