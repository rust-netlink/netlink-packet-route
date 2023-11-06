// SPDX-License-Identifier: MIT

const IF_RA_OTHERCONF: u32 = 0x80;
const IF_RA_MANAGED: u32 = 0x40;
const IF_RA_RCVD: u32 = 0x20;
const IF_RS_SENT: u32 = 0x10;
const IF_READY: u32 = 0x80000000;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Inet6IfaceFlags(pub Vec<Inet6IfaceFlag>);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[repr(u32)]
pub enum Inet6IfaceFlag {
    Otherconf = IF_RA_OTHERCONF,
    RaManaged = IF_RA_MANAGED,
    RaRcvd = IF_RA_RCVD,
    RsSent = IF_RS_SENT,
    Ready = IF_READY,
    Other(u32),
}

impl From<u32> for Inet6IfaceFlag {
    fn from(d: u32) -> Self {
        match d {
            d if (d & IF_RA_OTHERCONF) > 0 => Self::Otherconf,
            d if (d & IF_RA_MANAGED) > 0 => Self::RaManaged,
            d if (d & IF_RA_RCVD) > 0 => Self::RaRcvd,
            d if (d & IF_RS_SENT) > 0 => Self::RsSent,
            d if (d & IF_READY) > 0 => Self::Ready,
            _ => Self::Other(d),
        }
    }
}

impl From<Inet6IfaceFlag> for u32 {
    fn from(v: Inet6IfaceFlag) -> u32 {
        match v {
            Inet6IfaceFlag::Otherconf => IF_RA_OTHERCONF,
            Inet6IfaceFlag::RaManaged => IF_RA_MANAGED,
            Inet6IfaceFlag::RaRcvd => IF_RA_RCVD,
            Inet6IfaceFlag::RsSent => IF_RS_SENT,
            Inet6IfaceFlag::Ready => IF_READY,
            Inet6IfaceFlag::Other(i) => i,
        }
    }
}

impl std::fmt::Display for Inet6IfaceFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Otherconf => write!(f, "OTHERCONF"),
            Self::RaManaged => write!(f, "RA_MANAGED"),
            Self::RaRcvd => write!(f, "RA_RCVD"),
            Self::RsSent => write!(f, "RS_SENT"),
            Self::Ready => write!(f, "READY"),
            Self::Other(i) => write!(f, "Other({})", i),
        }
    }
}

const ALL_INET_IFACE_FLAGS: [Inet6IfaceFlag; 5] = [
    Inet6IfaceFlag::Otherconf,
    Inet6IfaceFlag::RaManaged,
    Inet6IfaceFlag::RaRcvd,
    Inet6IfaceFlag::RsSent,
    Inet6IfaceFlag::Ready,
];

impl From<u32> for Inet6IfaceFlags {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_INET_IFACE_FLAGS {
            if (d & u32::from(flag)) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            ret.push(Inet6IfaceFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&Inet6IfaceFlags> for u32 {
    fn from(v: &Inet6IfaceFlags) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}
