// SPDX-License-Identifier: MIT

const IFF_UP: u32 = 1 << 0;
const IFF_BROADCAST: u32 = 1 << 1;
const IFF_DEBUG: u32 = 1 << 2;
const IFF_LOOPBACK: u32 = 1 << 3;
const IFF_POINTOPOINT: u32 = 1 << 4;
const IFF_NOTRAILERS: u32 = 1 << 5;
const IFF_RUNNING: u32 = 1 << 6;
const IFF_NOARP: u32 = 1 << 7;
const IFF_PROMISC: u32 = 1 << 8;
const IFF_ALLMULTI: u32 = 1 << 9;
// Kernel constant name is IFF_MASTER
const IFF_CONTROLLER: u32 = 1 << 10;
// Kernel constant name is IFF_SLAVE
const IFF_PORT: u32 = 1 << 11;
const IFF_MULTICAST: u32 = 1 << 12;
const IFF_PORTSEL: u32 = 1 << 13;
const IFF_AUTOMEDIA: u32 = 1 << 14;
const IFF_DYNAMIC: u32 = 1 << 15;
const IFF_LOWER_UP: u32 = 1 << 16;
const IFF_DORMANT: u32 = 1 << 17;
const IFF_ECHO: u32 = 1 << 18;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct VecLinkFlag(pub Vec<LinkFlag>);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[repr(u32)]
pub enum LinkFlag {
    Up = IFF_UP,
    Broadcast = IFF_BROADCAST,
    Debug = IFF_DEBUG,
    Loopback = IFF_LOOPBACK,
    Pointopoint = IFF_POINTOPOINT,
    Notrailers = IFF_NOTRAILERS,
    Running = IFF_RUNNING,
    Noarp = IFF_NOARP,
    Promisc = IFF_PROMISC,
    Allmulti = IFF_ALLMULTI,
    Controller = IFF_CONTROLLER,
    Port = IFF_PORT,
    Multicast = IFF_MULTICAST,
    Portsel = IFF_PORTSEL,
    Automedia = IFF_AUTOMEDIA,
    Dynamic = IFF_DYNAMIC,
    LowerUp = IFF_LOWER_UP,
    Dormant = IFF_DORMANT,
    Echo = IFF_ECHO,
    Other(u32),
}

impl From<u32> for LinkFlag {
    fn from(d: u32) -> Self {
        match d {
            d if (d & IFF_UP) > 0 => Self::Up,
            d if (d & IFF_BROADCAST) > 0 => Self::Broadcast,
            d if (d & IFF_DEBUG) > 0 => Self::Debug,
            d if (d & IFF_LOOPBACK) > 0 => Self::Loopback,
            d if (d & IFF_POINTOPOINT) > 0 => Self::Pointopoint,
            d if (d & IFF_NOTRAILERS) > 0 => Self::Notrailers,
            d if (d & IFF_RUNNING) > 0 => Self::Running,
            d if (d & IFF_NOARP) > 0 => Self::Noarp,
            d if (d & IFF_PROMISC) > 0 => Self::Promisc,
            d if (d & IFF_ALLMULTI) > 0 => Self::Allmulti,
            d if (d & IFF_CONTROLLER) > 0 => Self::Controller,
            d if (d & IFF_PORT) > 0 => Self::Port,
            d if (d & IFF_MULTICAST) > 0 => Self::Multicast,
            d if (d & IFF_PORTSEL) > 0 => Self::Portsel,
            d if (d & IFF_AUTOMEDIA) > 0 => Self::Automedia,
            d if (d & IFF_DYNAMIC) > 0 => Self::Dynamic,
            d if (d & IFF_LOWER_UP) > 0 => Self::LowerUp,
            d if (d & IFF_DORMANT) > 0 => Self::Dormant,
            d if (d & IFF_ECHO) > 0 => Self::Echo,
            _ => Self::Other(d),
        }
    }
}

impl From<LinkFlag> for u32 {
    fn from(v: LinkFlag) -> u32 {
        match v {
            LinkFlag::Up => IFF_UP,
            LinkFlag::Broadcast => IFF_BROADCAST,
            LinkFlag::Debug => IFF_DEBUG,
            LinkFlag::Loopback => IFF_LOOPBACK,
            LinkFlag::Pointopoint => IFF_POINTOPOINT,
            LinkFlag::Notrailers => IFF_NOTRAILERS,
            LinkFlag::Running => IFF_RUNNING,
            LinkFlag::Noarp => IFF_NOARP,
            LinkFlag::Promisc => IFF_PROMISC,
            LinkFlag::Allmulti => IFF_ALLMULTI,
            LinkFlag::Controller => IFF_CONTROLLER,
            LinkFlag::Port => IFF_PORT,
            LinkFlag::Multicast => IFF_MULTICAST,
            LinkFlag::Portsel => IFF_PORTSEL,
            LinkFlag::Automedia => IFF_AUTOMEDIA,
            LinkFlag::Dynamic => IFF_DYNAMIC,
            LinkFlag::LowerUp => IFF_LOWER_UP,
            LinkFlag::Dormant => IFF_DORMANT,
            LinkFlag::Echo => IFF_ECHO,
            LinkFlag::Other(i) => i,
        }
    }
}

impl std::fmt::Display for LinkFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Up => write!(f, "UP"),
            Self::Broadcast => write!(f, "BROADCAST"),
            Self::Debug => write!(f, "DEBUG"),
            Self::Loopback => write!(f, "LOOPBACK"),
            Self::Pointopoint => write!(f, "POINTOPOINT"),
            Self::Notrailers => write!(f, "NOTRAILERS"),
            Self::Running => write!(f, "RUNNING"),
            Self::Noarp => write!(f, "NOARP"),
            Self::Promisc => write!(f, "PROMISC"),
            Self::Allmulti => write!(f, "ALLMULTI"),
            Self::Controller => write!(f, "CONTROLLER"),
            Self::Port => write!(f, "PORT"),
            Self::Multicast => write!(f, "MULTICAST"),
            Self::Portsel => write!(f, "PORTSEL"),
            Self::Automedia => write!(f, "AUTOMEDIA"),
            Self::Dynamic => write!(f, "DYNAMIC"),
            Self::LowerUp => write!(f, "LOWER_UP"),
            Self::Dormant => write!(f, "DORMANT"),
            Self::Echo => write!(f, "ECHO"),
            Self::Other(i) => write!(f, "Other({})", i),
        }
    }
}

// Please sort this list.
const ALL_LINK_FLAGS: [LinkFlag; 19] = [
    LinkFlag::Allmulti,
    LinkFlag::Automedia,
    LinkFlag::Broadcast,
    LinkFlag::Controller,
    LinkFlag::Debug,
    LinkFlag::Dormant,
    LinkFlag::Dynamic,
    LinkFlag::Echo,
    LinkFlag::Loopback,
    LinkFlag::LowerUp,
    LinkFlag::Multicast,
    LinkFlag::Noarp,
    LinkFlag::Notrailers,
    LinkFlag::Pointopoint,
    LinkFlag::Port,
    LinkFlag::Portsel,
    LinkFlag::Promisc,
    LinkFlag::Running,
    LinkFlag::Up,
];

impl From<u32> for VecLinkFlag {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_LINK_FLAGS {
            if (d & u32::from(flag)) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            ret.push(LinkFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&VecLinkFlag> for u32 {
    fn from(v: &VecLinkFlag) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}
