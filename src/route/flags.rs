// SPDX-License-Identifier: MIT

use super::next_hops::{
    RTNH_F_DEAD, RTNH_F_LINKDOWN, RTNH_F_OFFLOAD, RTNH_F_ONLINK,
    RTNH_F_PERVASIVE, RTNH_F_TRAP, RTNH_F_UNRESOLVED,
};

const RTM_F_NOTIFY: u32 = 0x100;
const RTM_F_CLONED: u32 = 0x200;
const RTM_F_EQUALIZE: u32 = 0x400;
const RTM_F_PREFIX: u32 = 0x800;
const RTM_F_LOOKUP_TABLE: u32 = 0x1000;
const RTM_F_FIB_MATCH: u32 = 0x2000;
const RTM_F_OFFLOAD: u32 = 0x4000;
const RTM_F_TRAP: u32 = 0x8000;
const RTM_F_OFFLOAD_FAILED: u32 = 0x20000000;

/// Flags that can be set in a `RTM_GETROUTE`
/// ([`RouteNetlinkMessage::GetRoute`]) message.
#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
pub enum RouteFlag {
    // Kernel also store next hope flags here
    Dead,
    Pervasive,
    Onlink,
    Offload,
    Linkdown,
    Unresolved,
    Trap,
    // Next hope flags ends
    Notify,
    Cloned,
    Equalize,
    Prefix,
    LookupTable,
    FibMatch,
    RtOffload,
    RtTrap,
    OffloadFailed,
    Other(u32),
}

const ALL_ROUTE_FLAGS: [RouteFlag; 16] = [
    RouteFlag::Dead,
    RouteFlag::Pervasive,
    RouteFlag::Onlink,
    RouteFlag::Offload,
    RouteFlag::Linkdown,
    RouteFlag::Unresolved,
    RouteFlag::Trap,
    RouteFlag::Notify,
    RouteFlag::Cloned,
    RouteFlag::Equalize,
    RouteFlag::Prefix,
    RouteFlag::LookupTable,
    RouteFlag::FibMatch,
    RouteFlag::RtOffload,
    RouteFlag::RtTrap,
    RouteFlag::OffloadFailed,
];

impl From<RouteFlag> for u32 {
    fn from(v: RouteFlag) -> u32 {
        match v {
            RouteFlag::Dead => RTNH_F_DEAD.into(),
            RouteFlag::Pervasive => RTNH_F_PERVASIVE.into(),
            RouteFlag::Onlink => RTNH_F_ONLINK.into(),
            RouteFlag::Offload => RTNH_F_OFFLOAD.into(),
            RouteFlag::Linkdown => RTNH_F_LINKDOWN.into(),
            RouteFlag::Unresolved => RTNH_F_UNRESOLVED.into(),
            RouteFlag::Trap => RTNH_F_TRAP.into(),

            RouteFlag::Notify => RTM_F_NOTIFY,
            RouteFlag::Cloned => RTM_F_CLONED,
            RouteFlag::Equalize => RTM_F_EQUALIZE,
            RouteFlag::Prefix => RTM_F_PREFIX,
            RouteFlag::LookupTable => RTM_F_LOOKUP_TABLE,
            RouteFlag::FibMatch => RTM_F_FIB_MATCH,
            RouteFlag::RtOffload => RTM_F_OFFLOAD,
            RouteFlag::RtTrap => RTM_F_TRAP,
            RouteFlag::OffloadFailed => RTM_F_OFFLOAD_FAILED,
            RouteFlag::Other(i) => i,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub(crate) struct VecRouteFlag(pub(crate) Vec<RouteFlag>);

impl From<u32> for VecRouteFlag {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_ROUTE_FLAGS {
            if (d & (u32::from(flag))) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            ret.push(RouteFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&VecRouteFlag> for u32 {
    fn from(v: &VecRouteFlag) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}
