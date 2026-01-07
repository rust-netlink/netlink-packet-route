// SPDX-License-Identifier: MIT

use super::common::*;

const IFF_DRV_OACTIVE: u32 = 1 << 10;
const IFF_SIMPLEX: u32 = 1 << 11;
// IFF_LINK0 to IFF_LINK2's meaning is link-layer specific
const IFF_LINK0: u32 = 1 << 12;
const IFF_LINK1: u32 = 1 << 13;
const IFF_LINK2: u32 = 1 << 14;
const IFF_MULTICAST: u32 = 1 << 15;
const IFF_CANTCONFIG: u32 = 1 << 16;
const IFF_PPROMISC: u32 = 1 << 17;
const IFF_MONITOR: u32 = 1 << 18;
const IFF_STATICARP: u32 = 1 << 19;
const IFF_STICKYARP: u32 = 1 << 20;
const IFF_DYING: u32 = 1 << 21;
const IFF_RENAMING: u32 = 1 << 22;
const IFF_PALLMULTI: u32 = 1 << 23;
const IFF_NETLINK_1: u32 = 1 << 24;
// Defined in `<netlink/route/interface.h>`
const IFF_LOWER_UP: u32 = IFF_NETLINK_1;

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
    #[non_exhaustive]
    pub struct LinkFlags: u32 {
        const Up = IFF_UP;
        const Broadcast = IFF_BROADCAST;
        const Debug = IFF_DEBUG;
        const Loopback = IFF_LOOPBACK;
        const Pointopoint = IFF_POINTOPOINT;
        const Notrailers = IFF_NOTRAILERS;
        const Running = IFF_RUNNING;
        const Noarp = IFF_NOARP;
        const Promisc = IFF_PROMISC;
        const Allmulti = IFF_ALLMULTI;
        const OActive = IFF_DRV_OACTIVE;
        const Simplex = IFF_SIMPLEX;
        const Link0 = IFF_LINK0;
        const Link1 = IFF_LINK1;
        const Link2 = IFF_LINK2;
        const Multicast = IFF_MULTICAST;
        const Cantconfig = IFF_CANTCONFIG;
        const Ppromisc = IFF_PPROMISC;
        const Monitor = IFF_MONITOR;
        const Staticarp = IFF_STATICARP;
        const Stickyarp = IFF_STICKYARP;
        const Dying = IFF_DYING;
        const Renaming = IFF_RENAMING;
        const Pallmulti = IFF_PALLMULTI;
        const LowerUp = IFF_LOWER_UP;
        const _ = !0;
    }
}
