// SPDX-License-Identifier: MIT

use super::common::*;

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
        const Controller = IFF_CONTROLLER;
        const Port = IFF_PORT;
        const Multicast = IFF_MULTICAST;
        const Portsel = IFF_PORTSEL;
        const Automedia = IFF_AUTOMEDIA;
        const Dynamic = IFF_DYNAMIC;
        const LowerUp = IFF_LOWER_UP;
        const Dormant = IFF_DORMANT;
        const Echo = IFF_ECHO;
        const _ = !0;
    }
}
