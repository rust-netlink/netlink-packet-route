// SPDX-License-Identifier: MIT

// Route Usable
const RTF_UP: u32 = 0x1;
// Destination is a Gateway
const RTF_GATEWAY: u32 = 0x2;
// Host Entry (net otherwise)
const RTF_HOST: u32 = 0x4;
// Host or Net Unreachable
const RTF_REJECT: u32 = 0x8;
// Route Created Dynamically (by redirect)
const RTF_DYNAMIC: u32 = 0x10;
// Route Modified Dynamically (by redirect)
const RTF_MODIFIED: u32 = 0x20;
// Message Confirmed
const RTF_DONE: u32 = 0x40;
// External Daemon Resolves Name
const RTF_XRESOLVE: u32 = 0x200;
// DEPRECATED - Exists ONLY for Backward Compatibility
// const RTF_LLINFO: u32 = 0x400;
// Used by Apps to Add/Del L2 Entries
const RTF_LLDATA: u32 = 0x400;
// Manually Added
const RTF_STATIC: u32 = 0x800;
// Just Discard Pkts (during updates)
const RTF_BLACKHOLE: u32 = 0x1000;
// Protocol Specific Routing Flag
const RTF_PROTO2: u32 = 0x4000;
const RTF_PROTO1: u32 = 0x8000;
const RTF_PROTO3: u32 = 0x40000;
// MTU was Explicitly Specified
const RTF_FIXEDMTU: u32 = 0x80000;
// Route is Immutable
const RTF_PINNED: u32 = 0x100000;
// Route Represents a Local Address
const RTF_LOCAL: u32 = 0x200000;
// Route Represents a Bcast Address
const RTF_BROADCAST: u32 = 0x400000;
// Route Represents a Mcast Address
const RTF_MULTICAST: u32 = 0x800000;
// Always Route Dst->Src
const RTF_STICKY: u32 = 0x10000000;
// A Compatibility Bit for Interacting with Existing Routing Apps
const RTF_GWFLAG_COMPAT: u32 = 0x80000000;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RtFlags : u32 {
        const Up = RTF_UP;
        const Gateway = RTF_GATEWAY;
        const Host = RTF_HOST;
        const Reject = RTF_REJECT;
        const Dynamic = RTF_DYNAMIC;
        const Modified = RTF_MODIFIED;
        const Done = RTF_DONE;
        const Xresolve = RTF_XRESOLVE;
        const Lldata = RTF_LLDATA;
        const Static = RTF_STATIC;
        const Blackhole = RTF_BLACKHOLE;
        const Proto1 = RTF_PROTO1;
        const Proto2 = RTF_PROTO2;
        const Proto3 = RTF_PROTO3;
        const FixedMtu = RTF_FIXEDMTU;
        const Pinned = RTF_PINNED;
        const Local = RTF_LOCAL;
        const Broadcast = RTF_BROADCAST;
        const Multicast = RTF_MULTICAST;
        const Sticky = RTF_STICKY;
        const GwflagCompat = RTF_GWFLAG_COMPAT;
        const _ = !0;
    }
}
