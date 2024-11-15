// SPDX-License-Identifier: MIT

const RTNH_F_DEAD: u32 = 1 << 0;
const RTNH_F_PERVASIVE: u32 = 1 << 1;
const RTNH_F_ONLINK: u32 = 1 << 2;
const RTNH_F_OFFLOAD: u32 = 1 << 3;
const RTNH_F_LINKDOWN: u32 = 1 << 4;
const RTNH_F_UNRESOLVED: u32 = 1 << 5;
const RTNH_F_TRAP: u32 = 1 << 6;
// const RTNH_COMPARE_MASK: u32 =
//     RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_OFFLOAD | RTNH_F_TRAP;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct NexthopFlags: u32 {
        const Dead = RTNH_F_DEAD;
        const Pervasive = RTNH_F_PERVASIVE;
        const Onlink = RTNH_F_ONLINK;
        const Offload  = RTNH_F_OFFLOAD;
        const Linkdown = RTNH_F_LINKDOWN;
        const Unresolved = RTNH_F_UNRESOLVED;
        const Trap= RTNH_F_TRAP;
        const _ = !0;
    }
}
