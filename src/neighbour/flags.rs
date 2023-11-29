// SPDX-License-Identifier: MIT

const NTF_USE: u8 = 1 << 0;
const NTF_SELF: u8 = 1 << 1;
// Kernel constant name is NTF_MASTER
const NTF_CONTROLLER: u8 = 1 << 2;
const NTF_PROXY: u8 = 1 << 3;
const NTF_EXT_LEARNED: u8 = 1 << 4;
const NTF_OFFLOADED: u8 = 1 << 5;
const NTF_STICKY: u8 = 1 << 6;
const NTF_ROUTER: u8 = 1 << 7;

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
pub enum NeighbourFlag {
    Use,
    // Hold NTF_SELF as Self is not rust reserved keyword
    Own,
    Controller,
    Proxy,
    ExtLearned,
    Offloaded,
    Sticky,
    Router,
    // No Other required as these are all 8 bits.
}

const ALL_RULE_FLAGS: [NeighbourFlag; 8] = [
    NeighbourFlag::Use,
    NeighbourFlag::Own,
    NeighbourFlag::Controller,
    NeighbourFlag::Proxy,
    NeighbourFlag::ExtLearned,
    NeighbourFlag::Offloaded,
    NeighbourFlag::Sticky,
    NeighbourFlag::Router,
];

impl From<NeighbourFlag> for u8 {
    fn from(v: NeighbourFlag) -> u8 {
        match v {
            NeighbourFlag::Use => NTF_USE,
            NeighbourFlag::Own => NTF_SELF,
            NeighbourFlag::Controller => NTF_CONTROLLER,
            NeighbourFlag::Proxy => NTF_PROXY,
            NeighbourFlag::ExtLearned => NTF_EXT_LEARNED,
            NeighbourFlag::Offloaded => NTF_OFFLOADED,
            NeighbourFlag::Sticky => NTF_STICKY,
            NeighbourFlag::Router => NTF_ROUTER,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub(crate) struct VecNeighbourFlag(pub(crate) Vec<NeighbourFlag>);

impl From<u8> for VecNeighbourFlag {
    fn from(d: u8) -> Self {
        let mut ret = Vec::new();
        for flag in ALL_RULE_FLAGS {
            if (d & (u8::from(flag))) > 0 {
                ret.push(flag);
            }
        }
        Self(ret)
    }
}

impl From<&VecNeighbourFlag> for u8 {
    fn from(v: &VecNeighbourFlag) -> u8 {
        let mut d: u8 = 0;
        for flag in &v.0 {
            d += u8::from(*flag);
        }
        d
    }
}
