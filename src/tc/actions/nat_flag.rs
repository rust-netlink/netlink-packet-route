// SPDX-License-Identifier: MIT

const TCA_NAT_FLAG_EGRESS: u32 = 1;
const TCA_ACT_FLAGS_USER_BITS: u32 = 16;
const TCA_ACT_FLAGS_POLICE: u32 = 1u32 << TCA_ACT_FLAGS_USER_BITS;
const TCA_ACT_FLAGS_BIND: u32 = 1u32 << (TCA_ACT_FLAGS_USER_BITS + 1);
const TCA_ACT_FLAGS_REPLACE: u32 = 1u32 << (TCA_ACT_FLAGS_USER_BITS + 2);
const TCA_ACT_FLAGS_NO_RTNL: u32 = 1u32 << (TCA_ACT_FLAGS_USER_BITS + 3);
const TCA_ACT_FLAGS_AT_INGRESS: u32 = 1u32 << (TCA_ACT_FLAGS_USER_BITS + 4);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum TcNatFlag {
    Egress,
    Police,
    Bind,
    Replace,
    NoRtnl,
    AtIngress,
    Other(u32),
}

impl From<TcNatFlag> for u32 {
    fn from(v: TcNatFlag) -> u32 {
        match v {
            TcNatFlag::Egress => TCA_NAT_FLAG_EGRESS,
            TcNatFlag::Police => TCA_ACT_FLAGS_POLICE,
            TcNatFlag::Bind => TCA_ACT_FLAGS_BIND,
            TcNatFlag::Replace => TCA_ACT_FLAGS_REPLACE,
            TcNatFlag::NoRtnl => TCA_ACT_FLAGS_NO_RTNL,
            TcNatFlag::AtIngress => TCA_ACT_FLAGS_AT_INGRESS,
            TcNatFlag::Other(i) => i,
        }
    }
}

const ALL_NAT_FLAGS: [TcNatFlag; 6] = [
    TcNatFlag::Egress,
    TcNatFlag::Police,
    TcNatFlag::Bind,
    TcNatFlag::Replace,
    TcNatFlag::NoRtnl,
    TcNatFlag::AtIngress,
];

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct VecTcNatFlag(pub(crate) Vec<TcNatFlag>);

impl From<u32> for VecTcNatFlag {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_NAT_FLAGS {
            if (d & (u32::from(flag))) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            ret.push(TcNatFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&VecTcNatFlag> for u32 {
    fn from(v: &VecTcNatFlag) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}
