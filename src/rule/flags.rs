// SPDX-License-Identifier: MIT

const FIB_RULE_PERMANENT: u32 = 0x00000001;
const FIB_RULE_INVERT: u32 = 0x00000002;
const FIB_RULE_UNRESOLVED: u32 = 0x00000004;
const FIB_RULE_IIF_DETACHED: u32 = 0x00000008;
const FIB_RULE_DEV_DETACHED: u32 = FIB_RULE_IIF_DETACHED;
const FIB_RULE_OIF_DETACHED: u32 = 0x00000010;

/// Flags that can be set in a `RTM_GETROUTE`
/// ([`RuleNetlinkMessage::GetRule`]) message.
#[derive(Clone, Eq, PartialEq, Debug, Copy)]
#[non_exhaustive]
pub enum RuleFlag {
    Permanent,
    Invert,
    Unresolved,
    IifDetached,
    DevDetached,
    OifDetached,
    Other(u32),
}

const ALL_RULE_FLAGS: [RuleFlag; 6] = [
    RuleFlag::Permanent,
    RuleFlag::Invert,
    RuleFlag::Unresolved,
    RuleFlag::IifDetached,
    RuleFlag::DevDetached,
    RuleFlag::OifDetached,
];

impl From<RuleFlag> for u32 {
    fn from(v: RuleFlag) -> u32 {
        match v {
            RuleFlag::Permanent => FIB_RULE_PERMANENT,
            RuleFlag::Invert => FIB_RULE_INVERT,
            RuleFlag::Unresolved => FIB_RULE_UNRESOLVED,
            RuleFlag::IifDetached => FIB_RULE_IIF_DETACHED,
            RuleFlag::DevDetached => FIB_RULE_DEV_DETACHED,
            RuleFlag::OifDetached => FIB_RULE_OIF_DETACHED,
            RuleFlag::Other(i) => i,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub(crate) struct VecRuleFlag(pub(crate) Vec<RuleFlag>);

impl From<u32> for VecRuleFlag {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_RULE_FLAGS {
            if (d & (u32::from(flag))) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            ret.push(RuleFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&VecRuleFlag> for u32 {
    fn from(v: &VecRuleFlag) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}
