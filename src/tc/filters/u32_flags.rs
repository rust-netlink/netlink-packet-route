// SPDX-License-Identifier: MIT

const TC_U32_TERMINAL: u8 = 1;
const TC_U32_OFFSET: u8 = 2;
const TC_U32_VAROFFSET: u8 = 4;
const TC_U32_EAT: u8 = 8;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum TcU32SelectorFlag {
    Terminal,
    Offset,
    VarOffset,
    Eat,
    Other(u8),
}

impl From<TcU32SelectorFlag> for u8 {
    fn from(v: TcU32SelectorFlag) -> u8 {
        match v {
            TcU32SelectorFlag::Terminal => TC_U32_TERMINAL,
            TcU32SelectorFlag::Offset => TC_U32_OFFSET,
            TcU32SelectorFlag::VarOffset => TC_U32_VAROFFSET,
            TcU32SelectorFlag::Eat => TC_U32_EAT,
            TcU32SelectorFlag::Other(i) => i,
        }
    }
}

const ALL_SELECTOR_FLAGS: [TcU32SelectorFlag; 4] = [
    TcU32SelectorFlag::Terminal,
    TcU32SelectorFlag::Offset,
    TcU32SelectorFlag::VarOffset,
    TcU32SelectorFlag::Eat,
];

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct VecTcU32SelectorFlag(pub(crate) Vec<TcU32SelectorFlag>);

impl From<u8> for VecTcU32SelectorFlag {
    fn from(d: u8) -> Self {
        let mut got: u8 = 0;
        let mut ret = Vec::new();
        for flag in ALL_SELECTOR_FLAGS {
            if (d & (u8::from(flag))) > 0 {
                ret.push(flag);
                got += u8::from(flag);
            }
        }
        if got != d {
            ret.push(TcU32SelectorFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&VecTcU32SelectorFlag> for u8 {
    fn from(v: &VecTcU32SelectorFlag) -> u8 {
        let mut d: u8 = 0;
        for flag in &v.0 {
            d += u8::from(*flag);
        }
        d
    }
}

const TCA_CLS_FLAGS_SKIP_HW: u32 = 1 << 0;
const TCA_CLS_FLAGS_SKIP_SW: u32 = 1 << 1;
const TCA_CLS_FLAGS_IN_HW: u32 = 1 << 2;
const TCA_CLS_FLAGS_NOT_IN_HW: u32 = 1 << 3;
const TCA_CLS_FLAGS_VERBOSE: u32 = 1 << 4;

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct TcU32OptionFlags: u32 {
        const SkipHw = TCA_CLS_FLAGS_SKIP_HW;
        const SkipSw = TCA_CLS_FLAGS_SKIP_SW;
        const InHw = TCA_CLS_FLAGS_IN_HW;
        const NotInHw = TCA_CLS_FLAGS_NOT_IN_HW;
        const Verbose = TCA_CLS_FLAGS_VERBOSE;
        const _ = !0;
    }
}
