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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum TcU32OptionFlag {
    SkipHw,
    SkipSw,
    InHw,
    NotInHw,
    Verbose,
    Other(u32),
}

impl From<TcU32OptionFlag> for u32 {
    fn from(v: TcU32OptionFlag) -> u32 {
        match v {
            TcU32OptionFlag::SkipHw => TCA_CLS_FLAGS_SKIP_HW,
            TcU32OptionFlag::SkipSw => TCA_CLS_FLAGS_SKIP_SW,
            TcU32OptionFlag::InHw => TCA_CLS_FLAGS_IN_HW,
            TcU32OptionFlag::NotInHw => TCA_CLS_FLAGS_NOT_IN_HW,
            TcU32OptionFlag::Verbose => TCA_CLS_FLAGS_VERBOSE,
            TcU32OptionFlag::Other(i) => i,
        }
    }
}

const ALL_OPTION_FLAGS: [TcU32OptionFlag; 5] = [
    TcU32OptionFlag::SkipHw,
    TcU32OptionFlag::SkipSw,
    TcU32OptionFlag::InHw,
    TcU32OptionFlag::NotInHw,
    TcU32OptionFlag::Verbose,
];

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct VecTcU32OptionFlag(pub(crate) Vec<TcU32OptionFlag>);

impl From<u32> for VecTcU32OptionFlag {
    fn from(d: u32) -> Self {
        let mut got: u32 = 0;
        let mut ret = Vec::new();
        for flag in ALL_OPTION_FLAGS {
            if (d & (u32::from(flag))) > 0 {
                ret.push(flag);
                got += u32::from(flag);
            }
        }
        if got != d {
            ret.push(TcU32OptionFlag::Other(d - got));
        }
        Self(ret)
    }
}

impl From<&VecTcU32OptionFlag> for u32 {
    fn from(v: &VecTcU32OptionFlag) -> u32 {
        let mut d: u32 = 0;
        for flag in &v.0 {
            d += u32::from(*flag);
        }
        d
    }
}
