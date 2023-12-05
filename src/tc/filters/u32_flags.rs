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

const ALL_FLAGS: [TcU32SelectorFlag; 4] = [
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
        for flag in ALL_FLAGS {
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
