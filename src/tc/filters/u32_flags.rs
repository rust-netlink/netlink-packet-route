// SPDX-License-Identifier: MIT

use crate::tc::filters::cls_flags::{
    TCA_CLS_FLAGS_IN_HW, TCA_CLS_FLAGS_NOT_IN_HW, TCA_CLS_FLAGS_SKIP_HW,
    TCA_CLS_FLAGS_SKIP_SW, TCA_CLS_FLAGS_VERBOSE,
};

const TC_U32_TERMINAL: u8 = 1 << 0;
const TC_U32_OFFSET: u8 = 1 << 1;
const TC_U32_VAROFFSET: u8 = 1 << 2;
const TC_U32_EAT: u8 = 1 << 3;

bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct TcU32SelectorFlags: u8 {
        const Terminal = TC_U32_TERMINAL;
        const Offset = TC_U32_OFFSET;
        const VarOffset = TC_U32_VAROFFSET;
        const Eat = TC_U32_EAT;
        const _ = !0;
    }
}

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
