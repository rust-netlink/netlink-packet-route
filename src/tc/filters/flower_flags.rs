use crate::tc::filters::cls_flags::{
    TCA_CLS_FLAGS_IN_HW, TCA_CLS_FLAGS_NOT_IN_HW, TCA_CLS_FLAGS_SKIP_HW,
    TCA_CLS_FLAGS_SKIP_SW, TCA_CLS_FLAGS_VERBOSE,
};

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct TcFlowerOptionFlags: u32 {
        const SkipHw = TCA_CLS_FLAGS_SKIP_HW;
        const SkipSw = TCA_CLS_FLAGS_SKIP_SW;
        const InHw = TCA_CLS_FLAGS_IN_HW;
        const NotInHw = TCA_CLS_FLAGS_NOT_IN_HW;
        const Verbose = TCA_CLS_FLAGS_VERBOSE;
        const _ = !0;
    }
}
