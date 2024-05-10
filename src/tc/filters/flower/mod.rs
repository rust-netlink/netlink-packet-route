pub mod encap;
pub mod mpls;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Flags : u32 {
        const IsFragment = 1 << 0;
        const FragmentIsFirst = 1 << 0;
        const _ = !0;
    }
}
