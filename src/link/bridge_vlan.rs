// SPDX-License-Identifier: MIT

const BRIDGE_VLAN_INFO_CONTROLLER: u16 = 1 << 0;
const BRIDGE_VLAN_INFO_PVID: u16 = 1 << 1;
const BRIDGE_VLAN_INFO_UNTAGGED: u16 = 1 << 2;
const BRIDGE_VLAN_INFO_RANGE_BEGIN: u16 = 1 << 3;
const BRIDGE_VLAN_INFO_RANGE_END: u16 = 1 << 4;
const BRIDGE_VLAN_INFO_BRENTRY: u16 = 1 << 5;
const BRIDGE_VLAN_INFO_ONLY_OPTS: u16 = 1 << 6;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct BridgeVlanInfoFlags: u16 {
        /// Operate on Bridge device as well
        const Controller = BRIDGE_VLAN_INFO_CONTROLLER;
        /// VLAN is PVID, ingress untagged
        const Pvid = BRIDGE_VLAN_INFO_PVID;
        /// VLAN egresses untagged
        const Untagged= BRIDGE_VLAN_INFO_UNTAGGED;
        /// VLAN is start of vlan range
        const RangeBegin = BRIDGE_VLAN_INFO_RANGE_BEGIN;
        /// VLAN is end of vlan range
        const RangeEnd = BRIDGE_VLAN_INFO_RANGE_END;
        /// Global bridge VLAN entry
        const Brentry = BRIDGE_VLAN_INFO_BRENTRY;
        /// Skip create/delete/flags
        const OnlyOpts= BRIDGE_VLAN_INFO_ONLY_OPTS;
        const _ = !0;
    }
}

impl BridgeVlanInfoFlags {
    pub const LENGTH: usize = 2;
}
