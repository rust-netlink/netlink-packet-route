// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, parse_u16, parse_u32, DecodeError, DefaultNla, Emitable,
    EncodeError, Nla, NlaBuffer, Parseable,
};

use super::bridge::{append_nla_u16, append_nla_u32};

const IFLA_BRIDGE_MRP_INSTANCE: u16 = 1;
const IFLA_BRIDGE_MRP_PORT_STATE: u16 = 2;
const IFLA_BRIDGE_MRP_PORT_ROLE: u16 = 3;
const IFLA_BRIDGE_MRP_RING_STATE: u16 = 4;
const IFLA_BRIDGE_MRP_RING_ROLE: u16 = 5;
const IFLA_BRIDGE_MRP_START_TEST: u16 = 6;
const IFLA_BRIDGE_MRP_INFO: u16 = 7;
const IFLA_BRIDGE_MRP_IN_ROLE: u16 = 8;
const IFLA_BRIDGE_MRP_IN_STATE: u16 = 9;
const IFLA_BRIDGE_MRP_START_IN_TEST: u16 = 10;

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpInstance {
    pub ring_id: u32,
    pub p_ifindex: u32,
    pub s_ifindex: u32,
    pub prio: u16,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpPortState {
    pub state: u32,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpPortRole {
    pub role: u32,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpRingState {
    pub ring_id: u32,
    pub ring_state: u32,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpRingRole {
    pub ring_id: u32,
    pub ring_role: u32,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpStartTest {
    pub ring_id: u32,
    pub interval: u32,
    pub max_miss: u32,
    pub period: u32,
    pub monitor: u32,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpInfo {
    pub ring_id: u32,
    pub p_ifindex: Option<u32>,
    pub s_ifindex: Option<u32>,
    pub i_ifindex: Option<u32>,
    pub prio: u16,
    pub ring_state: u32,
    pub ring_role: u32,
    pub test_interval: u32,
    pub test_max_miss: u32,
    pub test_monitor: u32,
    pub in_state: u32,
    pub in_role: u32,
    pub in_test_interval: u32,
    pub in_test_max_miss: u32,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpInRole {
    pub ring_id: u32,
    pub in_role: u32,
    pub i_ifindex: u32,
    pub in_id: u16,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpInState {
    pub in_state: u32,
    pub in_id: u32,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct BridgeMrpStartInTest {
    pub interval: u32,
    pub max_miss: u32,
    pub period: u32,
    pub in_id: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum BridgeMrp {
    Instance(BridgeMrpInstance),
    PortState(BridgeMrpPortState),
    PortRole(BridgeMrpPortRole),
    RingState(BridgeMrpRingState),
    RingRole(BridgeMrpRingRole),
    StartTest(BridgeMrpStartTest),
    Info(BridgeMrpInfo),
    InRole(BridgeMrpInRole),
    InState(BridgeMrpInState),
    StartInTest(BridgeMrpStartInTest),
    Other(DefaultNla),
}

impl Nla for BridgeMrp {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Instance(v) => v.emit(out),
            Self::PortState(v) => v.emit(out),
            Self::PortRole(v) => v.emit(out),
            Self::RingState(v) => v.emit(out),
            Self::RingRole(v) => v.emit(out),
            Self::StartTest(v) => v.emit(out),
            Self::Info(v) => v.emit(out),
            Self::InRole(v) => v.emit(out),
            Self::InState(v) => v.emit(out),
            Self::StartInTest(v) => v.emit(out),
            Self::Other(nla) => {
                append_bytes(out, nla.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Instance(_) => IFLA_BRIDGE_MRP_INSTANCE,
            Self::PortState(_) => IFLA_BRIDGE_MRP_PORT_STATE,
            Self::PortRole(_) => IFLA_BRIDGE_MRP_PORT_ROLE,
            Self::RingState(_) => IFLA_BRIDGE_MRP_RING_STATE,
            Self::RingRole(_) => IFLA_BRIDGE_MRP_RING_ROLE,
            Self::StartTest(_) => IFLA_BRIDGE_MRP_START_TEST,
            Self::Info(_) => IFLA_BRIDGE_MRP_INFO,
            Self::InRole(_) => IFLA_BRIDGE_MRP_IN_ROLE,
            Self::InState(_) => IFLA_BRIDGE_MRP_IN_STATE,
            Self::StartInTest(_) => IFLA_BRIDGE_MRP_START_IN_TEST,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for BridgeMrp {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            IFLA_BRIDGE_MRP_INSTANCE => {
                Self::Instance(BridgeMrpInstance::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_PORT_STATE => {
                Self::PortState(BridgeMrpPortState::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_PORT_ROLE => {
                Self::PortRole(BridgeMrpPortRole::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_RING_STATE => {
                Self::RingState(BridgeMrpRingState::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_RING_ROLE => {
                Self::RingRole(BridgeMrpRingRole::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_START_TEST => {
                Self::StartTest(BridgeMrpStartTest::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_INFO => Self::Info(BridgeMrpInfo::parse(buf)?),
            IFLA_BRIDGE_MRP_IN_ROLE => {
                Self::InRole(BridgeMrpInRole::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_IN_STATE => {
                Self::InState(BridgeMrpInState::parse(buf)?)
            }
            IFLA_BRIDGE_MRP_START_IN_TEST => {
                Self::StartInTest(BridgeMrpStartInTest::parse(buf)?)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

macro_rules! get_u32 {
    ($nla:expr, $kind:expr) => {
        if $nla.kind() == $kind {
            Some(parse_u32($nla.value())?)
        } else {
            None
        }
    };
}

impl BridgeMrpInstance {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let (mut ring_id, mut p, mut s, mut prio) = (None, None, None, None);
        for nla in buf.nlas()? {
            if let Some(v) = get_u32!(nla, 1) {
                ring_id = Some(v);
            } else if let Some(v) = get_u32!(nla, 2) {
                p = Some(v);
            } else if let Some(v) = get_u32!(nla, 3) {
                s = Some(v);
            } else if nla.kind() == 4 {
                prio = Some(parse_u16(nla.value())?);
            }
        }
        Ok(Self {
            ring_id: ring_id
                .ok_or_else(|| DecodeError::from("missing ring id"))?,
            p_ifindex: p
                .ok_or_else(|| DecodeError::from("missing p ifindex"))?,
            s_ifindex: s
                .ok_or_else(|| DecodeError::from("missing s ifindex"))?,
            prio: prio.ok_or_else(|| DecodeError::from("missing prio"))?,
        })
    }
}

impl Emitable for BridgeMrpInstance {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.ring_id);
        append_nla_u32(out, 2, self.p_ifindex);
        append_nla_u32(out, 3, self.s_ifindex);
        append_nla_u16(out, 4, self.prio);
        Ok(())
    }
}

impl BridgeMrpPortState {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut state = None;
        for nla in buf.nlas()? {
            if let Some(v) = get_u32!(nla, 1) {
                state = Some(v);
            }
        }
        Ok(Self {
            state: state.ok_or_else(|| DecodeError::from("missing state"))?,
        })
    }
}

impl Emitable for BridgeMrpPortState {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.state);
        Ok(())
    }
}

impl BridgeMrpPortRole {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut role = None;
        for nla in buf.nlas()? {
            if let Some(v) = get_u32!(nla, 1) {
                role = Some(v);
            }
        }
        Ok(Self {
            role: role.ok_or_else(|| DecodeError::from("missing role"))?,
        })
    }
}

impl Emitable for BridgeMrpPortRole {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.role);
        Ok(())
    }
}

impl BridgeMrpRingState {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let (mut ring_id, mut state) = (None, None);
        for nla in buf.nlas()? {
            if let Some(v) = get_u32!(nla, 1) {
                ring_id = Some(v);
            } else if let Some(v) = get_u32!(nla, 2) {
                state = Some(v);
            }
        }
        Ok(Self {
            ring_id: ring_id
                .ok_or_else(|| DecodeError::from("missing ring id"))?,
            ring_state: state
                .ok_or_else(|| DecodeError::from("missing ring state"))?,
        })
    }
}

impl Emitable for BridgeMrpRingState {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.ring_id);
        append_nla_u32(out, 2, self.ring_state);
        Ok(())
    }
}

impl BridgeMrpRingRole {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let (mut ring_id, mut role) = (None, None);
        for nla in buf.nlas()? {
            if let Some(v) = get_u32!(nla, 1) {
                ring_id = Some(v);
            } else if let Some(v) = get_u32!(nla, 2) {
                role = Some(v);
            }
        }
        Ok(Self {
            ring_id: ring_id
                .ok_or_else(|| DecodeError::from("missing ring id"))?,
            ring_role: role
                .ok_or_else(|| DecodeError::from("missing ring role"))?,
        })
    }
}

impl Emitable for BridgeMrpRingRole {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.ring_id);
        append_nla_u32(out, 2, self.ring_role);
        Ok(())
    }
}

impl BridgeMrpStartTest {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut v = [None; 5];
        for nla in buf.nlas()? {
            for (i, slot) in v.iter_mut().enumerate() {
                let kind = i as u16 + 1;
                if let Some(value) = get_u32!(nla, kind) {
                    *slot = Some(value);
                }
            }
        }
        Ok(Self {
            ring_id: v[0]
                .ok_or_else(|| DecodeError::from("missing ring id"))?,
            interval: v[1]
                .ok_or_else(|| DecodeError::from("missing interval"))?,
            max_miss: v[2]
                .ok_or_else(|| DecodeError::from("missing max miss"))?,
            period: v[3].ok_or_else(|| DecodeError::from("missing period"))?,
            monitor: v[4]
                .ok_or_else(|| DecodeError::from("missing monitor"))?,
        })
    }
}

impl Emitable for BridgeMrpStartTest {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.ring_id);
        append_nla_u32(out, 2, self.interval);
        append_nla_u32(out, 3, self.max_miss);
        append_nla_u32(out, 4, self.period);
        append_nla_u32(out, 5, self.monitor);
        Ok(())
    }
}

impl BridgeMrpInfo {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut info = Self::default();
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => info.ring_id = parse_u32(nla.value())?,
                2 => info.p_ifindex = Some(parse_u32(nla.value())?),
                3 => info.s_ifindex = Some(parse_u32(nla.value())?),
                4 => info.prio = parse_u16(nla.value())?,
                5 => info.ring_state = parse_u32(nla.value())?,
                6 => info.ring_role = parse_u32(nla.value())?,
                7 => info.test_interval = parse_u32(nla.value())?,
                8 => info.test_max_miss = parse_u32(nla.value())?,
                9 => info.test_monitor = parse_u32(nla.value())?,
                10 => info.i_ifindex = Some(parse_u32(nla.value())?),
                11 => info.in_state = parse_u32(nla.value())?,
                12 => info.in_role = parse_u32(nla.value())?,
                13 => info.in_test_interval = parse_u32(nla.value())?,
                14 => info.in_test_max_miss = parse_u32(nla.value())?,
                _ => {}
            }
        }
        Ok(info)
    }
}

impl Emitable for BridgeMrpInfo {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.ring_id);
        if let Some(v) = self.p_ifindex {
            append_nla_u32(out, 2, v);
        }
        if let Some(v) = self.s_ifindex {
            append_nla_u32(out, 3, v);
        }
        if let Some(v) = self.i_ifindex {
            append_nla_u32(out, 10, v);
        }
        append_nla_u16(out, 4, self.prio);
        append_nla_u32(out, 5, self.ring_state);
        append_nla_u32(out, 6, self.ring_role);
        append_nla_u32(out, 7, self.test_interval);
        append_nla_u32(out, 8, self.test_max_miss);
        append_nla_u32(out, 9, self.test_monitor);
        append_nla_u32(out, 11, self.in_state);
        append_nla_u32(out, 12, self.in_role);
        append_nla_u32(out, 13, self.in_test_interval);
        append_nla_u32(out, 14, self.in_test_max_miss);
        Ok(())
    }
}

impl BridgeMrpInRole {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut ring_id = None;
        let mut in_id = None;
        let mut in_role = None;
        let mut i_ifindex = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => ring_id = Some(parse_u32(nla.value())?),
                2 => in_id = Some(parse_u16(nla.value())?),
                3 => in_role = Some(parse_u32(nla.value())?),
                4 => i_ifindex = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            ring_id: ring_id
                .ok_or_else(|| DecodeError::from("missing ring id"))?,
            in_role: in_role
                .ok_or_else(|| DecodeError::from("missing in role"))?,
            i_ifindex: i_ifindex
                .ok_or_else(|| DecodeError::from("missing i ifindex"))?,
            in_id: in_id.ok_or_else(|| DecodeError::from("missing in id"))?,
        })
    }
}

impl Emitable for BridgeMrpInRole {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.ring_id);
        append_nla_u16(out, 2, self.in_id);
        append_nla_u32(out, 3, self.in_role);
        append_nla_u32(out, 4, self.i_ifindex);
        Ok(())
    }
}

impl BridgeMrpInState {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut in_state = None;
        let mut in_id = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => in_id = Some(parse_u32(nla.value())?),
                2 => in_state = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            in_state: in_state
                .ok_or_else(|| DecodeError::from("missing in state"))?,
            in_id: in_id.ok_or_else(|| DecodeError::from("missing in id"))?,
        })
    }
}

impl Emitable for BridgeMrpInState {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.in_id);
        append_nla_u32(out, 2, self.in_state);
        Ok(())
    }
}

impl BridgeMrpStartInTest {
    fn parse(buf: &NlaBuffer<'_>) -> Result<Self, DecodeError> {
        let mut interval = None;
        let mut max_miss = None;
        let mut period = None;
        let mut in_id = None;
        for nla in buf.nlas()? {
            match nla.kind() {
                1 => in_id = Some(parse_u32(nla.value())?),
                2 => interval = Some(parse_u32(nla.value())?),
                3 => max_miss = Some(parse_u32(nla.value())?),
                4 => period = Some(parse_u32(nla.value())?),
                _ => {}
            }
        }
        Ok(Self {
            interval: interval
                .ok_or_else(|| DecodeError::from("missing interval"))?,
            max_miss: max_miss
                .ok_or_else(|| DecodeError::from("missing max miss"))?,
            period: period
                .ok_or_else(|| DecodeError::from("missing period"))?,
            in_id: in_id.ok_or_else(|| DecodeError::from("missing in id"))?,
        })
    }
}

impl Emitable for BridgeMrpStartInTest {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_nla_u32(out, 1, self.in_id);
        append_nla_u32(out, 2, self.interval);
        append_nla_u32(out, 3, self.max_miss);
        append_nla_u32(out, 4, self.period);
        Ok(())
    }
}
