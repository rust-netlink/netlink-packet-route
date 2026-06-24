// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_i32, emit_u16, emit_u32, parse_i32, parse_u16, parse_u32, parse_u8,
    DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer, Parseable,
};

const IFLA_BOND_PORT_STATE_ACTIVE: u8 = 0;
const IFLA_BOND_PORT_STATE_BACKUP: u8 = 1;

const IFLA_BOND_PORT_MII_STATUS_UP: u8 = 0;
const IFLA_BOND_PORT_MII_STATUS_GOING_DOWN: u8 = 1;
const IFLA_BOND_PORT_MII_STATUS_DOWN: u8 = 2;
const IFLA_BOND_PORT_MII_STATUS_GOING_BACK: u8 = 3;

const IFLA_BOND_PORT_STATE: u16 = 1;
const IFLA_BOND_PORT_MII_STATUS: u16 = 2;
const IFLA_BOND_PORT_LINK_FAILURE_COUNT: u16 = 3;
const IFLA_BOND_PORT_PERM_HWADDR: u16 = 4;
const IFLA_BOND_PORT_QUEUE_ID: u16 = 5;
// const IFLA_BOND_PORT_AD_AGGREGATOR_ID: u16 = 6;
// const IFLA_BOND_PORT_AD_ACTOR_OPER_PORT_STATE: u16 = 7;
// const IFLA_BOND_PORT_AD_PARTNER_OPER_PORT_STATE: u16 = 8;
const IFLA_BOND_PORT_PRIO: u16 = 9;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum BondPortState {
    Active,
    Backup,
    Other(u8),
}

impl From<u8> for BondPortState {
    fn from(value: u8) -> Self {
        match value {
            IFLA_BOND_PORT_STATE_ACTIVE => BondPortState::Active,
            IFLA_BOND_PORT_STATE_BACKUP => BondPortState::Backup,
            _ => BondPortState::Other(value),
        }
    }
}

impl From<BondPortState> for u8 {
    fn from(value: BondPortState) -> Self {
        match value {
            BondPortState::Active => IFLA_BOND_PORT_STATE_ACTIVE,
            BondPortState::Backup => IFLA_BOND_PORT_STATE_BACKUP,
            BondPortState::Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum MiiStatus {
    Up,
    GoingDown,
    Down,
    GoingBack,
    Other(u8),
}

impl From<u8> for MiiStatus {
    fn from(value: u8) -> Self {
        match value {
            IFLA_BOND_PORT_MII_STATUS_UP => MiiStatus::Up,
            IFLA_BOND_PORT_MII_STATUS_GOING_DOWN => MiiStatus::GoingDown,
            IFLA_BOND_PORT_MII_STATUS_DOWN => MiiStatus::Down,
            IFLA_BOND_PORT_MII_STATUS_GOING_BACK => MiiStatus::GoingBack,
            _ => MiiStatus::Other(value),
        }
    }
}

impl From<MiiStatus> for u8 {
    fn from(value: MiiStatus) -> Self {
        match value {
            MiiStatus::Up => IFLA_BOND_PORT_MII_STATUS_UP,
            MiiStatus::GoingDown => IFLA_BOND_PORT_MII_STATUS_GOING_DOWN,
            MiiStatus::Down => IFLA_BOND_PORT_MII_STATUS_DOWN,
            MiiStatus::GoingBack => IFLA_BOND_PORT_MII_STATUS_GOING_BACK,
            MiiStatus::Other(other) => other,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoBondPort {
    LinkFailureCount(u32),
    MiiStatus(MiiStatus),
    PermHwaddr(Vec<u8>),
    Prio(i32),
    QueueId(u16),
    BondPortState(BondPortState),
    Other(DefaultNla),
}

impl Nla for InfoBondPort {
    fn value_len(&self) -> usize {
        match self {
            Self::QueueId(_) => 2,
            Self::LinkFailureCount(_) | Self::Prio(_) => 4,
            Self::PermHwaddr(ref bytes) => bytes.len(),
            Self::MiiStatus(_) => 1,
            Self::BondPortState(_) => 1,
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::QueueId(ref value) => emit_u16(buffer, *value).unwrap(),
            Self::PermHwaddr(ref bytes) => {
                buffer.copy_from_slice(bytes.as_slice())
            }
            Self::Prio(ref value) => emit_i32(buffer, *value).unwrap(),
            Self::LinkFailureCount(value) => emit_u32(buffer, *value).unwrap(),
            Self::MiiStatus(state) => buffer[0] = (*state).into(),
            Self::BondPortState(state) => buffer[0] = (*state).into(),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::LinkFailureCount(_) => IFLA_BOND_PORT_LINK_FAILURE_COUNT,
            Self::MiiStatus(_) => IFLA_BOND_PORT_MII_STATUS,
            Self::PermHwaddr(_) => IFLA_BOND_PORT_PERM_HWADDR,
            Self::Prio(_) => IFLA_BOND_PORT_PRIO,
            Self::QueueId(_) => IFLA_BOND_PORT_QUEUE_ID,
            Self::BondPortState(_) => IFLA_BOND_PORT_STATE,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoBondPort {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BOND_PORT_LINK_FAILURE_COUNT => {
                Self::LinkFailureCount(parse_u32(payload).context(
                    "invalid IFLA_BOND_PORT_LINK_FAILURE_COUNT value",
                )?)
            }
            IFLA_BOND_PORT_MII_STATUS => Self::MiiStatus(
                parse_u8(payload)
                    .context("invalid IFLA_BOND_PORT_MII_STATUS value")?
                    .into(),
            ),
            IFLA_BOND_PORT_PERM_HWADDR => Self::PermHwaddr(payload.to_vec()),
            IFLA_BOND_PORT_PRIO => Self::Prio(
                parse_i32(payload)
                    .context("invalid IFLA_BOND_PORT_PRIO value")?,
            ),
            IFLA_BOND_PORT_QUEUE_ID => Self::QueueId(
                parse_u16(payload)
                    .context("invalid IFLA_BOND_PORT_QUEUE_ID value")?,
            ),
            IFLA_BOND_PORT_STATE => Self::BondPortState(
                parse_u8(payload)
                    .context("invalid IFLA_BOND_PORT_STATE value")?
                    .into(),
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
