// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, parse_string, DecodeError, Emitable, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

use super::{
    super::{InfoBondPort, InfoBridgePort},
    InfoTeamPort, InfoVrf,
};

const BOND: &str = "bond";
const BRIDGE: &str = "bridge";
const VRF: &str = "vrf";
const TEAM: &str = "team";

const IFLA_INFO_PORT_KIND: u16 = 4;
const IFLA_INFO_PORT_DATA: u16 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoPortKind {
    Bond,
    Bridge,
    Vrf,
    Team,
    Other(String),
}

impl std::fmt::Display for InfoPortKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Bond => BOND,
                Self::Bridge => BRIDGE,
                Self::Vrf => VRF,
                Self::Team => TEAM,
                Self::Other(s) => s.as_str(),
            }
        )
    }
}

impl Nla for InfoPortKind {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let s = match self {
            Self::Bond => BOND,
            Self::Bridge => BRIDGE,
            Self::Vrf => VRF,
            Self::Team => TEAM,
            Self::Other(s) => s.as_str(),
        };
        append_bytes(out, s.as_bytes());
        out.push(0);
        Ok(())
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_PORT_KIND
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoPortKind {
    fn parse(buf: &NlaBuffer<'a>) -> Result<InfoPortKind, DecodeError> {
        if buf.kind() != IFLA_INFO_PORT_KIND {
            return Err(format!(
                "failed to parse IFLA_INFO_PORT_KIND: NLA type is {}",
                buf.kind()
            )
            .into());
        }
        let s = parse_string(buf.value())
            .context("invalid IFLA_INFO_PORT_KIND value")?;
        Ok(match s.as_str() {
            BOND => Self::Bond,
            BRIDGE => Self::Bridge,
            VRF => Self::Vrf,
            TEAM => Self::Team,
            _ => Self::Other(s),
        })
    }
}

pub type InfoVrfPort = InfoVrf;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoPortData {
    BondPort(Vec<InfoBondPort>),
    BridgePort(Vec<InfoBridgePort>),
    VrfPort(Vec<InfoVrfPort>),
    TeamPort(Vec<InfoTeamPort>),
    Other(Vec<u8>),
}

impl Nla for InfoPortData {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::BondPort(nlas) => (nlas).emit(out)?,
            Self::BridgePort(nlas) => (nlas).emit(out)?,
            Self::VrfPort(nlas) => (nlas).emit(out)?,
            Self::TeamPort(nlas) => (nlas).emit(out)?,
            Self::Other(bytes) => append_bytes(out, bytes),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_PORT_DATA
    }
}

impl InfoPortData {
    pub(crate) fn parse_with_param(
        buf: &NlaBuffer<'_>,
        kind: InfoPortKind,
    ) -> Result<InfoPortData, DecodeError> {
        let payload = buf.value();
        let port_data = match kind {
            InfoPortKind::Bond => buf
                .nlas()?
                .map(|nla| InfoBondPort::parse(&nla))
                .collect::<Result<Vec<_>, _>>()
                .map(InfoPortData::BondPort),
            InfoPortKind::Bridge => buf
                .nlas()?
                .map(|nla| InfoBridgePort::parse(&nla))
                .collect::<Result<Vec<_>, _>>()
                .map(InfoPortData::BridgePort),
            InfoPortKind::Vrf => buf
                .nlas()?
                .map(|nla| InfoVrfPort::parse(&nla))
                .collect::<Result<Vec<_>, _>>()
                .map(InfoPortData::VrfPort),
            InfoPortKind::Team => buf
                .nlas()?
                .map(|nla| InfoTeamPort::parse(&nla))
                .collect::<Result<Vec<_>, _>>()
                .map(InfoPortData::TeamPort),
            InfoPortKind::Other(_) => Ok(InfoPortData::Other(payload.to_vec())),
        };

        port_data.with_context(|| {
            format!(
                "failed to parse IFLA_INFO_PORT_DATA (IFLA_INFO_PORT_KIND is \
                 '{kind}')"
            )
        })
    }
}
