// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::parse_string,
    DecodeError, Emitable, Parseable,
};

use super::super::InfoBondPort;

const BOND: &str = "bond";

const IFLA_INFO_PORT_KIND: u16 = 4;
const IFLA_INFO_PORT_DATA: u16 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoPortKind {
    Bond,
    Other(String),
}

impl std::fmt::Display for InfoPortKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Bond => BOND,
                Self::Other(s) => s.as_str(),
            }
        )
    }
}

impl Nla for InfoPortKind {
    fn value_len(&self) -> usize {
        let len = match self {
            Self::Bond => BOND.len(),
            Self::Other(s) => s.len(),
        };
        len + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let s = match self {
            Self::Bond => BOND,
            Self::Other(s) => s.as_str(),
        };
        buffer[..s.len()].copy_from_slice(s.as_bytes());
        buffer[s.len()] = 0;
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_PORT_KIND
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoPortKind {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<InfoPortKind, DecodeError> {
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
            _ => Self::Other(s),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoPortData {
    BondPort(Vec<InfoBondPort>),
    Other(Vec<u8>),
}

impl Nla for InfoPortData {
    fn value_len(&self) -> usize {
        match self {
            Self::BondPort(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(bytes) => bytes.len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::BondPort(nlas) => nlas.as_slice().emit(buffer),
            Self::Other(bytes) => buffer.copy_from_slice(bytes),
        }
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_PORT_DATA
    }
}

impl InfoPortData {
    pub(crate) fn parse_with_param(
        payload: &[u8],
        kind: InfoPortKind,
    ) -> Result<InfoPortData, DecodeError> {
        Ok(match kind {
            InfoPortKind::Bond => {
                let mut v = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(format!(
                        "failed to parse IFLA_INFO_PORT_DATA \
                    (IFLA_INFO_PORT_KIND is '{kind}')"
                    ))?;
                    let parsed = InfoBondPort::parse(nla).context(format!(
                        "failed to parse IFLA_INFO_PORT_DATA \
                    (IFLA_INFO_PORT_KIND is '{kind}')"
                    ))?;
                    v.push(parsed);
                }
                InfoPortData::BondPort(v)
            }
            InfoPortKind::Other(_) => InfoPortData::Other(payload.to_vec()),
        })
    }
}
