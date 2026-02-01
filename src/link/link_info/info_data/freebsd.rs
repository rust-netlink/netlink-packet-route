// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, Nla, NlasIterator, Parseable,
};

use super::{super::InfoVlan, IFLA_INFO_DATA};
use crate::link::InfoKind;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoData {
    Vlan(Vec<InfoVlan>),
    Other(Vec<u8>),
}

impl Nla for InfoData {
    fn value_len(&self) -> usize {
        match self {
            Self::Vlan(nlas) => nlas.as_slice().buffer_len(),
            Self::Other(v) => v.len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Vlan(nlas) => nlas.as_slice().emit(buffer),
            Self::Other(v) => buffer.copy_from_slice(v),
        }
    }

    fn kind(&self) -> u16 {
        IFLA_INFO_DATA
    }
}

impl InfoData {
    pub(crate) fn parse_with_param(
        payload: &[u8],
        kind: &InfoKind,
    ) -> Result<InfoData, DecodeError> {
        Ok(match kind {
            InfoKind::Vlan => {
                let mut v = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(format!(
                        "invalid IFLA_INFO_DATA for {kind} {payload:?}"
                    ))?;
                    let parsed = InfoVlan::parse(nla)?;
                    v.push(parsed);
                }
                InfoData::Vlan(v)
            }
            _ => InfoData::Other(payload.to_vec()),
        })
    }
}
