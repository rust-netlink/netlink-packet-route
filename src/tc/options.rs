// SPDX-License-Identifier: MIT

use super::{
    TcError, TcFilterMatchAll, TcFilterMatchAllOption, TcFilterU32,
    TcFilterU32Option, TcQdiscFqCodel, TcQdiscFqCodelOption, TcQdiscIngress,
    TcQdiscIngressOption,
};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    traits::{Parseable, ParseableParametrized},
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcOption {
    FqCodel(TcQdiscFqCodelOption),
    // Qdisc specific options
    Ingress(TcQdiscIngressOption),
    // Filter specific options
    U32(TcFilterU32Option),
    // matchall options
    MatchAll(TcFilterMatchAllOption),
    // Other options
    Other(DefaultNla),
}

impl Nla for TcOption {
    fn value_len(&self) -> usize {
        match self {
            Self::FqCodel(u) => u.value_len(),
            Self::Ingress(u) => u.value_len(),
            Self::U32(u) => u.value_len(),
            Self::MatchAll(m) => m.value_len(),
            Self::Other(o) => o.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::FqCodel(u) => u.emit_value(buffer),
            Self::Ingress(u) => u.emit_value(buffer),
            Self::U32(u) => u.emit_value(buffer),
            Self::MatchAll(m) => m.emit_value(buffer),
            Self::Other(o) => o.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::FqCodel(u) => u.kind(),
            Self::Ingress(u) => u.kind(),
            Self::U32(u) => u.kind(),
            Self::MatchAll(m) => m.kind(),
            Self::Other(o) => o.kind(),
        }
    }
}

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, &str> for TcOption
where
    T: AsRef<[u8]> + ?Sized,
{
    type Error = TcError;
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        kind: &str,
    ) -> Result<Self, TcError> {
        Ok(match kind {
            TcQdiscIngress::KIND => {
                Self::Ingress(TcQdiscIngressOption::parse(buf).map_err(
                    |error| TcError::ParseTcaOptionAttributes {
                        kind: "ingress",
                        error,
                    },
                )?)
            }
            TcQdiscFqCodel::KIND => {
                Self::FqCodel(TcQdiscFqCodelOption::parse(buf)?)
            }
            TcFilterU32::KIND => Self::U32(TcFilterU32Option::parse(buf)?),
            TcFilterMatchAll::KIND => {
                Self::MatchAll(TcFilterMatchAllOption::parse(buf)?)
            }
            kind => Self::Other(DefaultNla::parse(buf).map_err(|error| {
                TcError::UnknownOption {
                    kind: kind.to_string(),
                    error,
                }
            })?),
        })
    }
}

pub(crate) struct VecTcOption(pub(crate) Vec<TcOption>);

impl<'a, T> ParseableParametrized<NlaBuffer<&'a T>, &str> for VecTcOption
where
    T: AsRef<[u8]> + ?Sized,
{
    type Error = TcError;
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        kind: &str,
    ) -> Result<VecTcOption, TcError> {
        Ok(match kind {
            TcFilterU32::KIND
            | TcFilterMatchAll::KIND
            | TcQdiscIngress::KIND
            | TcQdiscFqCodel::KIND => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(buf.value()) {
                    let nla = nla?;
                    nlas.push(TcOption::parse_with_param(&nla, kind)?)
                }
                Self(nlas)
            }
            // Kernel has no guide line or code indicate the scheduler
            // should place a nla_nest here. The `sfq` qdisc kernel code is
            // using single NLA instead nested ones. Hence we are storing
            // unknown Nla as Vec with single item.
            kind => {
                Self(vec![TcOption::Other(DefaultNla::parse(buf).map_err(
                    |error| TcError::UnknownOption {
                        kind: kind.to_string(),
                        error,
                    },
                )?)])
            }
        })
    }
}
