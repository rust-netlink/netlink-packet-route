// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_u16, parse_u16_be, parse_u32},
    traits::{Emitable, Parseable},
    DecodeError,
};

const IFLA_VLAN_ID: u16 = 1;
const IFLA_VLAN_FLAGS: u16 = 2;
const IFLA_VLAN_EGRESS_QOS: u16 = 3;
const IFLA_VLAN_INGRESS_QOS: u16 = 4;
const IFLA_VLAN_PROTOCOL: u16 = 5;

const IFLA_VLAN_QOS_MAPPING: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoVlan {
    Id(u16),
    Flags((u32, u32)),
    EgressQos(Vec<VlanQosMapping>),
    IngressQos(Vec<VlanQosMapping>),
    Protocol(VlanProtocol),
}

impl Nla for InfoVlan {
    fn value_len(&self) -> usize {
        use self::InfoVlan::*;
        match self {
            Id(_) | Protocol(_) => 2,
            Flags(_) => 8,
            EgressQos(mappings) | IngressQos(mappings) => {
                mappings.as_slice().buffer_len()
            }
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoVlan::*;
        match self {
            EgressQos(ref mappings) | IngressQos(ref mappings) => {
                mappings.as_slice().emit(buffer)
            }
            Id(ref value) => NativeEndian::write_u16(buffer, *value),
            Protocol(value) => BigEndian::write_u16(buffer, (*value).into()),
            Flags(ref flags) => {
                NativeEndian::write_u32(&mut buffer[0..4], flags.0);
                NativeEndian::write_u32(&mut buffer[4..8], flags.1)
            }
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoVlan::*;
        match self {
            Id(_) => IFLA_VLAN_ID,
            Flags(_) => IFLA_VLAN_FLAGS,
            EgressQos(_) => IFLA_VLAN_EGRESS_QOS,
            IngressQos(_) => IFLA_VLAN_INGRESS_QOS,
            Protocol(_) => IFLA_VLAN_PROTOCOL,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum VlanQosMapping {
    /// Tuple (from, to)
    Mapping(u32, u32),
    Other(DefaultNla),
}

impl Nla for VlanQosMapping {
    fn value_len(&self) -> usize {
        match self {
            VlanQosMapping::Mapping { .. } => 8,
            VlanQosMapping::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            VlanQosMapping::Mapping { .. } => IFLA_VLAN_QOS_MAPPING,
            VlanQosMapping::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use VlanQosMapping::*;
        match self {
            Mapping(from, to) => {
                NativeEndian::write_u32(buffer, *from);
                NativeEndian::write_u32(&mut buffer[4..], *to);
            }
            Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for VlanQosMapping
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use VlanQosMapping::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VLAN_QOS_MAPPING => Mapping(
                parse_u32(&payload[..4]).context("expected u32 from value")?,
                parse_u32(&payload[4..]).context("expected u32 to value")?,
            ),
            kind => Other(DefaultNla::parse(buf).context(format!(
                "unknown NLA type {kind} for VLAN QoS mapping"
            ))?),
        })
    }
}

fn parse_mappings(payload: &[u8]) -> Result<Vec<VlanQosMapping>, DecodeError> {
    let mut mappings = Vec::new();
    for nla in NlasIterator::new(payload) {
        let nla = nla?;
        let parsed = VlanQosMapping::parse(&nla)?;
        mappings.push(parsed);
    }
    Ok(mappings)
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoVlan {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoVlan::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VLAN_ID => {
                Id(parse_u16(payload).context("invalid IFLA_VLAN_ID value")?)
            }
            IFLA_VLAN_FLAGS => {
                let err = "invalid IFLA_VLAN_FLAGS value";
                if payload.len() != 8 {
                    return Err(err.into());
                }
                let flags = parse_u32(&payload[0..4]).context(err)?;
                let mask = parse_u32(&payload[4..]).context(err)?;
                Flags((flags, mask))
            }
            IFLA_VLAN_EGRESS_QOS => EgressQos(
                parse_mappings(payload)
                    .context("failed to parse IFLA_VLAN_EGRESS_QOS")?,
            ),
            IFLA_VLAN_INGRESS_QOS => IngressQos(
                parse_mappings(payload)
                    .context("failed to parse IFLA_VLAN_INGRESS_QOS")?,
            ),
            IFLA_VLAN_PROTOCOL => Protocol(
                parse_u16_be(payload)
                    .context("invalid IFLA_VLAN_PROTOCOL value")?
                    .into(),
            ),
            _ => return Err(format!("unknown NLA type {}", buf.kind()).into()),
        })
    }
}

const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
#[repr(u16)]
// VLAN protocol seldom add new, so no Other for this enum.
pub enum VlanProtocol {
    #[default]
    Ieee8021Q = ETH_P_8021Q,
    Ieee8021Ad = ETH_P_8021AD,
}

impl From<u16> for VlanProtocol {
    fn from(d: u16) -> Self {
        match d {
            ETH_P_8021Q => Self::Ieee8021Q,
            ETH_P_8021AD => Self::Ieee8021Ad,
            _ => {
                log::warn!(
                    "BUG: Got unknown VLAN protocol {}, treating as {}",
                    d,
                    Self::Ieee8021Q
                );
                Self::Ieee8021Q
            }
        }
    }
}

impl From<VlanProtocol> for u16 {
    fn from(v: VlanProtocol) -> u16 {
        match v {
            VlanProtocol::Ieee8021Q => ETH_P_8021Q,
            VlanProtocol::Ieee8021Ad => ETH_P_8021AD,
        }
    }
}

impl std::fmt::Display for VlanProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                VlanProtocol::Ieee8021Q => "802.1q",
                VlanProtocol::Ieee8021Ad => "802.1ad",
            }
        )
    }
}
