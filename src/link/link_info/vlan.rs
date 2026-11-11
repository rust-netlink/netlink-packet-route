// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u16, append_u16_be, append_u32, parse_u16,
    parse_u16_be, parse_u32, DecodeError, DefaultNla, Emitable, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

use crate::link::VlanProtocol;

const VLAN_FLAG_REORDER_HDR: u32 = 0x1;
const VLAN_FLAG_GVRP: u32 = 0x2;
const VLAN_FLAG_LOOSE_BINDING: u32 = 0x4;
const VLAN_FLAG_MVRP: u32 = 0x8;
const VLAN_FLAG_BRIDGE_BINDING: u32 = 0x10;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VlanFlags: u32 {
        /// Ethernet headers are reordered
        const ReorderHdr = VLAN_FLAG_REORDER_HDR;
        /// VLAN is registered using GARP VLAN Registration Protocol
        const Gvrp = VLAN_FLAG_GVRP;
        /// VLAN device state is bound to the physical device state
        const LooseBinding = VLAN_FLAG_LOOSE_BINDING;
        /// VLAN is be registered using Multiple VLAN Registration Protocol
        const Mvrp = VLAN_FLAG_MVRP;
        /// VLAN device link state tracks the state of bridge ports that are
        /// members of the VLAN
        const BridgeBinding = VLAN_FLAG_BRIDGE_BINDING;
        const _ = !0;
    }
}

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
    /// Active flags and flags mask
    Flags((VlanFlags, VlanFlags)),
    EgressQos(Vec<VlanQosMapping>),
    IngressQos(Vec<VlanQosMapping>),
    Protocol(VlanProtocol),
    Other(DefaultNla),
}

impl Nla for InfoVlan {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::EgressQos(ref mappings) | Self::IngressQos(ref mappings) => {
                (mappings).emit(out)?;
            }
            Self::Id(value) => append_u16(out, *value),
            Self::Protocol(value) => append_u16_be(out, (*value).into()),
            Self::Flags((active, mask)) => {
                append_u32(out, active.bits());
                append_u32(out, mask.bits());
            }
            Self::Other(v) => append_bytes(out, v.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => IFLA_VLAN_ID,
            Self::Flags(_) => IFLA_VLAN_FLAGS,
            Self::EgressQos(_) => IFLA_VLAN_EGRESS_QOS,
            Self::IngressQos(_) => IFLA_VLAN_INGRESS_QOS,
            Self::Protocol(_) => IFLA_VLAN_PROTOCOL,
            Self::Other(v) => v.kind(),
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
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Mapping(from, to) => {
                append_u32(out, *from);
                append_u32(out, *to);
            }
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            VlanQosMapping::Mapping { .. } => IFLA_VLAN_QOS_MAPPING,
            VlanQosMapping::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for VlanQosMapping {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VLAN_QOS_MAPPING => {
                if payload.len() != 8 {
                    return Err("invalid IFLA_VLAN_QOS_MAPPING value".into());
                }
                Self::Mapping(
                    parse_u32(&payload[..4])
                        .context("expected u32 from value")?,
                    parse_u32(&payload[4..])
                        .context("expected u32 to value")?,
                )
            }
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for VLAN QoS mapping")
            })?),
        })
    }
}

fn parse_mappings(
    buf: &NlaBuffer<'_>,
) -> Result<Vec<VlanQosMapping>, DecodeError> {
    let mut mappings = Vec::new();
    for nla in buf.nlas()? {
        let parsed = VlanQosMapping::parse(&nla)?;
        mappings.push(parsed);
    }
    Ok(mappings)
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoVlan {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VLAN_ID => Self::Id(
                parse_u16(payload).context("invalid IFLA_VLAN_ID value")?,
            ),
            IFLA_VLAN_FLAGS => {
                let err = "invalid IFLA_VLAN_FLAGS value";
                if payload.len() != 8 {
                    return Err(err.into());
                }
                let flags = parse_u32(&payload[0..4]).context(err)?;
                let mask = parse_u32(&payload[4..]).context(err)?;
                Self::Flags((
                    VlanFlags::from_bits_retain(flags),
                    VlanFlags::from_bits_retain(mask),
                ))
            }
            IFLA_VLAN_EGRESS_QOS => Self::EgressQos(
                parse_mappings(buf)
                    .context("failed to parse IFLA_VLAN_EGRESS_QOS")?,
            ),
            IFLA_VLAN_INGRESS_QOS => Self::IngressQos(
                parse_mappings(buf)
                    .context("failed to parse IFLA_VLAN_INGRESS_QOS")?,
            ),
            IFLA_VLAN_PROTOCOL => Self::Protocol(
                parse_u16_be(payload)
                    .context("invalid IFLA_VLAN_PROTOCOL value")?
                    .into(),
            ),
            _ => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("invalid NLA for {}: {payload:?}", buf.kind())
            })?),
        })
    }
}
