// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16_be, parse_u32, parse_u8},
    traits::Parseable,
    DecodeError,
};

const IFLA_VXLAN_UNSPEC: u16 = 0;
const IFLA_VXLAN_ID: u16 = 1;
const IFLA_VXLAN_GROUP: u16 = 2;
const IFLA_VXLAN_LINK: u16 = 3;
const IFLA_VXLAN_LOCAL: u16 = 4;
const IFLA_VXLAN_TTL: u16 = 5;
const IFLA_VXLAN_TOS: u16 = 6;
const IFLA_VXLAN_LEARNING: u16 = 7;
const IFLA_VXLAN_AGEING: u16 = 8;
const IFLA_VXLAN_LIMIT: u16 = 9;
const IFLA_VXLAN_PORT_RANGE: u16 = 10;
const IFLA_VXLAN_PROXY: u16 = 11;
const IFLA_VXLAN_RSC: u16 = 12;
const IFLA_VXLAN_L2MISS: u16 = 13;
const IFLA_VXLAN_L3MISS: u16 = 14;
const IFLA_VXLAN_PORT: u16 = 15;
const IFLA_VXLAN_GROUP6: u16 = 16;
const IFLA_VXLAN_LOCAL6: u16 = 17;
const IFLA_VXLAN_UDP_CSUM: u16 = 18;
const IFLA_VXLAN_UDP_ZERO_CSUM6_TX: u16 = 19;
const IFLA_VXLAN_UDP_ZERO_CSUM6_RX: u16 = 20;
const IFLA_VXLAN_REMCSUM_TX: u16 = 21;
const IFLA_VXLAN_REMCSUM_RX: u16 = 22;
const IFLA_VXLAN_GBP: u16 = 23;
const IFLA_VXLAN_REMCSUM_NOPARTIAL: u16 = 24;
const IFLA_VXLAN_COLLECT_METADATA: u16 = 25;
const IFLA_VXLAN_LABEL: u16 = 26;
const IFLA_VXLAN_GPE: u16 = 27;
const IFLA_VXLAN_TTL_INHERIT: u16 = 28;
const IFLA_VXLAN_DF: u16 = 29;
const __IFLA_VXLAN_MAX: u16 = 30;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoVxlan {
    Unspec(Vec<u8>),
    Id(u32),
    Group(Vec<u8>),
    Group6(Vec<u8>),
    Link(u32),
    Local(Vec<u8>),
    Local6(Vec<u8>),
    Tos(u8),
    Ttl(u8),
    Label(u32),
    Learning(u8),
    Ageing(u32),
    Limit(u32),
    PortRange((u16, u16)),
    Proxy(u8),
    Rsc(u8),
    L2Miss(u8),
    L3Miss(u8),
    CollectMetadata(u8),
    Port(u16),
    UDPCsum(u8),
    UDPZeroCsumTX(u8),
    UDPZeroCsumRX(u8),
    RemCsumTX(u8),
    RemCsumRX(u8),
    Gbp(u8),
    Gpe(u8),
    RemCsumNoPartial(u8),
    TtlInherit(u8),
    Df(u8),
    Other(DefaultNla),
}

impl Nla for InfoVxlan {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::InfoVxlan::*;
        match *self {
            Tos(_)
                | Ttl(_)
                | Learning(_)
                | Proxy(_)
                | Rsc(_)
                | L2Miss(_)
                | L3Miss(_)
                | CollectMetadata(_)
                | UDPCsum(_)
                | UDPZeroCsumTX(_)
                | UDPZeroCsumRX(_)
                | RemCsumTX(_)
                | RemCsumRX(_)
                | Gbp(_)
                | Gpe(_)
                | RemCsumNoPartial(_)
                | TtlInherit(_)
                | Df(_)
            => 1,
            Port(_) => 2,
            Id(_)
                | Label(_)
                | Link(_)
                | Ageing(_)
                | Limit(_)
                | PortRange(_)
            => 4,
            Local(ref bytes)
                | Local6(ref bytes)
                | Group(ref bytes)
                | Group6(ref bytes)
                | Unspec(ref bytes)
            => bytes.len(),
            Other(ref nla) => nla.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoVxlan::*;
        match self {
            Unspec(ref bytes) => buffer.copy_from_slice(bytes),
            Id(ref value)
                | Label(ref value)
                | Link(ref value)
                | Ageing(ref value)
                | Limit(ref value)
            => NativeEndian::write_u32(buffer, *value),
            Tos(ref value)
                | Ttl(ref value)
                | Learning (ref value)
                | Proxy(ref value)
                | Rsc(ref value)
                | L2Miss(ref value)
                | L3Miss(ref value)
                | CollectMetadata(ref value)
                | UDPCsum(ref value)
                | UDPZeroCsumTX(ref value)
                | UDPZeroCsumRX(ref value)
                | RemCsumTX(ref value)
                | RemCsumRX(ref value)
                | Gbp(ref value)
                | Gpe(ref value)
                | RemCsumNoPartial(ref value)
                | TtlInherit(ref value)
                | Df(ref value)
            =>  buffer[0] = *value,
            Local(ref value)
                | Group(ref value)
                | Group6(ref value)
                | Local6(ref value)
            => buffer.copy_from_slice(value.as_slice()),
            Port(ref value) => BigEndian::write_u16(buffer, *value),
            PortRange(ref range) => {
                BigEndian::write_u16(buffer, range.0);
                BigEndian::write_u16(&mut buffer[2..], range.1)
            }
            Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoVxlan::*;

        match self {
            Id(_) => IFLA_VXLAN_ID,
            Group(_) => IFLA_VXLAN_GROUP,
            Group6(_) => IFLA_VXLAN_GROUP6,
            Link(_) => IFLA_VXLAN_LINK,
            Local(_) => IFLA_VXLAN_LOCAL,
            Local6(_) => IFLA_VXLAN_LOCAL6,
            Tos(_) => IFLA_VXLAN_TOS,
            Ttl(_) => IFLA_VXLAN_TTL,
            Label(_) => IFLA_VXLAN_LABEL,
            Learning(_) => IFLA_VXLAN_LEARNING,
            Ageing(_) => IFLA_VXLAN_AGEING,
            Limit(_) => IFLA_VXLAN_LIMIT,
            PortRange(_) => IFLA_VXLAN_PORT_RANGE,
            Proxy(_) => IFLA_VXLAN_PROXY,
            Rsc(_) => IFLA_VXLAN_RSC,
            L2Miss(_) => IFLA_VXLAN_L2MISS,
            L3Miss(_) => IFLA_VXLAN_L3MISS,
            CollectMetadata(_) => IFLA_VXLAN_COLLECT_METADATA,
            Port(_) => IFLA_VXLAN_PORT,
            UDPCsum(_) => IFLA_VXLAN_UDP_CSUM,
            UDPZeroCsumTX(_) => IFLA_VXLAN_UDP_ZERO_CSUM6_TX,
            UDPZeroCsumRX(_) => IFLA_VXLAN_UDP_ZERO_CSUM6_RX,
            RemCsumTX(_) => IFLA_VXLAN_REMCSUM_TX,
            RemCsumRX(_) => IFLA_VXLAN_REMCSUM_RX,
            Gbp(_) => IFLA_VXLAN_GBP,
            Gpe(_) => IFLA_VXLAN_GPE,
            RemCsumNoPartial(_) => IFLA_VXLAN_REMCSUM_NOPARTIAL,
            TtlInherit(_) => IFLA_VXLAN_TTL_INHERIT,
            Df(_) => IFLA_VXLAN_DF,
            Unspec(_) => IFLA_VXLAN_UNSPEC,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoVxlan {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoVxlan::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_VXLAN_UNSPEC => Unspec(payload.to_vec()),
            IFLA_VXLAN_ID => {
                Id(parse_u32(payload).context("invalid IFLA_VXLAN_ID value")?)
            }
            IFLA_VXLAN_GROUP => Group(payload.to_vec()),
            IFLA_VXLAN_GROUP6 => Group6(payload.to_vec()),
            IFLA_VXLAN_LINK => Link(
                parse_u32(payload).context("invalid IFLA_VXLAN_LINK value")?,
            ),
            IFLA_VXLAN_LOCAL => Local(payload.to_vec()),
            IFLA_VXLAN_LOCAL6 => Local6(payload.to_vec()),
            IFLA_VXLAN_TOS => {
                Tos(parse_u8(payload)
                    .context("invalid IFLA_VXLAN_TOS value")?)
            }
            IFLA_VXLAN_TTL => {
                Ttl(parse_u8(payload)
                    .context("invalid IFLA_VXLAN_TTL value")?)
            }
            IFLA_VXLAN_LABEL => Label(
                parse_u32(payload).context("invalid IFLA_VXLAN_LABEL value")?,
            ),
            IFLA_VXLAN_LEARNING => Learning(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_LEARNING value")?,
            ),
            IFLA_VXLAN_AGEING => Ageing(
                parse_u32(payload)
                    .context("invalid IFLA_VXLAN_AGEING value")?,
            ),
            IFLA_VXLAN_LIMIT => Limit(
                parse_u32(payload).context("invalid IFLA_VXLAN_LIMIT value")?,
            ),
            IFLA_VXLAN_PROXY => Proxy(
                parse_u8(payload).context("invalid IFLA_VXLAN_PROXY value")?,
            ),
            IFLA_VXLAN_RSC => {
                Rsc(parse_u8(payload)
                    .context("invalid IFLA_VXLAN_RSC value")?)
            }
            IFLA_VXLAN_L2MISS => L2Miss(
                parse_u8(payload).context("invalid IFLA_VXLAN_L2MISS value")?,
            ),
            IFLA_VXLAN_L3MISS => L3Miss(
                parse_u8(payload).context("invalid IFLA_VXLAN_L3MISS value")?,
            ),
            IFLA_VXLAN_COLLECT_METADATA => CollectMetadata(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_COLLECT_METADATA value")?,
            ),
            IFLA_VXLAN_PORT_RANGE => {
                let err = "invalid IFLA_VXLAN_PORT value";
                if payload.len() != 4 {
                    return Err(err.into());
                }
                let low = parse_u16_be(&payload[0..2]).context(err)?;
                let high = parse_u16_be(&payload[2..]).context(err)?;
                PortRange((low, high))
            }
            IFLA_VXLAN_PORT => Port(
                parse_u16_be(payload)
                    .context("invalid IFLA_VXLAN_PORT value")?,
            ),
            IFLA_VXLAN_UDP_CSUM => UDPCsum(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_UDP_CSUM value")?,
            ),
            IFLA_VXLAN_UDP_ZERO_CSUM6_TX => UDPZeroCsumTX(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_UDP_ZERO_CSUM6_TX value")?,
            ),
            IFLA_VXLAN_UDP_ZERO_CSUM6_RX => UDPZeroCsumRX(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_UDP_ZERO_CSUM6_RX value")?,
            ),
            IFLA_VXLAN_REMCSUM_TX => RemCsumTX(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_REMCSUM_TX value")?,
            ),
            IFLA_VXLAN_REMCSUM_RX => RemCsumRX(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_REMCSUM_RX value")?,
            ),
            IFLA_VXLAN_DF => {
                Df(parse_u8(payload).context("invalid IFLA_VXLAN_DF value")?)
            }
            IFLA_VXLAN_GBP => {
                Gbp(parse_u8(payload)
                    .context("invalid IFLA_VXLAN_GBP value")?)
            }
            IFLA_VXLAN_GPE => {
                Gpe(parse_u8(payload)
                    .context("invalid IFLA_VXLAN_GPE value")?)
            }
            IFLA_VXLAN_REMCSUM_NOPARTIAL => RemCsumNoPartial(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_REMCSUM_NO_PARTIAL")?,
            ),
            IFLA_VXLAN_TTL_INHERIT => TtlInherit(
                parse_u8(payload)
                    .context("invalid IFLA_VXLAN_TTL_INHERIT value")?,
            ),
            __IFLA_VXLAN_MAX => Unspec(payload.to_vec()),
            unknown_kind => Other(DefaultNla::parse(buf).context(format!(
                "Failed to parse IFLA_INFO_DATA(vxlan) NLA type: {unknown_kind} as DefaultNla"
            ))?),
        })
    }
}
