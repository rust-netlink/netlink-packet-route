// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::{
    append_bytes, append_u32, append_u32_be, parse_u16_be, parse_u32,
    parse_u32_be, parse_u8, DecodeError, DefaultNla, Emitable, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};

// `LWTUNNEL_IP_OPTS` and its `LWTUNNEL_IP6_OPTS` twin share the same
// attribute number.
pub(crate) const LWTUNNEL_IP_OPTS: u16 = 8;

const LWTUNNEL_IP_OPTS_GENEVE: u16 = 1;
const LWTUNNEL_IP_OPTS_VXLAN: u16 = 2;
const LWTUNNEL_IP_OPTS_ERSPAN: u16 = 3;

const LWTUNNEL_IP_OPT_GENEVE_CLASS: u16 = 1;
const LWTUNNEL_IP_OPT_GENEVE_TYPE: u16 = 2;
const LWTUNNEL_IP_OPT_GENEVE_DATA: u16 = 3;

const LWTUNNEL_IP_OPT_VXLAN_GBP: u16 = 1;

const LWTUNNEL_IP_OPT_ERSPAN_VER: u16 = 1;
const LWTUNNEL_IP_OPT_ERSPAN_INDEX: u16 = 2;
const LWTUNNEL_IP_OPT_ERSPAN_DIR: u16 = 3;
const LWTUNNEL_IP_OPT_ERSPAN_HWID: u16 = 4;

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// A single Geneve option of an `LWTUNNEL_IP_OPTS_GENEVE` attribute.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct RouteGeneveOpt {
    /// `LWTUNNEL_IP_OPT_GENEVE_CLASS`, the option class.
    pub class: u16,
    /// `LWTUNNEL_IP_OPT_GENEVE_TYPE`, the option type.
    pub typ: u8,
    /// `LWTUNNEL_IP_OPT_GENEVE_DATA`, the option data, its length is a
    /// multiple of 4 octets.
    pub data: Vec<u8>,
}

/// An attribute of `LWTUNNEL_IP_OPTS_ERSPAN`, the nested `erspan_opts` of
/// `encap ip` and `encap ip6`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteErspanOpt {
    /// `LWTUNNEL_IP_OPT_ERSPAN_VER`, the ERSPAN version.
    Ver(u8),
    /// `LWTUNNEL_IP_OPT_ERSPAN_INDEX`, the ERSPAN v1 session ID.
    Index(u32),
    /// `LWTUNNEL_IP_OPT_ERSPAN_DIR`, the ERSPAN v2 direction.
    Dir(u8),
    /// `LWTUNNEL_IP_OPT_ERSPAN_HWID`, the ERSPAN v2 hardware ID.
    Hwid(u8),
    Other(DefaultNla),
}

/// An attribute of `LWTUNNEL_IP_OPTS_VXLAN`, the nested `vxlan_opts` of
/// `encap ip` and `encap ip6`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteVxlanOpt {
    /// `LWTUNNEL_IP_OPT_VXLAN_GBP`, the VXLAN GBP.
    Gbp(u32),
    Other(DefaultNla),
}

/// A nested attribute of `LWTUNNEL_IP_OPTS`, which carries the `geneve_opts`,
/// `vxlan_opts` and `erspan_opts` options of `encap ip` and `encap ip6`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RouteLwTunnelOpt {
    /// An `LWTUNNEL_IP_OPTS_GENEVE` attribute, the kernel dumps all the
    /// Geneve options inside a single attribute while `iproute2` sends one
    /// attribute per option.
    Geneve(Vec<RouteGeneveOpt>),
    /// An `LWTUNNEL_IP_OPTS_VXLAN` attribute, the kernel only sends the
    /// VXLAN GBP inside it.
    Vxlan(Vec<RouteVxlanOpt>),
    /// An `LWTUNNEL_IP_OPTS_ERSPAN` attribute, its content depends on the
    /// ERSPAN version.
    Erspan(Vec<RouteErspanOpt>),
    Other(DefaultNla),
}

impl Nla for RouteVxlanOpt {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Gbp(gbp) => append_u32(out, *gbp),
            Self::Other(other) => append_bytes(out, other.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Gbp(_) => LWTUNNEL_IP_OPT_VXLAN_GBP,
            Self::Other(other) => other.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for RouteVxlanOpt {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            LWTUNNEL_IP_OPT_VXLAN_GBP => Self::Gbp(
                parse_u32(payload)
                    .context("Invalid LWTUNNEL_IP_OPT_VXLAN_GBP value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

impl Nla for RouteErspanOpt {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Ver(value) | Self::Dir(value) | Self::Hwid(value) => {
                out.push(*value)
            }
            Self::Index(index) => append_u32_be(out, *index),
            Self::Other(other) => append_bytes(out, other.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Ver(_) => LWTUNNEL_IP_OPT_ERSPAN_VER,
            Self::Index(_) => LWTUNNEL_IP_OPT_ERSPAN_INDEX,
            Self::Dir(_) => LWTUNNEL_IP_OPT_ERSPAN_DIR,
            Self::Hwid(_) => LWTUNNEL_IP_OPT_ERSPAN_HWID,
            Self::Other(other) => other.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for RouteErspanOpt {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            LWTUNNEL_IP_OPT_ERSPAN_VER => Self::Ver(
                parse_u8(payload)
                    .context("Invalid LWTUNNEL_IP_OPT_ERSPAN_VER value")?,
            ),
            LWTUNNEL_IP_OPT_ERSPAN_INDEX => Self::Index(
                parse_u32_be(payload)
                    .context("Invalid LWTUNNEL_IP_OPT_ERSPAN_INDEX value")?,
            ),
            LWTUNNEL_IP_OPT_ERSPAN_DIR => Self::Dir(
                parse_u8(payload)
                    .context("Invalid LWTUNNEL_IP_OPT_ERSPAN_DIR value")?,
            ),
            LWTUNNEL_IP_OPT_ERSPAN_HWID => Self::Hwid(
                parse_u8(payload)
                    .context("Invalid LWTUNNEL_IP_OPT_ERSPAN_HWID value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

impl std::fmt::Display for RouteLwTunnelOpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Geneve(opts) => {
                for (index, opt) in opts.iter().enumerate() {
                    if index > 0 {
                        write!(f, ",")?;
                    }
                    write!(
                        f,
                        "geneve_opts {}:{}:{}",
                        opt.class,
                        opt.typ,
                        hex_encode(&opt.data)
                    )?;
                }
                Ok(())
            }
            Self::Vxlan(opts) => {
                for (index, opt) in opts.iter().enumerate() {
                    if index > 0 {
                        write!(f, ",")?;
                    }
                    match opt {
                        RouteVxlanOpt::Gbp(gbp) => {
                            write!(f, "vxlan_opts {gbp}")?
                        }
                        RouteVxlanOpt::Other(other) => other.fmt(f)?,
                    }
                }
                Ok(())
            }
            Self::Erspan(opts) => {
                let mut ver = 0u8;
                let mut index = 0u32;
                let mut dir = 0u8;
                let mut hwid = 0u8;
                for opt in opts {
                    match opt {
                        RouteErspanOpt::Ver(v) => ver = *v,
                        RouteErspanOpt::Index(v) => index = *v,
                        RouteErspanOpt::Dir(v) => dir = *v,
                        RouteErspanOpt::Hwid(v) => hwid = *v,
                        RouteErspanOpt::Other(_) => (),
                    }
                }
                // `iproute2` only shows the ERSPAN v1 session ID or the
                // ERSPAN v2 direction and hardware ID.
                if ver == 1 {
                    write!(f, "erspan_opts {ver}:{index}:0:0")
                } else {
                    write!(f, "erspan_opts {ver}:0:{dir}:{hwid}")
                }
            }
            Self::Other(other) => other.fmt(f),
        }
    }
}

fn geneve_nlas(opts: &[RouteGeneveOpt]) -> Vec<DefaultNla> {
    let mut nlas = Vec::new();
    for opt in opts {
        nlas.push(DefaultNla::new(
            LWTUNNEL_IP_OPT_GENEVE_CLASS,
            opt.class.to_be_bytes().to_vec(),
        ));
        nlas.push(DefaultNla::new(LWTUNNEL_IP_OPT_GENEVE_TYPE, vec![opt.typ]));
        nlas.push(DefaultNla::new(
            LWTUNNEL_IP_OPT_GENEVE_DATA,
            opt.data.clone(),
        ));
    }
    nlas
}

impl Nla for RouteLwTunnelOpt {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Geneve(opts) => {
                geneve_nlas(opts).emit(out)?;
            }
            Self::Vxlan(opts) => (opts).emit(out)?,
            Self::Erspan(opts) => (opts).emit(out)?,
            Self::Other(other) => append_bytes(out, other.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Geneve(_) => LWTUNNEL_IP_OPTS_GENEVE | NLA_F_NESTED,
            Self::Vxlan(_) => LWTUNNEL_IP_OPTS_VXLAN | NLA_F_NESTED,
            Self::Erspan(_) => LWTUNNEL_IP_OPTS_ERSPAN | NLA_F_NESTED,
            Self::Other(other) => other.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for RouteLwTunnelOpt {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            LWTUNNEL_IP_OPTS_GENEVE => {
                let mut opts: Vec<RouteGeneveOpt> = Vec::new();
                let mut current: Option<RouteGeneveOpt> = None;
                for nla in buf
                    .nlas()
                    .context("Invalid LWTUNNEL_IP_OPTS_GENEVE value")?
                {
                    match nla.kind() {
                        LWTUNNEL_IP_OPT_GENEVE_CLASS => {
                            if let Some(opt) = current.take() {
                                opts.push(opt);
                            }
                            current = Some(RouteGeneveOpt {
                                class: parse_u16_be(nla.value()).context(
                                    "Invalid LWTUNNEL_IP_OPT_GENEVE_CLASS \
                                     value",
                                )?,
                                ..Default::default()
                            });
                        }
                        LWTUNNEL_IP_OPT_GENEVE_TYPE => {
                            let opt = current.as_mut().ok_or_else(|| {
                                DecodeError::from(
                                    "LWTUNNEL_IP_OPT_GENEVE_TYPE without \
                                     LWTUNNEL_IP_OPT_GENEVE_CLASS",
                                )
                            })?;
                            opt.typ = parse_u8(nla.value()).context(
                                "Invalid LWTUNNEL_IP_OPT_GENEVE_TYPE value",
                            )?;
                        }
                        LWTUNNEL_IP_OPT_GENEVE_DATA => {
                            let opt = current.as_mut().ok_or_else(|| {
                                DecodeError::from(
                                    "LWTUNNEL_IP_OPT_GENEVE_DATA without \
                                     LWTUNNEL_IP_OPT_GENEVE_CLASS",
                                )
                            })?;
                            opt.data = nla.value().to_vec();
                        }
                        kind => {
                            return Err(DecodeError::from(format!(
                                "Unknown LWTUNNEL_IP_OPTS_GENEVE child {kind}"
                            )));
                        }
                    }
                }
                if let Some(opt) = current.take() {
                    opts.push(opt);
                }
                Self::Geneve(opts)
            }
            LWTUNNEL_IP_OPTS_VXLAN => {
                let mut opts: Vec<RouteVxlanOpt> = Vec::new();
                for nla in buf
                    .nlas()
                    .context("Invalid LWTUNNEL_IP_OPTS_VXLAN value")?
                {
                    opts.push(RouteVxlanOpt::parse(&nla)?);
                }
                Self::Vxlan(opts)
            }
            LWTUNNEL_IP_OPTS_ERSPAN => {
                let mut opts: Vec<RouteErspanOpt> = Vec::new();
                for nla in buf
                    .nlas()
                    .context("Invalid LWTUNNEL_IP_OPTS_ERSPAN value")?
                {
                    opts.push(RouteErspanOpt::parse(&nla)?);
                }
                Self::Erspan(opts)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
