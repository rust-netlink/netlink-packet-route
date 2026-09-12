// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::{
    parse_u16_be, parse_u32, parse_u32_be, parse_u8, DecodeError, DefaultNla,
    Emitable, ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
    NLA_F_NESTED,
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

/// The `LWTUNNEL_IP_OPTS_ERSPAN` options.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct RouteErspanOpt {
    /// `LWTUNNEL_IP_OPT_ERSPAN_VER`, the ERSPAN version.
    pub ver: u8,
    /// `LWTUNNEL_IP_OPT_ERSPAN_INDEX`, the ERSPAN v1 session ID.
    pub index: Option<u32>,
    /// `LWTUNNEL_IP_OPT_ERSPAN_DIR`, the ERSPAN v2 direction.
    pub dir: Option<u8>,
    /// `LWTUNNEL_IP_OPT_ERSPAN_HWID`, the ERSPAN v2 hardware ID.
    pub hwid: Option<u8>,
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
    /// An `LWTUNNEL_IP_OPTS_VXLAN` attribute carrying the VXLAN GBP.
    Vxlan(u32),
    /// An `LWTUNNEL_IP_OPTS_ERSPAN` attribute.
    Erspan(RouteErspanOpt),
    Other(DefaultNla),
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
            Self::Vxlan(gbp) => write!(f, "vxlan_opts {gbp}"),
            Self::Erspan(opt) => {
                // `iproute2` only shows the ERSPAN v1 session ID or the
                // ERSPAN v2 direction and hardware ID.
                let (index, dir, hwid) = if opt.ver == 1 {
                    (opt.index.unwrap_or(0), 0, 0)
                } else {
                    (0, opt.dir.unwrap_or(0), opt.hwid.unwrap_or(0))
                };
                write!(f, "erspan_opts {}:{}:{}:{}", opt.ver, index, dir, hwid)
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

fn vxlan_nlas(gbp: u32) -> Vec<DefaultNla> {
    vec![DefaultNla::new(
        LWTUNNEL_IP_OPT_VXLAN_GBP,
        gbp.to_ne_bytes().to_vec(),
    )]
}

fn erspan_nlas(opt: &RouteErspanOpt) -> Vec<DefaultNla> {
    let mut nlas =
        vec![DefaultNla::new(LWTUNNEL_IP_OPT_ERSPAN_VER, vec![opt.ver])];
    if let Some(index) = opt.index {
        nlas.push(DefaultNla::new(
            LWTUNNEL_IP_OPT_ERSPAN_INDEX,
            index.to_be_bytes().to_vec(),
        ));
    }
    if let Some(dir) = opt.dir {
        nlas.push(DefaultNla::new(LWTUNNEL_IP_OPT_ERSPAN_DIR, vec![dir]));
    }
    if let Some(hwid) = opt.hwid {
        nlas.push(DefaultNla::new(LWTUNNEL_IP_OPT_ERSPAN_HWID, vec![hwid]));
    }
    nlas
}

impl Nla for RouteLwTunnelOpt {
    fn value_len(&self) -> usize {
        match self {
            Self::Geneve(opts) => geneve_nlas(opts).as_slice().buffer_len(),
            Self::Vxlan(gbp) => vxlan_nlas(*gbp).as_slice().buffer_len(),
            Self::Erspan(opt) => erspan_nlas(opt).as_slice().buffer_len(),
            Self::Other(other) => other.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            // The kernel validates these attributes with `nla_parse_nested()`
            // which requires the `NLA_F_NESTED` flag.
            Self::Geneve(_) => LWTUNNEL_IP_OPTS_GENEVE | NLA_F_NESTED,
            Self::Vxlan(_) => LWTUNNEL_IP_OPTS_VXLAN | NLA_F_NESTED,
            Self::Erspan(_) => LWTUNNEL_IP_OPTS_ERSPAN | NLA_F_NESTED,
            Self::Other(other) => other.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Geneve(opts) => geneve_nlas(opts).as_slice().emit(buffer),
            Self::Vxlan(gbp) => vxlan_nlas(*gbp).as_slice().emit(buffer),
            Self::Erspan(opt) => erspan_nlas(opt).as_slice().emit(buffer),
            Self::Other(other) => other.emit_value(buffer),
        }
    }
}

impl<'a, T> Parseable<NlaBuffer<&'a T>> for RouteLwTunnelOpt
where
    T: AsRef<[u8]> + ?Sized,
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            LWTUNNEL_IP_OPTS_GENEVE => {
                let mut opts: Vec<RouteGeneveOpt> = Vec::new();
                let mut current: Option<RouteGeneveOpt> = None;
                for nla in NlasIterator::new(payload) {
                    let nla =
                        nla.context("Invalid LWTUNNEL_IP_OPTS_GENEVE value")?;
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
                let mut gbp: Option<u32> = None;
                for nla in NlasIterator::new(payload) {
                    let nla =
                        nla.context("Invalid LWTUNNEL_IP_OPTS_VXLAN value")?;
                    if nla.kind() == LWTUNNEL_IP_OPT_VXLAN_GBP {
                        gbp = Some(parse_u32(nla.value()).context(
                            "Invalid LWTUNNEL_IP_OPT_VXLAN_GBP value",
                        )?);
                    }
                }
                Self::Vxlan(gbp.ok_or_else(|| {
                    DecodeError::from("Missing LWTUNNEL_IP_OPT_VXLAN_GBP value")
                })?)
            }
            LWTUNNEL_IP_OPTS_ERSPAN => {
                let mut opt = RouteErspanOpt::default();
                for nla in NlasIterator::new(payload) {
                    let nla =
                        nla.context("Invalid LWTUNNEL_IP_OPTS_ERSPAN value")?;
                    match nla.kind() {
                        LWTUNNEL_IP_OPT_ERSPAN_VER => {
                            opt.ver = parse_u8(nla.value()).context(
                                "Invalid LWTUNNEL_IP_OPT_ERSPAN_VER value",
                            )?;
                        }
                        LWTUNNEL_IP_OPT_ERSPAN_INDEX => {
                            opt.index =
                                Some(parse_u32_be(nla.value()).context(
                                    "Invalid LWTUNNEL_IP_OPT_ERSPAN_INDEX \
                                     value",
                                )?);
                        }
                        LWTUNNEL_IP_OPT_ERSPAN_DIR => {
                            opt.dir = Some(parse_u8(nla.value()).context(
                                "Invalid LWTUNNEL_IP_OPT_ERSPAN_DIR value",
                            )?);
                        }
                        LWTUNNEL_IP_OPT_ERSPAN_HWID => {
                            opt.hwid = Some(parse_u8(nla.value()).context(
                                "Invalid LWTUNNEL_IP_OPT_ERSPAN_HWID value",
                            )?);
                        }
                        kind => {
                            return Err(DecodeError::from(format!(
                                "Unknown LWTUNNEL_IP_OPTS_ERSPAN child {kind}"
                            )));
                        }
                    }
                }
                Self::Erspan(opt)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
