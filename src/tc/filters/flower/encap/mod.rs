use anyhow::Context;
use netlink_packet_utils::nla::{DefaultNla, Nla, NlaBuffer, NlasIterator};
use netlink_packet_utils::{DecodeError, Emitable, Parseable};

pub mod erspan;
pub mod geneve;
pub mod gtp;
pub mod vxlan;

const TCA_FLOWER_KEY_ENC_OPTS_GENEVE: u16 = 1;
const TCA_FLOWER_KEY_ENC_OPTS_VXLAN: u16 = 2;
const TCA_FLOWER_KEY_ENC_OPTS_ERSPAN: u16 = 3;
const TCA_FLOWER_KEY_ENC_OPTS_GTP: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Options {
    Geneve(Vec<geneve::Options>),
    Vxlan(Vec<vxlan::Options>),
    Erspan(Vec<erspan::Options>),
    Gtp(Vec<gtp::Options>),
    Other(DefaultNla),
}

impl Nla for Options {
    fn value_len(&self) -> usize {
        match self {
            Self::Geneve(opts) => opts.as_slice().buffer_len(),
            Self::Vxlan(opts) => opts.as_slice().buffer_len(),
            Self::Erspan(opts) => opts.as_slice().buffer_len(),
            Self::Gtp(opts) => opts.as_slice().buffer_len(),
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Geneve(_) => TCA_FLOWER_KEY_ENC_OPTS_GENEVE,
            Self::Vxlan(_) => TCA_FLOWER_KEY_ENC_OPTS_VXLAN,
            Self::Erspan(_) => TCA_FLOWER_KEY_ENC_OPTS_ERSPAN,
            Self::Gtp(_) => TCA_FLOWER_KEY_ENC_OPTS_GTP,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Geneve(opts) => opts.as_slice().emit(buffer),
            Self::Vxlan(opts) => opts.as_slice().emit(buffer),
            Self::Erspan(opts) => opts.as_slice().emit(buffer),
            Self::Gtp(opts) => opts.as_slice().emit(buffer),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Options {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            crate::tc::filters::cls_flower::TCA_FLOWER_KEY_ENC_OPTS => {
                let nested = NlaBuffer::new_checked(buf.value())
                    .context("failed to parse encap opts")?;
                parse_enc_opts(&nested)?
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

/// # Errors
/// Returns `DecodeError` if the NLA is not a valid `EncOpts` NLA.
pub(crate) fn parse_enc_opts<T: AsRef<[u8]> + ?Sized>(
    buf: &NlaBuffer<&T>,
) -> Result<Options, DecodeError> {
    Ok(match buf.kind() {
        TCA_FLOWER_KEY_ENC_OPTS_GENEVE => Options::Geneve(
            NlasIterator::new(buf.value())
                .map(|nla| {
                    let nla =
                        nla.context("failed to parse geneve encap opt")?;
                    geneve::Options::parse(&nla)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        TCA_FLOWER_KEY_ENC_OPTS_VXLAN => Options::Vxlan(
            NlasIterator::new(buf.value())
                .map(|nla| {
                    let nla = nla.context("failed to parse vxlan encap opt")?;
                    vxlan::Options::parse(&nla)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        TCA_FLOWER_KEY_ENC_OPTS_ERSPAN => Options::Erspan(
            NlasIterator::new(buf.value())
                .map(|nla| {
                    let nla =
                        nla.context("failed to parse erspan encap opt")?;
                    erspan::Options::parse(&nla)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        TCA_FLOWER_KEY_ENC_OPTS_GTP => Options::Gtp(
            NlasIterator::new(buf.value())
                .map(|nla| {
                    let nla = nla.context("failed to parse gtp encap opt")?;
                    gtp::Options::parse(&nla)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        _ => Options::Other(DefaultNla::parse(buf)?),
    })
}

impl From<geneve::Option> for Options {
    fn from(opt: geneve::Option) -> Self {
        Options::Geneve(opt.into())
    }
}

impl From<geneve::Option> for Vec<Options> {
    fn from(opt: geneve::Option) -> Self {
        vec![Options::Geneve(opt.into())]
    }
}

impl From<vxlan::Gpb> for Options {
    fn from(gpb: vxlan::Gpb) -> Self {
        Options::Vxlan(vec![vxlan::Options::Gpb(gpb)])
    }
}

impl From<vxlan::Gpb> for Vec<Options> {
    fn from(gpb: vxlan::Gpb) -> Self {
        vec![Options::Vxlan(vec![vxlan::Options::Gpb(gpb)])]
    }
}
