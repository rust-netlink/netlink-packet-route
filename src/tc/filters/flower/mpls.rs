use netlink_packet_utils::nla::{
    DefaultNla, Nla, NlaBuffer, NlasIterator, NLA_F_NESTED,
};
use netlink_packet_utils::parsers::{parse_u32, parse_u8};
use netlink_packet_utils::{DecodeError, Emitable, Parseable};

use crate::net::mpls;
use crate::tc::filters::cls_flower::TCA_FLOWER_KEY_MPLS_OPTS;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Options {
    Lses(Vec<LseFilter>),
    Unknown(DefaultNla),
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum LseOptions {
    Depth(u8),
    Label(mpls::Label),
    TrafficClass(mpls::TrafficClass),
    BottomOfStack(mpls::BottomOfStack),
    Ttl(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Ord, PartialOrd, Hash)]
pub struct LseFilter {
    pub depth: u8, // TODO: consider making this NonZeroU8
    pub label: Option<mpls::Label>,
    pub traffic_class: Option<mpls::TrafficClass>,
    pub bottom_of_stack: Option<mpls::BottomOfStack>,
    pub ttl: Option<u8>,
}

impl Default for LseFilter {
    fn default() -> Self {
        Self {
            depth: 1,
            label: None,
            traffic_class: None,
            bottom_of_stack: None,
            ttl: None,
        }
    }
}

impl From<&LseFilter> for Vec<LseOptions> {
    fn from(lse: &LseFilter) -> Vec<LseOptions> {
        let mut opts = Vec::new();
        opts.push(LseOptions::Depth(lse.depth));
        if let Some(label) = lse.label {
            opts.push(LseOptions::Label(label));
        }
        if let Some(traffic_class) = lse.traffic_class {
            opts.push(LseOptions::TrafficClass(traffic_class));
        }
        if let Some(bottom_of_stack) = lse.bottom_of_stack {
            opts.push(LseOptions::BottomOfStack(bottom_of_stack));
        }
        if let Some(ttl) = lse.ttl {
            opts.push(LseOptions::Ttl(ttl));
        }
        opts
    }
}

impl TryFrom<Vec<LseOptions>> for LseFilter {
    type Error = DecodeError;

    fn try_from(value: Vec<LseOptions>) -> Result<Self, Self::Error> {
        let depths = value
            .iter()
            .filter_map(|opt| match opt {
                LseOptions::Depth(depth) => Some(depth),
                _ => None,
            })
            .collect::<Vec<_>>();
        if depths.len() > 1 {
            return Err(DecodeError::from("multiple depth options"));
        }
        let depth = match depths.first() {
            Some(depth) => **depth,
            None => return Err(DecodeError::from("missing depth option")),
        };
        let mut labels = value.iter().filter_map(|opt| match opt {
            LseOptions::Label(label) => Some(*label),
            _ => None,
        });
        let label = labels.next();
        if labels.next().is_some() {
            return Err(DecodeError::from("multiple label options"));
        }
        let mut traffic_classes = value.iter().filter_map(|opt| match opt {
            LseOptions::TrafficClass(tc) => Some(*tc),
            _ => None,
        });
        let traffic_class = traffic_classes.next();
        if traffic_classes.next().is_some() {
            return Err(DecodeError::from("multiple traffic class options"));
        };
        let mut bottom_of_stacks = value.iter().filter_map(|opt| match opt {
            LseOptions::BottomOfStack(bos) => Some(*bos),
            _ => None,
        });
        let bottom_of_stack = bottom_of_stacks.next();
        if bottom_of_stacks.next().is_some() {
            return Err(DecodeError::from("multiple bottom of stack options"));
        };
        let mut ttls = value.iter().filter_map(|opt| match opt {
            LseOptions::Ttl(ttl) => Some(*ttl),
            _ => None,
        });
        let ttl = ttls.next();
        if ttls.next().is_some() {
            return Err(DecodeError::from("multiple ttl options"));
        };
        Ok(LseFilter {
            depth,
            label,
            traffic_class,
            bottom_of_stack,
            ttl,
        })
    }
}

impl Nla for LseFilter {
    fn value_len(&self) -> usize {
        Vec::from(self).as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_MPLS_OPTS_LSE | NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        Vec::from(self).as_slice().emit(buffer);
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for LseFilter {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        NlasIterator::new(payload)
            .map(|nla| LseOptions::parse(&nla?))
            .collect::<Result<Vec<_>, _>>()
            .map(LseFilter::try_from)?
    }
}

impl From<LseFilter> for Vec<LseOptions> {
    fn from(lse: LseFilter) -> Self {
        let mut opts = Vec::with_capacity(5);
        opts.push(LseOptions::Depth(lse.depth));
        if let Some(label) = lse.label {
            opts.push(LseOptions::Label(label));
        }
        if let Some(traffic_class) = lse.traffic_class {
            opts.push(LseOptions::TrafficClass(traffic_class));
        }
        if let Some(bottom_of_stack) = lse.bottom_of_stack {
            opts.push(LseOptions::BottomOfStack(bottom_of_stack));
        }
        if let Some(ttl) = lse.ttl {
            opts.push(LseOptions::Ttl(ttl));
        }
        opts
    }
}

const TCA_FLOWER_KEY_MPLS_OPTS_LSE: u16 = 1;

const TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH: u16 = 1;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL: u16 = 2;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS: u16 = 3;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_TC: u16 = 4;
const TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL: u16 = 5;

impl Nla for LseOptions {
    fn value_len(&self) -> usize {
        match self {
            LseOptions::Depth(_)
            | LseOptions::Ttl(_)
            | LseOptions::BottomOfStack(_)
            | LseOptions::TrafficClass(_) => 1,
            LseOptions::Label(_) => 4,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            LseOptions::Depth(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH,
            LseOptions::Ttl(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL,
            LseOptions::BottomOfStack(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS,
            LseOptions::TrafficClass(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_TC,
            LseOptions::Label(_) => TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            LseOptions::Depth(depth) => {
                buffer.copy_from_slice(&depth.to_ne_bytes());
            }
            LseOptions::Ttl(ttl) => {
                buffer.copy_from_slice(&ttl.to_ne_bytes());
            }
            LseOptions::BottomOfStack(bos) => {
                buffer.copy_from_slice(&u8::from(*bos).to_ne_bytes());
            }
            LseOptions::TrafficClass(tc) => {
                buffer.copy_from_slice(&tc.as_ref().to_ne_bytes());
            }
            LseOptions::Label(label) => {
                buffer.copy_from_slice(&u32::from(*label).to_ne_bytes());
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for LseOptions {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH => {
                Self::Depth(parse_u8(payload)?)
            }
            TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL => Self::Ttl(parse_u8(payload)?),
            TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS => Self::BottomOfStack(
                mpls::BottomOfStack::from(parse_u8(payload)?),
            ),
            TCA_FLOWER_KEY_MPLS_OPT_LSE_TC => {
                Self::TrafficClass(mpls::TrafficClass::new(parse_u8(payload)?)?)
            }
            TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL => {
                Self::Label(mpls::Label::try_from(parse_u32(payload)?)?)
            }
            _ => Err(DecodeError::from("invalid mpls option kind"))?,
        })
    }
}

impl Nla for Options {
    fn value_len(&self) -> usize {
        match self {
            Options::Lses(lses) => lses.as_slice().buffer_len(),
            Options::Unknown(unknown) => unknown.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_MPLS_OPTS | NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Options::Lses(lses) => lses.as_slice().emit(buffer),
            Options::Unknown(unknown) => unknown.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Options {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        NlasIterator::new(payload)
            .map(|nla| {
                let nla = nla?;
                LseFilter::parse(&nla)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self::Lses)
    }
}

impl From<Vec<LseFilter>> for Options {
    fn from(value: Vec<LseFilter>) -> Self {
        Self::Lses(value)
    }
}
