// SPDX-License-Identifier: MIT

use super::{
    TcActionMirror, TcActionMirrorOption, TcActionNat, TcActionNatOption,
};
use crate::tc::{TcError, TcStats2};
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_string, parse_u32},
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

const TCA_ACT_TAB: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcAction {
    pub tab: u16,
    pub attributes: Vec<TcActionAttribute>,
}

impl Default for TcAction {
    fn default() -> Self {
        Self {
            tab: TCA_ACT_TAB,
            attributes: Vec::new(),
        }
    }
}

impl Nla for TcAction {
    fn value_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn kind(&self) -> u16 {
        self.tab
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TcAction {
    type Error = TcError;
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, TcError> {
        let mut attributes = vec![];
        let mut kind = String::new();

        for iter in NlasIterator::new(buf.value()) {
            let buf = iter?;
            let payload = buf.value();
            attributes.push(match buf.kind() {
                TCA_ACT_KIND => {
                    kind = parse_string(payload).map_err(|error| {
                        TcError::ParseAction {
                            kind: "TCA_ACT_KIND",
                            error,
                        }
                    })?;
                    TcActionAttribute::Kind(kind.clone())
                }
                TCA_ACT_OPTIONS => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(payload) {
                        let nla = nla?;
                        nlas.push(TcActionOption::parse_with_param(
                            &nla, &kind,
                        )?);
                    }
                    TcActionAttribute::Options(nlas)
                }
                TCA_ACT_INDEX => {
                    TcActionAttribute::Index(parse_u32(payload).map_err(
                        |error| TcError::ParseAction {
                            kind: "TCA_ACT_INDEX",
                            error,
                        },
                    )?)
                }
                TCA_ACT_STATS => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(payload) {
                        let nla = nla?;
                        nlas.push(TcStats2::parse_with_param(&nla, &kind)?);
                    }
                    TcActionAttribute::Stats(nlas)
                }
                TCA_ACT_COOKIE => TcActionAttribute::Cookie(payload.to_vec()),
                TCA_ACT_IN_HW_COUNT => {
                    TcActionAttribute::InHwCount(parse_u32(payload).map_err(
                        |error| TcError::ParseAction {
                            kind: "TCA_ACT_IN_HW_COUNT",
                            error,
                        },
                    )?)
                }
                kind => TcActionAttribute::Other(
                    DefaultNla::parse(&buf)
                        .map_err(|error| TcError::UnknownNla { kind, error })?,
                ),
            });
        }
        Ok(Self {
            tab: buf.kind(),
            attributes,
        })
    }
}

const TCA_ACT_KIND: u16 = 1;
const TCA_ACT_OPTIONS: u16 = 2;
const TCA_ACT_INDEX: u16 = 3;
const TCA_ACT_STATS: u16 = 4;
// const TCA_ACT_PAD: u16 = 5;
const TCA_ACT_COOKIE: u16 = 6;
// const TCA_ACT_FLAGS: u16 = 7;
// const TCA_ACT_HW_STATS: u16 = 8;
// const TCA_ACT_USED_HW_STATS: u16 = 9;
const TCA_ACT_IN_HW_COUNT: u16 = 10;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcActionAttribute {
    Kind(String),
    Options(Vec<TcActionOption>),
    Index(u32),
    Stats(Vec<TcStats2>),
    Cookie(Vec<u8>),
    InHwCount(u32),
    Other(DefaultNla),
}

impl Nla for TcActionAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::Cookie(bytes) => bytes.len(),
            Self::Kind(k) => k.len() + 1,
            Self::Options(opt) => opt.as_slice().buffer_len(),
            Self::Index(_) | Self::InHwCount(_) => 4,
            Self::Stats(s) => s.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Cookie(bytes) => buffer.copy_from_slice(bytes.as_slice()),
            Self::Kind(string) => {
                buffer[..string.as_bytes().len()]
                    .copy_from_slice(string.as_bytes());
                buffer[string.as_bytes().len()] = 0;
            }
            Self::Options(opt) => opt.as_slice().emit(buffer),
            Self::Index(value) | Self::InHwCount(value) => {
                NativeEndian::write_u32(buffer, *value)
            }
            Self::Stats(s) => s.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn kind(&self) -> u16 {
        match self {
            Self::Kind(_) => TCA_ACT_KIND,
            Self::Options(_) => TCA_ACT_OPTIONS,
            Self::Index(_) => TCA_ACT_INDEX,
            Self::Stats(_) => TCA_ACT_STATS,
            Self::Cookie(_) => TCA_ACT_COOKIE,
            Self::InHwCount(_) => TCA_ACT_IN_HW_COUNT,
            Self::Other(nla) => nla.kind(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcActionOption {
    Mirror(TcActionMirrorOption),
    Nat(TcActionNatOption),
    Other(DefaultNla),
}

impl Nla for TcActionOption {
    fn value_len(&self) -> usize {
        match self {
            Self::Mirror(nla) => nla.value_len(),
            Self::Nat(nla) => nla.value_len(),
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Mirror(nla) => nla.emit_value(buffer),
            Self::Nat(nla) => nla.emit_value(buffer),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Mirror(nla) => nla.kind(),
            Self::Nat(nla) => nla.kind(),
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T, S> ParseableParametrized<NlaBuffer<&'a T>, S> for TcActionOption
where
    T: AsRef<[u8]> + ?Sized,
    S: AsRef<str>,
{
    type Error = TcError;
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        kind: S,
    ) -> Result<Self, TcError> {
        Ok(match kind.as_ref() {
            TcActionMirror::KIND => Self::Mirror(
                TcActionMirrorOption::parse(buf)
                    .map_err(TcError::ParseMirrorAction)?,
            ),
            TcActionNat::KIND => Self::Nat(
                TcActionNatOption::parse(buf)
                    .map_err(TcError::ParseMirrorAction)?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).map_err(TcError::ParseMirrorAction)?,
            ),
        })
    }
}

// `define tc_gen` in `linux/pkt_cls.h`
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TcActionGeneric {
    pub index: u32,
    pub capab: u32,
    pub action: TcActionType,
    pub refcnt: i32,
    pub bindcnt: i32,
}

impl TcActionGeneric {
    pub(crate) const BUF_LEN: usize = 20;
}

buffer!(TcActionGenericBuffer(TcActionGeneric::BUF_LEN) {
    index: (u32, 0..4),
    capab: (u32, 4..8),
    action: (i32, 8..12),
    refcnt: (i32, 12..16),
    bindcnt: (i32, 16..20),
});

impl Emitable for TcActionGeneric {
    fn buffer_len(&self) -> usize {
        Self::BUF_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = TcActionGenericBuffer::new(buffer);
        packet.set_index(self.index);
        packet.set_capab(self.capab);
        packet.set_action(self.action.into());
        packet.set_refcnt(self.refcnt);
        packet.set_bindcnt(self.bindcnt);
    }
}

impl<T: AsRef<[u8]>> Parseable<TcActionGenericBuffer<T>> for TcActionGeneric {
    type Error = DecodeError;
    fn parse(buf: &TcActionGenericBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: buf.index(),
            capab: buf.capab(),
            action: buf.action().into(),
            refcnt: buf.refcnt(),
            bindcnt: buf.bindcnt(),
        })
    }
}

const TC_ACT_UNSPEC: i32 = -1;
const TC_ACT_OK: i32 = 0;
const TC_ACT_RECLASSIFY: i32 = 1;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_PIPE: i32 = 3;
const TC_ACT_STOLEN: i32 = 4;
const TC_ACT_QUEUED: i32 = 5;
const TC_ACT_REPEAT: i32 = 6;
const TC_ACT_REDIRECT: i32 = 7;
const TC_ACT_TRAP: i32 = 8;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[non_exhaustive]
pub enum TcActionType {
    #[default]
    Unspec,
    Ok,
    Reclassify,
    Shot,
    Pipe,
    Stolen,
    Queued,
    Repeat,
    Redirect,
    Trap,
    Other(i32),
}

impl From<i32> for TcActionType {
    fn from(d: i32) -> Self {
        match d {
            TC_ACT_UNSPEC => Self::Unspec,
            TC_ACT_OK => Self::Ok,
            TC_ACT_RECLASSIFY => Self::Reclassify,
            TC_ACT_SHOT => Self::Shot,
            TC_ACT_PIPE => Self::Pipe,
            TC_ACT_STOLEN => Self::Stolen,
            TC_ACT_QUEUED => Self::Queued,
            TC_ACT_REPEAT => Self::Repeat,
            TC_ACT_REDIRECT => Self::Redirect,
            TC_ACT_TRAP => Self::Trap,
            _ => Self::Other(d),
        }
    }
}

impl From<TcActionType> for i32 {
    fn from(v: TcActionType) -> i32 {
        match v {
            TcActionType::Unspec => TC_ACT_UNSPEC,
            TcActionType::Ok => TC_ACT_OK,
            TcActionType::Reclassify => TC_ACT_RECLASSIFY,
            TcActionType::Shot => TC_ACT_SHOT,
            TcActionType::Pipe => TC_ACT_PIPE,
            TcActionType::Stolen => TC_ACT_STOLEN,
            TcActionType::Queued => TC_ACT_QUEUED,
            TcActionType::Repeat => TC_ACT_REPEAT,
            TcActionType::Redirect => TC_ACT_REDIRECT,
            TcActionType::Trap => TC_ACT_TRAP,
            TcActionType::Other(d) => d,
        }
    }
}
