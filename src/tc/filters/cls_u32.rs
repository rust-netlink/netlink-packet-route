// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::ErrorContext;
/// U32 filter
///
/// In its simplest form the U32 filter is a list of records, each
/// consisting of two fields: a selector and an action. The selectors,
/// described below, are compared with the currently processed IP packet
/// until the first match occurs, and then the associated action is
/// performed.
use netlink_packet_core::{
    append_bytes, append_u32, append_u64, parse_i32, parse_string, parse_u32,
    parse_u64, DecodeError, DefaultNla, Emitable, EncodeError, Nla, NlaBuffer,
    Parseable,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::u32_flags::{TcU32OptionFlags, TcU32SelectorFlags};
use crate::tc::{TcAction, TcHandle};

const TCA_U32_CLASSID: u16 = 1;
const TCA_U32_HASH: u16 = 2;
const TCA_U32_LINK: u16 = 3;
const TCA_U32_DIVISOR: u16 = 4;
const TCA_U32_SEL: u16 = 5;
const TCA_U32_POLICE: u16 = 6;
const TCA_U32_ACT: u16 = 7;
const TCA_U32_INDEV: u16 = 8;
const TCA_U32_PCNT: u16 = 9;
const TCA_U32_MARK: u16 = 10;
const TCA_U32_FLAGS: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcFilterU32 {}

impl TcFilterU32 {
    pub const KIND: &'static str = "u32";
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcFilterU32Option {
    ClassId(TcHandle),
    Hash(u32),
    Link(u32),
    Divisor(u32),
    Selector(TcU32Selector),
    Police(Vec<TcPoliceOption>),
    Action(Vec<TcAction>),
    Indev(String),
    Pnct(TcU32Pcnt),
    Mark(TcU32Mark),
    Flags(TcU32OptionFlags),
    Other(DefaultNla),
}

impl Nla for TcFilterU32Option {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Police(options) => (options).emit(out)?,
            Self::Indev(name) => {
                append_bytes(out, name.as_bytes());
                out.push(0);
            }
            Self::Pnct(value) => value.emit(out)?,
            Self::Mark(value) => value.emit(out)?,
            Self::Hash(i) | Self::Link(i) | Self::Divisor(i) => {
                append_u32(out, *i);
            }
            Self::Flags(f) => append_u32(out, f.bits()),
            Self::ClassId(i) => append_u32(out, (*i).into()),
            Self::Selector(s) => s.emit(out)?,
            Self::Action(acts) => (acts).emit(out)?,
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::ClassId(_) => TCA_U32_CLASSID,
            Self::Hash(_) => TCA_U32_HASH,
            Self::Link(_) => TCA_U32_LINK,
            Self::Divisor(_) => TCA_U32_DIVISOR,
            Self::Selector(_) => TCA_U32_SEL,
            Self::Police(_) => TCA_U32_POLICE,
            Self::Action(_) => TCA_U32_ACT,
            Self::Indev(_) => TCA_U32_INDEV,
            Self::Pnct(_) => TCA_U32_PCNT,
            Self::Mark(_) => TCA_U32_MARK,
            Self::Flags(_) => TCA_U32_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcFilterU32Option {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_U32_CLASSID => Self::ClassId(TcHandle::from(
                parse_u32(payload)
                    .context("failed to parse TCA_U32_CLASSID")?,
            )),
            TCA_U32_HASH => Self::Hash(
                parse_u32(payload).context("failed to parse TCA_U32_HASH")?,
            ),
            TCA_U32_LINK => Self::Link(
                parse_u32(payload).context("failed to parse TCA_U32_LINK")?,
            ),
            TCA_U32_DIVISOR => Self::Divisor(
                parse_u32(payload)
                    .context("failed to parse TCA_U32_DIVISOR")?,
            ),
            TCA_U32_SEL => Self::Selector(
                TcU32Selector::parse(payload)
                    .context("failed to parse TCA_U32_SEL")?,
            ),
            TCA_U32_POLICE => {
                let mut options = vec![];
                for nla in buf.nlas().context("invalid TCA_U32_POLICE")? {
                    options.push(
                        TcPoliceOption::parse(&nla)
                            .context("failed to parse TCA_U32_POLICE")?,
                    );
                }
                Self::Police(options)
            }
            TCA_U32_ACT => {
                let mut acts = vec![];
                for act in buf.nlas().context("invalid TCA_U32_ACT")? {
                    acts.push(
                        TcAction::parse(&act)
                            .context("failed to parse TCA_U32_ACT")?,
                    );
                }
                Self::Action(acts)
            }
            TCA_U32_INDEV => Self::Indev(
                parse_string(payload)
                    .context("failed to parse TCA_U32_INDEV")?,
            ),
            TCA_U32_PCNT => Self::Pnct(
                TcU32Pcnt::parse(payload)
                    .context("failed to parse TCA_U32_PCNT")?,
            ),
            TCA_U32_MARK => Self::Mark(
                TcU32Mark::parse(payload)
                    .context("failed to parse TCA_U32_MARK")?,
            ),
            TCA_U32_FLAGS => Self::Flags(TcU32OptionFlags::from_bits_retain(
                parse_u32(payload).context("failed to parse TCA_U32_FLAGS")?,
            )),
            _ => Self::Other(
                DefaultNla::parse(buf).context("failed to parse u32 nla")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcU32Selector {
    pub flags: TcU32SelectorFlags,
    pub offshift: u8,
    pub nkeys: u8,
    pub offmask: u16,
    pub off: u16,
    pub offoff: i16,
    pub hoff: i16,
    pub hmask: u32,
    pub keys: Vec<TcU32Key>,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct TcU32SelectorBuffer {
    flags: u8,
    offshift: u8,
    nkeys: u8,
    _pad: u8,
    offmask: u16,
    off: u16,
    offoff: i16,
    hoff: i16,
    hmask: u32,
}

impl TcU32SelectorBuffer {
    pub fn new_checked(buffer: &[u8]) -> Result<&Self, DecodeError> {
        let len = buffer.len();
        let sel_len = size_of::<Self>();
        if len < sel_len {
            return Err(format!(
                "invalid TcU32SelectorBuffer: length {len} < {sel_len}"
            )
            .into());
        }
        let raw = Self::ref_from_prefix(buffer)
            .map_err(|_| DecodeError::buffer_too_small(len, sel_len))?
            .0;
        let nkeys = raw.nkeys;
        // Expect the buffer to be large enough to hold `nkeys`.
        let expected_len =
            (nkeys as usize * size_of::<TcU32KeyBuffer>()) + sel_len;
        if len < expected_len {
            return Err(format!(
                "invalid TcU32SelectorBuffer: length {len} < {expected_len}",
            )
            .into());
        }
        Ok(raw)
    }
}

impl From<&TcU32Selector> for TcU32SelectorBuffer {
    fn from(selector: &TcU32Selector) -> Self {
        Self {
            flags: selector.flags.bits(),
            offshift: selector.offshift,
            nkeys: selector.nkeys,
            _pad: 0,
            // `offmask` is `__be16` and `hmask` is `__be32` in
            // `struct tc_u32_sel`.
            offmask: selector.offmask.to_be(),
            off: selector.off,
            offoff: selector.offoff,
            hoff: selector.hoff,
            hmask: selector.hmask.to_be(),
        }
    }
}

impl Emitable for TcU32Selector {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TcU32SelectorBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        for k in &self.keys {
            k.emit(out)?;
        }
        Ok(())
    }
}

impl TcU32Selector {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let raw = TcU32SelectorBuffer::new_checked(payload)?;
        let nkeys = raw.nkeys;
        let key_len = size_of::<TcU32KeyBuffer>();
        let key_payload = &payload[size_of::<TcU32SelectorBuffer>()..];
        let mut keys = Vec::<TcU32Key>::with_capacity(nkeys.into());
        for i in 0..nkeys {
            let i = i as usize;
            keys.push(
                TcU32Key::parse(
                    &key_payload[(i * key_len)..((i + 1) * key_len)],
                )
                .context("failed to parse u32 key")?,
            );
        }

        Ok(Self {
            flags: TcU32SelectorFlags::from_bits_retain(raw.flags),
            offshift: raw.offshift,
            nkeys,
            offmask: u16::from_be(raw.offmask),
            off: raw.off,
            offoff: raw.offoff,
            hoff: raw.hoff,
            hmask: u32::from_be(raw.hmask),
            keys,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcU32Key {
    pub mask: u32,
    pub val: u32,
    pub off: i32,
    pub offmask: i32,
}

// Wire format of a `struct tc_u32_key`: `mask` and `val` are `__be32`
// (always big-endian on the wire), while `off` and `offmask` are plain
// native `int`.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct TcU32KeyBuffer {
    mask: u32,
    val: u32,
    off: i32,
    offmask: i32,
}

impl From<&TcU32Key> for TcU32KeyBuffer {
    fn from(key: &TcU32Key) -> Self {
        Self {
            mask: key.mask.to_be(),
            val: key.val.to_be(),
            off: key.off,
            offmask: key.offmask,
        }
    }
}

impl Emitable for TcU32Key {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TcU32KeyBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

impl TcU32Key {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcU32KeyBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcU32KeyBuffer>(),
                )
            })?;
        Ok(Self {
            mask: u32::from_be(raw.mask),
            val: u32::from_be(raw.val),
            off: raw.off,
            offmask: raw.offmask,
        })
    }
}

/// Result from the u32 mark matcher (`struct tc_u32_mark`).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcU32Mark {
    pub val: u32,
    pub mask: u32,
    pub success: u32,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct TcU32MarkBuffer {
    val: u32,
    mask: u32,
    success: u32,
}

impl TcU32Mark {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcU32MarkBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcU32MarkBuffer>(),
                )
            })?;
        Ok(Self {
            val: raw.val,
            mask: raw.mask,
            success: raw.success,
        })
    }
}

impl Emitable for TcU32Mark {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TcU32MarkBuffer {
            val: self.val,
            mask: self.mask,
            success: self.success,
        };
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

/// u32 per-filter counters (`struct tc_u32_pcnt`).
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct TcU32Pcnt {
    pub rcnt: u64,
    pub rhit: u64,
    pub kcnts: Vec<u64>,
}

impl TcU32Pcnt {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 16 {
            return Err(DecodeError::buffer_too_small(payload.len(), 16));
        }
        if (payload.len() - 16) % 8 != 0 {
            return Err(DecodeError::from(format!(
                "Invalid TCA_U32_PCNT, unexpected payload length {}",
                payload.len()
            )));
        }
        let rcnt =
            parse_u64(&payload[0..8]).context("invalid TCA_U32_PCNT rcnt")?;
        let rhit =
            parse_u64(&payload[8..16]).context("invalid TCA_U32_PCNT rhit")?;
        let mut kcnts = Vec::with_capacity((payload.len() - 16) / 8);
        for chunk in payload[16..].chunks_exact(8) {
            kcnts.push(parse_u64(chunk).context("invalid TCA_U32_PCNT kcnt")?);
        }
        Ok(Self { rcnt, rhit, kcnts })
    }
}

impl Emitable for TcU32Pcnt {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u64(out, self.rcnt);
        append_u64(out, self.rhit);
        for value in &self.kcnts {
            append_u64(out, *value);
        }
        Ok(())
    }
}

/// Traffic shaping rate specification (`struct tc_ratespec`).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcRateSpec {
    pub cell_log: u8,
    pub linklayer: u8,
    pub overhead: u16,
    pub cell_align: i16,
    pub mpu: u16,
    pub rate: u32,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct TcRateSpecBuffer {
    cell_log: u8,
    linklayer: u8,
    overhead: u16,
    cell_align: i16,
    mpu: u16,
    rate: u32,
}

impl From<&TcRateSpec> for TcRateSpecBuffer {
    fn from(value: &TcRateSpec) -> Self {
        Self {
            cell_log: value.cell_log,
            linklayer: value.linklayer,
            overhead: value.overhead,
            cell_align: value.cell_align,
            mpu: value.mpu,
            rate: value.rate,
        }
    }
}

impl TcRateSpec {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcRateSpecBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcRateSpecBuffer>(),
                )
            })?;
        Ok(Self {
            cell_log: raw.cell_log,
            linklayer: raw.linklayer,
            overhead: raw.overhead,
            cell_align: raw.cell_align,
            mpu: raw.mpu,
            rate: raw.rate,
        })
    }
}

/// Policing configuration (`struct tc_police`).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcPolice {
    pub index: u32,
    pub action: i32,
    pub limit: u32,
    pub burst: u32,
    pub mtu: u32,
    pub rate: TcRateSpec,
    pub peakrate: TcRateSpec,
    pub refcnt: i32,
    pub bindcnt: i32,
    pub capab: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct TcPoliceTm {
    pub install: u64,
    pub lastuse: u64,
    pub expires: u64,
    pub firstuse: u64,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct TcPoliceTmBuffer {
    install: u64,
    lastuse: u64,
    expires: u64,
    firstuse: u64,
}

impl From<&TcPoliceTm> for TcPoliceTmBuffer {
    fn from(value: &TcPoliceTm) -> Self {
        Self {
            install: value.install,
            lastuse: value.lastuse,
            expires: value.expires,
            firstuse: value.firstuse,
        }
    }
}

impl TcPoliceTm {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TcPoliceTmBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TcPoliceTmBuffer>(),
                )
            })?;
        Ok(Self {
            install: raw.install,
            lastuse: raw.lastuse,
            expires: raw.expires,
            firstuse: raw.firstuse,
        })
    }
}

impl TcPolice {
    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        const LEN: usize = 56;
        if payload.len() < LEN {
            return Err(DecodeError::buffer_too_small(payload.len(), LEN));
        }
        Ok(Self {
            index: parse_u32(&payload[0..4])
                .context("invalid tc_police index")?,
            action: parse_i32(&payload[4..8])
                .context("invalid tc_police action")?,
            limit: parse_u32(&payload[8..12])
                .context("invalid tc_police limit")?,
            burst: parse_u32(&payload[12..16])
                .context("invalid tc_police burst")?,
            mtu: parse_u32(&payload[16..20])
                .context("invalid tc_police mtu")?,
            rate: TcRateSpec::parse(&payload[20..32])?,
            peakrate: TcRateSpec::parse(&payload[32..44])?,
            refcnt: parse_i32(&payload[44..48])
                .context("invalid tc_police refcnt")?,
            bindcnt: parse_i32(&payload[48..52])
                .context("invalid tc_police bindcnt")?,
            capab: parse_u32(&payload[52..56])
                .context("invalid tc_police capab")?,
        })
    }
}

impl Emitable for TcPolice {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.index);
        append_bytes(out, &self.action.to_ne_bytes());
        append_u32(out, self.limit);
        append_u32(out, self.burst);
        append_u32(out, self.mtu);
        let rate = TcRateSpecBuffer::from(&self.rate);
        append_bytes(out, rate.as_bytes());
        let peakrate = TcRateSpecBuffer::from(&self.peakrate);
        append_bytes(out, peakrate.as_bytes());
        append_bytes(out, &self.refcnt.to_ne_bytes());
        append_bytes(out, &self.bindcnt.to_ne_bytes());
        append_u32(out, self.capab);
        Ok(())
    }
}

impl Emitable for TcPoliceTm {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TcPoliceTmBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}

const TCA_POLICE_TBF: u16 = 1;
const TCA_POLICE_RATE: u16 = 2;
const TCA_POLICE_PEAKRATE: u16 = 3;
const TCA_POLICE_AVRATE: u16 = 4;
const TCA_POLICE_RESULT: u16 = 5;
const TCA_POLICE_TM: u16 = 6;
const TCA_POLICE_RATE64: u16 = 8;
const TCA_POLICE_PEAKRATE64: u16 = 9;
const TCA_POLICE_PKTRATE64: u16 = 10;
const TCA_POLICE_PKTBURST64: u16 = 11;

/// Nested attributes of `TCA_U32_POLICE`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcPoliceOption {
    Tbf(TcPolice),
    Rate(Vec<u8>),
    PeakRate(Vec<u8>),
    AvRate(u32),
    Result(u32),
    Tm(TcPoliceTm),
    Rate64(u64),
    PeakRate64(u64),
    PktRate64(u64),
    PktBurst64(u64),
    Other(DefaultNla),
}

impl Nla for TcPoliceOption {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Tbf(v) => v.emit(out)?,
            Self::Rate(v) | Self::PeakRate(v) => append_bytes(out, v),
            Self::AvRate(v) | Self::Result(v) => append_u32(out, *v),
            Self::Tm(v) => v.emit(out)?,
            Self::Rate64(v)
            | Self::PeakRate64(v)
            | Self::PktRate64(v)
            | Self::PktBurst64(v) => append_u64(out, *v),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Tbf(_) => TCA_POLICE_TBF,
            Self::Rate(_) => TCA_POLICE_RATE,
            Self::PeakRate(_) => TCA_POLICE_PEAKRATE,
            Self::AvRate(_) => TCA_POLICE_AVRATE,
            Self::Result(_) => TCA_POLICE_RESULT,
            Self::Tm(_) => TCA_POLICE_TM,
            Self::Rate64(_) => TCA_POLICE_RATE64,
            Self::PeakRate64(_) => TCA_POLICE_PEAKRATE64,
            Self::PktRate64(_) => TCA_POLICE_PKTRATE64,
            Self::PktBurst64(_) => TCA_POLICE_PKTBURST64,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcPoliceOption {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TCA_POLICE_TBF => Self::Tbf(
                TcPolice::parse(payload)
                    .context("invalid TCA_POLICE_TBF value")?,
            ),
            TCA_POLICE_RATE => Self::Rate(payload.to_vec()),
            TCA_POLICE_PEAKRATE => Self::PeakRate(payload.to_vec()),
            TCA_POLICE_AVRATE => Self::AvRate(
                parse_u32(payload)
                    .context("invalid TCA_POLICE_AVRATE value")?,
            ),
            TCA_POLICE_RESULT => Self::Result(
                parse_u32(payload)
                    .context("invalid TCA_POLICE_RESULT value")?,
            ),
            TCA_POLICE_TM => Self::Tm(
                TcPoliceTm::parse(payload)
                    .context("invalid TCA_POLICE_TM value")?,
            ),
            TCA_POLICE_RATE64 => Self::Rate64(
                parse_u64(payload)
                    .context("invalid TCA_POLICE_RATE64 value")?,
            ),
            TCA_POLICE_PEAKRATE64 => Self::PeakRate64(
                parse_u64(payload)
                    .context("invalid TCA_POLICE_PEAKRATE64 value")?,
            ),
            TCA_POLICE_PKTRATE64 => Self::PktRate64(
                parse_u64(payload)
                    .context("invalid TCA_POLICE_PKTRATE64 value")?,
            ),
            TCA_POLICE_PKTBURST64 => Self::PktBurst64(
                parse_u64(payload)
                    .context("invalid TCA_POLICE_PKTBURST64 value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
