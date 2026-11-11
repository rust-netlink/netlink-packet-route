// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use netlink_packet_core::{
    append_bytes, append_u16, append_u32, parse_u16, parse_u32, DecodeError,
    DefaultNla, Emitable, EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
    NLA_F_NESTED,
};

const IFLA_CAN_BITTIMING: u16 = 1;
const IFLA_CAN_BITTIMING_CONST: u16 = 2;
const IFLA_CAN_CLOCK: u16 = 3;
const IFLA_CAN_STATE: u16 = 4;
const IFLA_CAN_CTRLMODE: u16 = 5;
const IFLA_CAN_RESTART_MS: u16 = 6;
const IFLA_CAN_RESTART: u16 = 7;
const IFLA_CAN_BERR_COUNTER: u16 = 8;
const IFLA_CAN_DATA_BITTIMING: u16 = 9;
const IFLA_CAN_DATA_BITTIMING_CONST: u16 = 10;
const IFLA_CAN_TERMINATION: u16 = 11;
const IFLA_CAN_BITRATE_MAX: u16 = 15;
const IFLA_CAN_TDC: u16 = 16;
const IFLA_CAN_CTRLMODE_EXT: u16 = 17;

const IFLA_CAN_TDC_TDCV_MIN: u16 = 1;
const IFLA_CAN_TDC_TDCV_MAX: u16 = 2;
const IFLA_CAN_TDC_TDCO_MIN: u16 = 3;
const IFLA_CAN_TDC_TDCO_MAX: u16 = 4;
const IFLA_CAN_TDC_TDCF_MIN: u16 = 5;
const IFLA_CAN_TDC_TDCF_MAX: u16 = 6;
const IFLA_CAN_TDC_TDCV: u16 = 7;
const IFLA_CAN_TDC_TDCO: u16 = 8;
const IFLA_CAN_TDC_TDCF: u16 = 9;

const IFLA_CAN_CTRLMODE_SUPPORTED: u16 = 1;

/// CAN bit timing parameters, corresponding to `struct can_bittiming` in the
/// kernel.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct CanBitTiming {
    pub bitrate: u32,
    pub sample_point: u32,
    pub tq: u32,
    pub prop_seg: u32,
    pub phase_seg1: u32,
    pub phase_seg2: u32,
    pub sjw: u32,
    pub brp: u32,
}

const CAN_BITTIMING_LEN: usize = 32;

impl Emitable for CanBitTiming {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.bitrate);
        append_u32(out, self.sample_point);
        append_u32(out, self.tq);
        append_u32(out, self.prop_seg);
        append_u32(out, self.phase_seg1);
        append_u32(out, self.phase_seg2);
        append_u32(out, self.sjw);
        append_u32(out, self.brp);
        Ok(())
    }
}

impl CanBitTiming {
    /// Create a new `CanBitTiming` with the given bitrate.
    pub fn new(bitrate: u32) -> Self {
        Self {
            bitrate,
            ..Default::default()
        }
    }

    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < CAN_BITTIMING_LEN {
            return Err("invalid IFLA_CAN_BITTIMING: expected 32 bytes".into());
        }
        Ok(Self {
            bitrate: parse_u32(&payload[0..4])
                .context("invalid IFLA_CAN_BITTIMING bitrate")?,
            sample_point: parse_u32(&payload[4..8])
                .context("invalid IFLA_CAN_BITTIMING sample_point")?,
            tq: parse_u32(&payload[8..12])
                .context("invalid IFLA_CAN_BITTIMING tq")?,
            prop_seg: parse_u32(&payload[12..16])
                .context("invalid IFLA_CAN_BITTIMING prop_seg")?,
            phase_seg1: parse_u32(&payload[16..20])
                .context("invalid IFLA_CAN_BITTIMING phase_seg1")?,
            phase_seg2: parse_u32(&payload[20..24])
                .context("invalid IFLA_CAN_BITTIMING phase_seg2")?,
            sjw: parse_u32(&payload[24..28])
                .context("invalid IFLA_CAN_BITTIMING sjw")?,
            brp: parse_u32(&payload[28..32])
                .context("invalid IFLA_CAN_BITTIMING brp")?,
        })
    }
}

const CAN_CTRLMODE_LOOPBACK: u32 = 0x001;
const CAN_CTRLMODE_LISTENONLY: u32 = 0x002;
const CAN_CTRLMODE_3_SAMPLES: u32 = 0x004;
const CAN_CTRLMODE_ONE_SHOT: u32 = 0x008;
const CAN_CTRLMODE_BERR_REPORTING: u32 = 0x010;
const CAN_CTRLMODE_FD: u32 = 0x020;
const CAN_CTRLMODE_PRESUME_ACK: u32 = 0x040;
const CAN_CTRLMODE_FD_NON_ISO: u32 = 0x080;
const CAN_CTRLMODE_CC_LEN8_DLC: u32 = 0x100;
const CAN_CTRLMODE_TDC_AUTO: u32 = 0x200;
const CAN_CTRLMODE_TDC_MANUAL: u32 = 0x400;
const CAN_CTRLMODE_RESTRICTED: u32 = 0x800;
const CAN_CTRLMODE_XL: u32 = 0x1000;
const CAN_CTRLMODE_XL_TDC_AUTO: u32 = 0x2000;
const CAN_CTRLMODE_XL_TDC_MANUAL: u32 = 0x4000;
const CAN_CTRLMODE_XL_TMS: u32 = 0x8000;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CanCtrlModeFlags: u32 {
        const Loopback = CAN_CTRLMODE_LOOPBACK;
        const ListenOnly = CAN_CTRLMODE_LISTENONLY;
        const TripleSampling = CAN_CTRLMODE_3_SAMPLES;
        const OneShot = CAN_CTRLMODE_ONE_SHOT;
        const BerrReporting = CAN_CTRLMODE_BERR_REPORTING;
        const Fd = CAN_CTRLMODE_FD;
        const PresumeAck = CAN_CTRLMODE_PRESUME_ACK;
        const FdNonIso = CAN_CTRLMODE_FD_NON_ISO;
        const CcLen8Dlc = CAN_CTRLMODE_CC_LEN8_DLC;
        const TdcAuto = CAN_CTRLMODE_TDC_AUTO;
        const TdcManual = CAN_CTRLMODE_TDC_MANUAL;
        const Restricted = CAN_CTRLMODE_RESTRICTED;
        const Xl = CAN_CTRLMODE_XL;
        const XlTdcAuto = CAN_CTRLMODE_XL_TDC_AUTO;
        const XlTdcManual = CAN_CTRLMODE_XL_TDC_MANUAL;
        const XlTms = CAN_CTRLMODE_XL_TMS;
        const _ = !0;
    }
}

/// CAN controller mode, corresponding to `struct can_ctrlmode` in the kernel.
///
/// Contains `mask` and `flags` fields, each a bitmask of
/// [`CanCtrlModeFlags`].
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct CanCtrlMode {
    pub mask: CanCtrlModeFlags,
    pub flags: CanCtrlModeFlags,
}

const CAN_CTRLMODE_LEN: usize = 8;

impl Emitable for CanCtrlMode {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.mask.bits());
        append_u32(out, self.flags.bits());
        Ok(())
    }
}

impl CanCtrlMode {
    pub const fn new(mask: CanCtrlModeFlags, flags: CanCtrlModeFlags) -> Self {
        Self { mask, flags }
    }

    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < CAN_CTRLMODE_LEN {
            return Err("invalid IFLA_CAN_CTRLMODE: expected 8 bytes".into());
        }
        Ok(Self {
            mask: CanCtrlModeFlags::from_bits_retain(
                parse_u32(&payload[0..4])
                    .context("invalid IFLA_CAN_CTRLMODE mask")?,
            ),
            flags: CanCtrlModeFlags::from_bits_retain(
                parse_u32(&payload[4..8])
                    .context("invalid IFLA_CAN_CTRLMODE flags")?,
            ),
        })
    }
}

/// CAN clock parameters, corresponding to `struct can_clock` in the kernel.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct CanClock {
    pub freq: u32,
}

const CAN_CLOCK_LEN: usize = 4;

impl Emitable for CanClock {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.freq);
        Ok(())
    }
}

impl CanClock {
    pub fn new(freq: u32) -> Self {
        Self { freq }
    }

    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < CAN_CLOCK_LEN {
            return Err("invalid IFLA_CAN_CLOCK: expected 4 bytes".into());
        }
        Ok(Self {
            freq: parse_u32(payload).context("invalid IFLA_CAN_CLOCK value")?,
        })
    }
}

/// CAN bus error counter, corresponding to `struct can_berr_counter` in the
/// kernel.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct CanBerrCounter {
    pub txerr: u16,
    pub rxerr: u16,
}

const CAN_BERR_COUNTER_LEN: usize = 4;

impl Emitable for CanBerrCounter {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u16(out, self.txerr);
        append_u16(out, self.rxerr);
        Ok(())
    }
}

impl CanBerrCounter {
    pub const fn new(txerr: u16, rxerr: u16) -> Self {
        Self { txerr, rxerr }
    }

    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < CAN_BERR_COUNTER_LEN {
            return Err(
                "invalid IFLA_CAN_BERR_COUNTER: expected 4 bytes".into()
            );
        }
        Ok(Self {
            txerr: parse_u16(&payload[0..2])
                .context("invalid IFLA_CAN_BERR_COUNTER txerr")?,
            rxerr: parse_u16(&payload[2..4])
                .context("invalid IFLA_CAN_BERR_COUNTER rxerr")?,
        })
    }
}

/// CAN Transmitter Delay Compensation (TDC) attributes nested in
/// `IFLA_CAN_TDC`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum CanTdc {
    TdcvMin(u32),
    TdcvMax(u32),
    TdcoMin(u32),
    TdcoMax(u32),
    TdcfMin(u32),
    TdcfMax(u32),
    Tdcv(u32),
    Tdco(u32),
    Tdcf(u32),
    Other(DefaultNla),
}

impl Nla for CanTdc {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::TdcvMin(v)
            | Self::TdcvMax(v)
            | Self::TdcoMin(v)
            | Self::TdcoMax(v)
            | Self::TdcfMin(v)
            | Self::TdcfMax(v)
            | Self::Tdcv(v)
            | Self::Tdco(v)
            | Self::Tdcf(v) => {
                append_u32(out, *v);
                Ok(())
            }
            Self::Other(nla) => {
                append_bytes(out, nla.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::TdcvMin(_) => IFLA_CAN_TDC_TDCV_MIN,
            Self::TdcvMax(_) => IFLA_CAN_TDC_TDCV_MAX,
            Self::TdcoMin(_) => IFLA_CAN_TDC_TDCO_MIN,
            Self::TdcoMax(_) => IFLA_CAN_TDC_TDCO_MAX,
            Self::TdcfMin(_) => IFLA_CAN_TDC_TDCF_MIN,
            Self::TdcfMax(_) => IFLA_CAN_TDC_TDCF_MAX,
            Self::Tdcv(_) => IFLA_CAN_TDC_TDCV,
            Self::Tdco(_) => IFLA_CAN_TDC_TDCO,
            Self::Tdcf(_) => IFLA_CAN_TDC_TDCF,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for CanTdc {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_CAN_TDC_TDCV_MIN => Self::TdcvMin(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCV_MIN value")?,
            ),
            IFLA_CAN_TDC_TDCV_MAX => Self::TdcvMax(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCV_MAX value")?,
            ),
            IFLA_CAN_TDC_TDCO_MIN => Self::TdcoMin(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCO_MIN value")?,
            ),
            IFLA_CAN_TDC_TDCO_MAX => Self::TdcoMax(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCO_MAX value")?,
            ),
            IFLA_CAN_TDC_TDCF_MIN => Self::TdcfMin(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCF_MIN value")?,
            ),
            IFLA_CAN_TDC_TDCF_MAX => Self::TdcfMax(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCF_MAX value")?,
            ),
            IFLA_CAN_TDC_TDCV => Self::Tdcv(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCV value")?,
            ),
            IFLA_CAN_TDC_TDCO => Self::Tdco(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCO value")?,
            ),
            IFLA_CAN_TDC_TDCF => Self::Tdcf(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_TDC_TDCF value")?,
            ),
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for IFLA_CAN_TDC")
            })?),
        })
    }
}

/// CAN controller mode extended attributes nested in `IFLA_CAN_CTRLMODE_EXT`.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum CanCtrlModeExt {
    Supported(CanCtrlModeFlags),
    Other(DefaultNla),
}

impl Nla for CanCtrlModeExt {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Supported(v) => {
                append_u32(out, v.bits());
                Ok(())
            }
            Self::Other(nla) => {
                append_bytes(out, nla.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Supported(_) => IFLA_CAN_CTRLMODE_SUPPORTED,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for CanCtrlModeExt {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_CAN_CTRLMODE_SUPPORTED => {
                Self::Supported(CanCtrlModeFlags::from_bits_retain(
                    parse_u32(payload)
                        .context("invalid IFLA_CAN_CTRLMODE_SUPPORTED value")?,
                ))
            }
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for IFLA_CAN_CTRLMODE_EXT")
            })?),
        })
    }
}

/// CAN bittiming const (read-only), corresponding to
/// `struct can_bittiming_const` in the kernel.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct CanBitTimingConst {
    pub name: String,
    pub tseg1_min: u32,
    pub tseg1_max: u32,
    pub tseg2_min: u32,
    pub tseg2_max: u32,
    pub sjw_max: u32,
    pub brp_min: u32,
    pub brp_max: u32,
    pub brp_inc: u32,
}

const CAN_BITTIMING_CONST_LEN: usize = 48;

impl Emitable for CanBitTimingConst {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let name_bytes = self.name.as_bytes();
        let name_len = name_bytes.len().min(15);
        let start = out.len();
        append_bytes(out, &name_bytes[..name_len]);
        out.push(0);
        out.resize(start + 16, 0);
        append_u32(out, self.tseg1_min);
        append_u32(out, self.tseg1_max);
        append_u32(out, self.tseg2_min);
        append_u32(out, self.tseg2_max);
        append_u32(out, self.sjw_max);
        append_u32(out, self.brp_min);
        append_u32(out, self.brp_max);
        append_u32(out, self.brp_inc);
        Ok(())
    }
}

impl CanBitTimingConst {
    /// Create a new `CanBitTimingConst` with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < CAN_BITTIMING_CONST_LEN {
            return Err(
                "invalid IFLA_CAN_BITTIMING_CONST: expected 48 bytes".into()
            );
        }
        let name_end = payload[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&payload[..name_end]).to_string();
        Ok(Self {
            name,
            tseg1_min: parse_u32(&payload[16..20])
                .context("invalid IFLA_CAN_BITTIMING_CONST tseg1_min")?,
            tseg1_max: parse_u32(&payload[20..24])
                .context("invalid IFLA_CAN_BITTIMING_CONST tseg1_max")?,
            tseg2_min: parse_u32(&payload[24..28])
                .context("invalid IFLA_CAN_BITTIMING_CONST tseg2_min")?,
            tseg2_max: parse_u32(&payload[28..32])
                .context("invalid IFLA_CAN_BITTIMING_CONST tseg2_max")?,
            sjw_max: parse_u32(&payload[32..36])
                .context("invalid IFLA_CAN_BITTIMING_CONST sjw_max")?,
            brp_min: parse_u32(&payload[36..40])
                .context("invalid IFLA_CAN_BITTIMING_CONST brp_min")?,
            brp_max: parse_u32(&payload[40..44])
                .context("invalid IFLA_CAN_BITTIMING_CONST brp_max")?,
            brp_inc: parse_u32(&payload[44..48])
                .context("invalid IFLA_CAN_BITTIMING_CONST brp_inc")?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoCan {
    BitTiming(CanBitTiming),
    BitTimingConst(CanBitTimingConst),
    Clock(CanClock),
    State(u32),
    CtrlMode(CanCtrlMode),
    RestartMs(u32),
    Restart(u32),
    BerrCounter(CanBerrCounter),
    DataBitTiming(CanBitTiming),
    DataBitTimingConst(CanBitTimingConst),
    Termination(u16),
    BitrateMax(u32),
    Tdc(Vec<CanTdc>),
    CtrlModeExt(Vec<CanCtrlModeExt>),
    Other(DefaultNla),
}

impl Nla for InfoCan {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::BitTiming(v) => v.emit(out),
            Self::BitTimingConst(v) => v.emit(out),
            Self::Clock(v) => v.emit(out),
            Self::State(v) => {
                append_u32(out, *v);
                Ok(())
            }
            Self::CtrlMode(v) => v.emit(out),
            Self::RestartMs(v) => {
                append_u32(out, *v);
                Ok(())
            }
            Self::Restart(v) => {
                append_u32(out, *v);
                Ok(())
            }
            Self::BerrCounter(v) => v.emit(out),
            Self::DataBitTiming(v) => v.emit(out),
            Self::DataBitTimingConst(v) => v.emit(out),
            Self::Termination(v) => {
                append_u16(out, *v);
                Ok(())
            }
            Self::BitrateMax(v) => {
                append_u32(out, *v);
                Ok(())
            }
            Self::Tdc(nlas) => (nlas.as_slice()).emit(out),
            Self::CtrlModeExt(nlas) => (nlas.as_slice()).emit(out),
            Self::Other(nla) => {
                append_bytes(out, nla.value());
                Ok(())
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::BitTiming(_) => IFLA_CAN_BITTIMING,
            Self::BitTimingConst(_) => IFLA_CAN_BITTIMING_CONST,
            Self::Clock(_) => IFLA_CAN_CLOCK,
            Self::State(_) => IFLA_CAN_STATE,
            Self::CtrlMode(_) => IFLA_CAN_CTRLMODE,
            Self::RestartMs(_) => IFLA_CAN_RESTART_MS,
            Self::Restart(_) => IFLA_CAN_RESTART,
            Self::BerrCounter(_) => IFLA_CAN_BERR_COUNTER,
            Self::DataBitTiming(_) => IFLA_CAN_DATA_BITTIMING,
            Self::DataBitTimingConst(_) => IFLA_CAN_DATA_BITTIMING_CONST,
            Self::Termination(_) => IFLA_CAN_TERMINATION,
            Self::BitrateMax(_) => IFLA_CAN_BITRATE_MAX,
            Self::Tdc(_) => IFLA_CAN_TDC | NLA_F_NESTED,
            Self::CtrlModeExt(_) => IFLA_CAN_CTRLMODE_EXT | NLA_F_NESTED,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for InfoCan {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_CAN_BITTIMING => Self::BitTiming(
                CanBitTiming::parse(payload)
                    .context("invalid IFLA_CAN_BITTIMING")?,
            ),
            IFLA_CAN_BITTIMING_CONST => Self::BitTimingConst(
                CanBitTimingConst::parse(payload)
                    .context("invalid IFLA_CAN_BITTIMING_CONST")?,
            ),
            IFLA_CAN_CLOCK => Self::Clock(
                CanClock::parse(payload).context("invalid IFLA_CAN_CLOCK")?,
            ),
            IFLA_CAN_STATE => Self::State(
                parse_u32(payload).context("invalid IFLA_CAN_STATE value")?,
            ),
            IFLA_CAN_CTRLMODE => Self::CtrlMode(
                CanCtrlMode::parse(payload)
                    .context("invalid IFLA_CAN_CTRLMODE")?,
            ),
            IFLA_CAN_RESTART_MS => Self::RestartMs(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_RESTART_MS value")?,
            ),
            IFLA_CAN_RESTART => Self::Restart(
                parse_u32(payload).context("invalid IFLA_CAN_RESTART value")?,
            ),
            IFLA_CAN_BERR_COUNTER => Self::BerrCounter(
                CanBerrCounter::parse(payload)
                    .context("invalid IFLA_CAN_BERR_COUNTER")?,
            ),
            IFLA_CAN_DATA_BITTIMING => Self::DataBitTiming(
                CanBitTiming::parse(payload)
                    .context("invalid IFLA_CAN_DATA_BITTIMING")?,
            ),
            IFLA_CAN_DATA_BITTIMING_CONST => Self::DataBitTimingConst(
                CanBitTimingConst::parse(payload)
                    .context("invalid IFLA_CAN_DATA_BITTIMING_CONST")?,
            ),
            IFLA_CAN_TERMINATION => Self::Termination(
                parse_u16(payload)
                    .context("invalid IFLA_CAN_TERMINATION value")?,
            ),
            IFLA_CAN_BITRATE_MAX => Self::BitrateMax(
                parse_u32(payload)
                    .context("invalid IFLA_CAN_BITRATE_MAX value")?,
            ),
            IFLA_CAN_TDC => {
                let mut v = Vec::new();
                let err = "invalid IFLA_CAN_TDC";
                for nla in buf.nlas().context(err)? {
                    v.push(CanTdc::parse(&nla).context(err)?);
                }
                Self::Tdc(v)
            }
            IFLA_CAN_CTRLMODE_EXT => {
                let mut v = Vec::new();
                let err = "invalid IFLA_CAN_CTRLMODE_EXT";
                for nla in buf.nlas().context(err)? {
                    v.push(CanCtrlModeExt::parse(&nla).context(err)?);
                }
                Self::CtrlModeExt(v)
            }
            kind => Self::Other(DefaultNla::parse(buf).with_context(|| {
                format!("unknown NLA type {kind} for IFLA_INFO_DATA(can)")
            })?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_berr_counter_round_trip() {
        let counter = CanBerrCounter::new(3, 7);
        let mut buf = Vec::new();
        counter.emit_value(&mut buf).unwrap();
        assert_eq!(buf, [3, 0, 7, 0]);
        assert_eq!(CanBerrCounter::parse(&buf).unwrap(), counter);
    }
}
