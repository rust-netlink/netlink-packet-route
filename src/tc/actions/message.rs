// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_string, parse_u32, DecodeError, DefaultNla,
    Emitable, EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};

use crate::tc::{
    actions::{header::TCA_HEADER_LEN, TcActionMessageHeader},
    TcAction,
};

/// Message to describe [tc-actions]
///
/// [tc-actions]: https://man7.org/linux/man-pages/man8/tc-actions.8.html
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct TcActionMessage {
    /// Header of the message.
    pub header: TcActionMessageHeader,
    /// Attributes of the message.
    pub attributes: Vec<TcActionMessageAttribute>,
}

const TCA_ACT_FLAG_LARGE_DUMP_ON: u32 = 1 << 0;
const TCA_ACT_FLAG_TERSE_DUMP: u32 = 1 << 1;

bitflags! {
    /// Flags to configure action dumps (list operations).
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Default, PartialOrd, Ord, Hash)]
    #[non_exhaustive]
    pub struct TcActionMessageFlags: u32 {
        /// If set, this flag enables more than `TCA_ACT_MAX_PRIO` actions in a single
        /// actions listing operation.
        const LargeDump = TCA_ACT_FLAG_LARGE_DUMP_ON;
        /// If set, this flag restricts an action dump to only include essential
        /// details.
        const TerseDump = TCA_ACT_FLAG_TERSE_DUMP;
        const _ = !0;
    }
}

/// [`TcActionMessageFlagsWithSelector`] sets the [`TcActionMessageFlags`] which
/// are to be included in an operation, based on the accompanying [`flags`] and
/// [`selector`] fields.
///
/// [`flags`]: #structfield.flags
/// [`selector`]: #structfield.selector
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default, PartialOrd, Ord, Hash)]
pub struct TcActionMessageFlagsWithSelector {
    /// A bitmask of [`TcActionMessageFlags`] to be associated with an
    /// operation.
    pub flags: TcActionMessageFlags,
    /// A bitmask to determine which flags are to be included in an operation.
    ///
    /// Any flags which are set in the [`flags`] field but which are not set in
    /// the [`selector`] field will be ignored.
    ///
    /// [`flags`]: #structfield.flags
    /// [`selector`]: #structfield.selector
    pub selector: TcActionMessageFlags,
}

impl Nla for TcActionMessageFlagsWithSelector {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32(out, self.flags.bits());
        append_u32(out, self.selector.bits());
        Ok(())
    }

    fn kind(&self) -> u16 {
        TCA_ROOT_FLAGS
    }
}

impl TcActionMessageFlagsWithSelector {
    /// Create a new [`TcActionMessageFlagsWithSelector`] with the given
    /// [`flags`].
    /// The [`selector`] field is set to the same value as [`flags`] (i.e., none
    /// of the [`flags`] will be ignored).
    ///
    /// [`flags`]: #structfield.flags
    /// [`selector`]: #structfield.selector
    #[must_use]
    pub fn new(flags: TcActionMessageFlags) -> Self {
        Self {
            flags,
            selector: flags,
        }
    }

    /// Create a new [`TcActionMessageFlagsWithSelector`] with the given
    /// [`flags`] and [`selector`].
    ///
    /// [`flags`]: #structfield.flags
    /// [`selector`]: #structfield.selector
    #[must_use]
    pub fn new_with_selector(
        flags: TcActionMessageFlags,
        selector: TcActionMessageFlags,
    ) -> Self {
        Self { flags, selector }
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TcActionMessageFlagsWithSelector {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let value = buf.value();
        if value.len() != 8 {
            return Err(DecodeError::from("invalid length"));
        }
        let flags = TcActionMessageFlags::from_bits(
            parse_u32(&value[..4]).context("invalid flags")?,
        )
        .ok_or_else(|| DecodeError::from("invalid flags selector"))?;
        let selector = TcActionMessageFlags::from_bits(
            parse_u32(&value[4..]).context("invalid flags seclector")?,
        )
        .ok_or_else(|| DecodeError::from("invalid flags selector"))?;
        Ok(Self::new_with_selector(flags, selector))
    }
}

const TCA_ACT_TAB: u16 = 1;
const TCA_ROOT_FLAGS: u16 = 2;
const TCA_ROOT_COUNT: u16 = 3;
const TCA_ROOT_TIME_DELTA: u16 = 4;
const TCA_ROOT_EXT_WARN_MSG: u16 = 5;

/// This enum is used to represent the different types of attributes that can be
/// part of a [`TcActionMessage`].
///
/// This enum is non-exhaustive, additional variants may be added in the future.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TcActionMessageAttribute {
    /// Collection of `TcActions`.
    Actions(Vec<TcAction>),
    /// Flags to configure action dumps (list operations).
    Flags(TcActionMessageFlagsWithSelector),
    /// Number of actions being dumped.
    RootCount(u32),
    /// Time delta.
    RootTimeDelta(u32),
    /// Extended warning message.
    RootExtWarnMsg(String),
    /// Other attributes unknown at the time of writing.
    Other(DefaultNla),
}

impl<'a> Parseable<NlaBuffer<'a>> for TcActionMessageAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            TCA_ACT_TAB => {
                let actions = buf
                    .nlas()
                    .map(|nla| TcAction::parse(&nla?))
                    .collect::<Result<Vec<_>, _>>()?;
                Self::Actions(actions)
            }
            TCA_ROOT_FLAGS => {
                Self::Flags(TcActionMessageFlagsWithSelector::parse(buf)?)
            }
            TCA_ROOT_COUNT => {
                let count =
                    parse_u32(buf.value()).context("Invalid TCA_ROOT_COUNT")?;
                Self::RootCount(count)
            }
            TCA_ROOT_TIME_DELTA => {
                let delta = parse_u32(buf.value())
                    .context("Invalid TCA_ROOT_TIME_DELTA")?;
                Self::RootTimeDelta(delta)
            }
            TCA_ROOT_EXT_WARN_MSG => {
                let msg = parse_string(buf.value())
                    .context("Invalid TCA_ROOT_EXT_WARN_MSG")?;
                Self::RootExtWarnMsg(msg)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

impl Nla for TcActionMessageAttribute {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Actions(actions) => (actions).emit(out)?,
            Self::Flags(flags) => flags.emit_value(out)?,
            Self::RootCount(count) => append_u32(out, *count),
            Self::RootTimeDelta(delta) => append_u32(out, *delta),
            Self::RootExtWarnMsg(msg) => append_bytes(out, msg.as_bytes()),
            Self::Other(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Actions(_) => TCA_ACT_TAB,
            Self::Flags(_) => TCA_ROOT_FLAGS,
            Self::RootCount(_) => TCA_ROOT_COUNT,
            Self::RootTimeDelta(_) => TCA_ROOT_TIME_DELTA,
            Self::RootExtWarnMsg(_) => TCA_ROOT_EXT_WARN_MSG,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl Parseable<[u8]> for TcActionMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let header = TcActionMessageHeader::parse(buf)
            .context("failed to parse tc message header")?;
        let attributes =
            Vec::<TcActionMessageAttribute>::parse(&buf[TCA_HEADER_LEN..])
                .context("failed to parse tc action message NLAs")?;
        Ok(Self { header, attributes })
    }
}

impl Emitable for TcActionMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        self.attributes.emit(out)?;
        Ok(())
    }
}
