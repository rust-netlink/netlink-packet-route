use anyhow::Error;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Display, Formatter};

/// An MPLS label.
///
/// The MPLS label is a 20-bit value used to identify a particular forwarding
/// equivalence class (FEC) or to apply a particular operation to a packet.
///
/// See [RFC 3032][1] for more information.
///
/// # Outstanding questions:
///
/// Should we add handling for reserved labels as per the [IANA specs][2]?
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc3032
/// [2]: https://www.iana.org/assignments/mpls-label-values/mpls-label-values.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Label(u32);

impl Label {
    /// Creates a new `Label` value.
    /// Note:
    /// this function will allow you to create a label with a value greater than
    /// 0xFFFFF.
    /// Use `new` if you want to ensure that the label
    /// value is less than 0xFFFFF.
    #[must_use]
    pub fn new_unchecked(label: u32) -> Self {
        Self(label)
    }

    /// Creates a new `Label` value, ensuring that the label value is a legal
    /// MPLS label.
    ///
    /// # Safety
    /// You must ensure that the label value is less than 0xFFFFF if you want
    /// the resulting `Label` value to be semantically valid.
    ///
    /// # Errors
    /// Returns an error if the label value is greater than 20 bits (2^20 - 1 or
    /// 0xFFFFF).
    pub fn new(label: u32) -> Result<Self, Error> {
        if label > 0xFFFFF {
            Err(Error::msg("MPLS label must be less than 0xFFFFF"))?;
        }
        Ok(Self(label))
    }
}

impl TryFrom<u32> for Label {
    type Error = Error;

    fn try_from(label: u32) -> Result<Self, Self::Error> {
        Self::new(label)
    }
}

impl From<Label> for u32 {
    fn from(label: Label) -> u32 {
        label.0
    }
}

impl AsRef<u32> for Label {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

/// Bottom-of-stack flag.
///
/// If `Set`,
/// this indicates that the current label is the bottom of the label stack
/// (i.e., that there are no further MPLS labels before the payload).
/// Conversely, if `Unset`, this indicates that there are more labels to follow.
/// See [RFC 3032][1] for more information.
///
/// # Outstanding questions:
///
/// The "bottom of stack" flag is only a single bit wide.
/// For this reason, we can get away without marking this as non-exhaustive.
/// It is represented as `u8` in the netlink message.
///
/// [1]: https://www.rfc-editor.org/rfc/rfc3032.html
#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum BottomOfStack {
    Unset = 0,
    Set = 1,
}

impl From<u8> for BottomOfStack {
    /// Any value other than zero or one will trigger a warning log message
    /// on conversion.
    fn from(bos: u8) -> Self {
        match bos {
            0 => BottomOfStack::Unset,
            1 => BottomOfStack::Set,
            _ => {
                log::warn!(
                    "Invalid BottomOfStack value: {}, interpreting as Set",
                    bos
                );
                BottomOfStack::Set
            }
        }
    }
}

impl From<BottomOfStack> for u8 {
    fn from(value: BottomOfStack) -> Self {
        match value {
            BottomOfStack::Unset => 0,
            BottomOfStack::Set => 1,
        }
    }
}

impl From<bool> for BottomOfStack {
    fn from(value: bool) -> Self {
        if value {
            BottomOfStack::Set
        } else {
            BottomOfStack::Unset
        }
    }
}

impl From<BottomOfStack> for bool {
    fn from(value: BottomOfStack) -> Self {
        match value {
            BottomOfStack::Unset => false,
            BottomOfStack::Set => true,
        }
    }
}

impl Display for BottomOfStack {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BottomOfStack::Unset => {
                write!(f, "Unset")
            }
            BottomOfStack::Set => {
                write!(f, "Set")
            }
        }
    }
}

/// MPLS Traffic Class.
///
/// A 3-bit Traffic Class field for [quality of service][1] and [Explicit
/// Congestion Notification][2]
///
/// [1]: https://en.wikipedia.org/wiki/Quality_of_service
/// [2]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct TrafficClass(u8);

impl TrafficClass {
    /// Creates a new `TrafficClass` value.
    ///
    /// # Safety
    /// You must ensure that the value is less than 8 or the result will not be
    /// semantically valid.
    /// Use `new` if you want to ensure validity.
    #[must_use]
    pub fn new_unchecked(value: u8) -> Self {
        Self(value)
    }

    /// Creates a new `TrafficClass` value, ensuring that the value is a legal
    /// MPLS Traffic Class.
    ///
    /// # Errors
    /// Returns an error if the value is greater than three bits (7 or 0b111).
    pub fn new(value: u8) -> Result<Self, Error> {
        if value > 7 {
            Err(Error::msg("MPLS Traffic Class must be less than 8"))?;
        }
        Ok(Self(value))
    }
}

impl TryFrom<u8> for TrafficClass {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TrafficClass> for u8 {
    fn from(value: TrafficClass) -> u8 {
        value.0
    }
}

impl AsRef<u8> for TrafficClass {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}
