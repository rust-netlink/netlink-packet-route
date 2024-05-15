use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::nla::{DefaultNla, Nla, NlaBuffer};
use netlink_packet_utils::{DecodeError, Parseable};

const TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER: u16 = 1;
const TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX: u16 = 2;
const TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR: u16 = 3;
const TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Version(u8);

impl Nla for Version {
    fn value_len(&self) -> usize {
        1
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0] = self.0;
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Version {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        if buf.value().len() != 1 {
            return Err(DecodeError::from(format!(
                "Invalid length for ErspanVer attribute: {}",
                buf.value().len()
            )));
        }
        Ok(Self(buf.value()[0]))
    }
}

impl From<u8> for Version {
    fn from(ver: u8) -> Self {
        Self(ver)
    }
}

impl From<Version> for u8 {
    fn from(ver: Version) -> Self {
        ver.0
    }
}

impl Version {
    #[must_use]
    pub fn new(ver: u8) -> Self {
        Self(ver)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Index(u32);

impl Nla for Index {
    fn value_len(&self) -> usize {
        4
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        BigEndian::write_u32(buffer, self.0);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Index {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        if buf.value().len() != 4 {
            return Err(DecodeError::from(format!(
                "Invalid length for erspan::Index attribute: {}",
                buf.value().len()
            )));
        }
        Ok(Self(BigEndian::read_u32(buf.value())))
    }
}

impl From<u32> for Index {
    fn from(index: u32) -> Self {
        Self(index)
    }
}

impl From<Index> for u32 {
    fn from(index: Index) -> Self {
        index.0
    }
}

impl Index {
    #[must_use]
    pub fn new(index: u32) -> Self {
        Self(index)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[non_exhaustive]
pub enum Direction {
    Ingress = 0,
    Egress = 1,
    Other(u8), // This should never happen because it is nonsensical.
}

impl From<u8> for Direction {
    fn from(dir: u8) -> Self {
        match dir {
            0 => Self::Ingress,
            1 => Self::Egress,
            _ => Self::Other(dir),
        }
    }
}

impl From<Direction> for u8 {
    fn from(dir: Direction) -> Self {
        match dir {
            Direction::Ingress => 0,
            Direction::Egress => 1,
            Direction::Other(v) => v,
        }
    }
}

impl Nla for Direction {
    fn value_len(&self) -> usize {
        1
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0] = (*self).into();
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Direction {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        if buf.value().len() != 1 {
            return Err(DecodeError::from(format!(
                "Invalid length for erspan::Direction attribute: {}",
                buf.value().len()
            )));
        }
        Ok(buf.value()[0].into())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ErspanHwid(u8);

impl Nla for ErspanHwid {
    fn value_len(&self) -> usize {
        1
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0] = self.0;
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for ErspanHwid {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        if buf.value().len() != 1 {
            return Err(DecodeError::from(format!(
                "Invalid length for ErspanHwid attribute: {}",
                buf.value().len()
            )));
        }
        Ok(buf.value()[0].into())
    }
}

impl From<u8> for ErspanHwid {
    fn from(hwid: u8) -> Self {
        Self(hwid)
    }
}

impl From<ErspanHwid> for u8 {
    fn from(hwid: ErspanHwid) -> Self {
        hwid.0
    }
}

impl ErspanHwid {
    #[must_use]
    pub fn new(hwid: u8) -> Self {
        Self(hwid)
    }

    /// # Errors
    /// Returns `DecodeError` if the value is greater than 63.
    pub fn new_checked(hwid: u8) -> Result<Self, DecodeError> {
        if hwid >= (1 << 6) {
            return Err(DecodeError::from(format!(
                "Invalid value for ErspanHwid: {hwid}.  Must be less than 64",
            )));
        }
        Ok(Self(hwid))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Options {
    Version(Version),
    Index(Index),
    Direction(Direction),
    Hwid(ErspanHwid),
    Other(DefaultNla),
}

impl Nla for Options {
    fn value_len(&self) -> usize {
        match self {
            Self::Version(v) => v.value_len(),
            Self::Index(i) => i.value_len(),
            Self::Direction(d) => d.value_len(),
            Self::Hwid(h) => h.value_len(),
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Version(v) => v.kind(),
            Self::Index(i) => i.kind(),
            Self::Direction(d) => d.kind(),
            Self::Hwid(h) => h.kind(),
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Version(v) => v.emit_value(buffer),
            Self::Index(i) => i.emit_value(buffer),
            Self::Direction(d) => d.emit_value(buffer),
            Self::Hwid(h) => h.emit_value(buffer),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Options {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER => {
                Self::Version(Version::parse(buf)?)
            }
            TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX => {
                Self::Index(Index::parse(buf)?)
            }
            TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR => {
                Self::Direction(Direction::parse(buf)?)
            }
            TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID => {
                Self::Hwid(ErspanHwid::parse(buf)?)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
