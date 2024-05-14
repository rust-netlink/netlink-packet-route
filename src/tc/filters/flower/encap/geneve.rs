use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::nla::{DefaultNla, Nla, NlaBuffer};
use netlink_packet_utils::parsers::{parse_u16_be, parse_u8};
use netlink_packet_utils::{DecodeError, Parseable};

const TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS: u16 = 1; /* u16 */
const TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE: u16 = 2; /* u8 */
const TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA: u16 = 3; /* 4 to 128 bytes */

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Options {
    Class(Class),
    Type(Type),
    Data(Data),
    Other(DefaultNla),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Option {
    pub class: Class,
    pub type_: Type,
    pub data: Data,
}

impl From<Option> for Vec<Options> {
    fn from(option: Option) -> Self {
        vec![
            Options::Class(option.class),
            Options::Type(option.type_),
            Options::Data(option.data),
        ]
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Class(u16);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Options {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(match buf.kind() {
            TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS => {
                Self::Class(Class::new(parse_u16_be(buf.value())?))
            }
            TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE => {
                Self::Type(Type::new(parse_u8(buf.value())?))
            }
            TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA => Self::Data(Data::parse(buf)?),
            _ => Err(DecodeError::from("Invalid geneve options attribute"))?,
        })
    }
}

impl From<u16> for Class {
    fn from(class: u16) -> Self {
        Self(class)
    }
}

impl Class {
    #[must_use]
    pub fn new(class: u16) -> Self {
        Self(class)
    }
}

impl Nla for Class {
    fn value_len(&self) -> usize {
        2
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        BigEndian::write_u16(buffer, self.0);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Class {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let len = buf.value().len();
        if len != 2 {
            return Err(DecodeError::from(format!(
                "Invalid length for GeneveClass attribute: {len}",
            )));
        }
        Ok(Self(BigEndian::read_u16(buf.value())))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct Type(u8);

impl Type {
    #[must_use]
    pub fn new(type_: u8) -> Self {
        Self(type_)
    }
}

impl From<u8> for Type {
    fn from(type_: u8) -> Self {
        Self(type_)
    }
}

impl Nla for Type {
    fn value_len(&self) -> usize {
        1
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0] = self.0;
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Type {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        if buf.value().len() != 1 {
            let len = buf.value().len();
            return Err(DecodeError::from(format!(
                "Invalid length for GeneveType attribute: {len}",
            )));
        }
        Ok(Self(buf.value()[0]))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct Data(Vec<u32>);

impl Data {
    #[must_use]
    pub fn new<T: AsRef<[u32]>>(data: T) -> Self {
        Self(data.as_ref().to_vec())
    }
}

impl From<Vec<u32>> for Data {
    fn from(data: Vec<u32>) -> Self {
        Self(data)
    }
}

impl Nla for Data {
    fn value_len(&self) -> usize {
        self.0.len() * 4
    }

    fn kind(&self) -> u16 {
        TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        for (i, d) in self.0.iter().enumerate() {
            BigEndian::write_u32(&mut buffer[(i * 4)..], *d);
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Data {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let data = buf.value();
        let len = data.len();
        if data.len() % 4 != 0 {
            return Err(DecodeError::from(format!(
                "Invalid length for GeneveData attribute: {len}",
            )));
        }
        Ok(Self(data.chunks(4).map(BigEndian::read_u32).collect()))
    }
}

impl Nla for Options {
    fn value_len(&self) -> usize {
        match self {
            Self::Class(c) => c.value_len(),
            Self::Type(t) => t.value_len(),
            Self::Data(d) => d.value_len(),
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Class(c) => c.kind(),
            Self::Type(t) => t.kind(),
            Self::Data(d) => d.kind(),
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Class(c) => c.emit_value(buffer),
            Self::Type(t) => t.emit_value(buffer),
            Self::Data(d) => d.emit_value(buffer),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }
}
