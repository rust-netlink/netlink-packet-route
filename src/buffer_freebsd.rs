// SPDX-License-Identifier: MIT

/// Buffer wrapper for FreeBSD netlink attributes.
///
/// FreeBSD nests its private attributes using a 4-byte header (native-endian
/// u16 length including the header itself, then u16 attribute type), followed
/// by the attribute value.
pub struct FreeBSDBuffer<T> {
    buffer: T,
}

pub(crate) const FREEBSD_NLA_HEADER_LEN: usize = 4;

impl<T> FreeBSDBuffer<T> {
    pub fn new(buffer: T) -> Self {
        FreeBSDBuffer { buffer }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]>> FreeBSDBuffer<T> {
    pub fn inner(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    /// Total attribute length (header included), in native byte order.
    pub fn length(&self) -> u16 {
        let len_bytes = [self.inner()[0], self.inner()[1]];
        u16::from_ne_bytes(len_bytes)
    }

    /// Attribute type, in native byte order.
    pub fn value_type(&self) -> u16 {
        let type_bytes = [self.inner()[2], self.inner()[3]];
        u16::from_ne_bytes(type_bytes)
    }

    /// Attribute payload (everything after the 4-byte header).
    pub fn value(&self) -> &[u8] {
        &self.buffer.as_ref()[FREEBSD_NLA_HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> FreeBSDBuffer<T> {
    /// Mutable attribute payload.
    pub fn value_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[FREEBSD_NLA_HEADER_LEN..]
    }

    pub fn set_length(&mut self, value: u16) {
        let buffer = self.buffer.as_mut();
        buffer[0..2].copy_from_slice(&value.to_ne_bytes());
    }

    pub fn set_value_type(&mut self, value: u16) {
        let buffer = self.buffer.as_mut();
        buffer[2..4].copy_from_slice(&value.to_ne_bytes());
    }
}
