use netlink_packet_core::{NlaBuffer, NlasIterator};

use super::NexthopFlags;

buffer!(NexthopMessageBuffer(8) {
    family: (u8, 0),
    scope: (u8, 1),
    protocol: (u8, 2),
    resvd: (u8, 3),
    flags_raw: (u32, 4..8),
    payload: (slice, 8..),
});

impl<T: AsRef<[u8]>> NexthopMessageBuffer<T> {
    pub fn flags(&self) -> NexthopFlags {
        NexthopFlags::from_bits_truncate(self.flags_raw())
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NexthopMessageBuffer<T> {
    pub fn set_flags(&mut self, flags: NexthopFlags) {
        self.set_flags_raw(flags.bits());
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> NexthopMessageBuffer<&'a T> {
    pub fn attributes(
        &self,
    ) -> impl Iterator<
        Item = Result<NlaBuffer<&'a [u8]>, netlink_packet_core::DecodeError>,
    > {
        NlasIterator::new(self.payload())
    }
}
