// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, Emitable, Parseable};

/// Mirror of the kernel's `struct rtnl_link_ifmap`.
///
/// Never constructed; it exists so that `size_of` yields the layout the
/// kernel's C compiler produces for *this* target. `repr(C)` is what makes
/// that equivalence hold, since it applies the target's C ABI rules.
#[repr(C)]
struct RtnlLinkIfmap {
    mem_start: u64,
    mem_end: u64,
    base_addr: u64,
    irq: u16,
    dma: u8,
    port: u8,
}

/// Bytes the six fields themselves occupy.
///
/// Every ABI places them at the same offsets (0, 8, 16, 24, 26, 27); only the
/// trailing alignment padding differs. This is therefore the shortest payload
/// that still carries a complete map, and the minimum accepted when parsing.
const LINK_MAP_FIELDS_LEN: usize = 28;

/// Size of `struct rtnl_link_ifmap` as the running kernel lays it out: 28
/// where `u64` is 4-byte aligned (the i386 psABI), 32 where it is 8-byte
/// aligned (x86-64, arm, aarch64 -- the extra 4 bytes being trailing
/// padding). Used when emitting, so a map we produce is the size the local
/// kernel expects.
const LINK_MAP_LEN: usize = std::mem::size_of::<RtnlLinkIfmap>();

const _: () = assert!(
    LINK_MAP_LEN >= LINK_MAP_FIELDS_LEN,
    "rtnl_link_ifmap cannot be smaller than its own fields"
);

// The generated length check is a *minimum*, so declaring the fields' length
// here accepts both the padded (32-byte) and unpadded (28-byte) forms.
buffer!(MapBuffer(LINK_MAP_FIELDS_LEN) {
    memory_start: (u64, 0..8),
    memory_end: (u64, 8..16),
    base_address: (u64, 16..24),
    irq: (u16, 24..26),
    dma: (u8, 26),
    port: (u8, 27),
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
#[non_exhaustive]
pub struct Map {
    pub memory_start: u64,
    pub memory_end: u64,
    pub base_address: u64,
    pub irq: u16,
    pub dma: u8,
    pub port: u8,
}

impl<T: AsRef<[u8]>> Parseable<MapBuffer<T>> for Map {
    fn parse(buf: &MapBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            memory_start: buf.memory_start(),
            memory_end: buf.memory_end(),
            base_address: buf.base_address(),
            irq: buf.irq(),
            dma: buf.dma(),
            port: buf.port(),
        })
    }
}

impl Emitable for Map {
    fn buffer_len(&self) -> usize {
        LINK_MAP_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        // Zero any trailing alignment padding rather than leaving whatever
        // the caller's buffer happened to hold.
        buffer[LINK_MAP_FIELDS_LEN..LINK_MAP_LEN].fill(0);
        let mut buffer = MapBuffer::new(buffer);
        buffer.set_memory_start(self.memory_start);
        buffer.set_memory_end(self.memory_end);
        buffer.set_base_address(self.base_address);
        buffer.set_irq(self.irq);
        buffer.set_dma(self.dma);
        buffer.set_port(self.port);
    }
}
