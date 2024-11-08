use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    parsers::{parse_u16, parse_u32},
    DecodeError, Emitable,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
/// Nexthop Group
pub struct NexthopGroup {
    /// Nexthop id
    pub id: u32,
    /// Weight of this nexthop
    pub weight: u8,
    /// High order bits of weight
    pub weight_high: u8,
    /// Reserved
    pub resvd2: u16,
}

impl Emitable for NexthopGroup {
    fn buffer_len(&self) -> usize {
        8
    }

    fn emit(&self, buffer: &mut [u8]) {
        NativeEndian::write_u32(buffer, self.id);
        buffer[4] = self.weight;
        buffer[5] = self.weight_high;
        NativeEndian::write_u16(&mut buffer[6..8], self.resvd2);
    }
}

impl NexthopGroup {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let grp = Self {
            id: parse_u32(payload)?,
            weight: payload[4],
            weight_high: payload[5],
            resvd2: parse_u16(&payload[6..8])?,
        };
        Ok(grp)
    }
}
