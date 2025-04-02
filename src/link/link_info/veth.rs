// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    traits::{Emitable, Parseable},
    DecodeError,
};

use super::super::{LinkMessage, LinkMessageBuffer};

const VETH_INFO_PEER: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
// This data is not for querying/dumping as in kernel 6.5.8,
// because the `struct rtnl_link_ops veth_link_ops` does not have `fill_info`.
// Only for create veth
pub enum InfoVeth {
    Peer(LinkMessage),
    Other(DefaultNla),
}

impl Nla for InfoVeth {
    fn value_len(&self) -> usize {
        use self::InfoVeth::*;
        match *self {
            Peer(ref message) => message.buffer_len(),
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoVeth::*;
        match *self {
            Peer(ref message) => message.emit(buffer),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoVeth::*;
        match *self {
            Peer(_) => VETH_INFO_PEER,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>> for InfoVeth {
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, Self::Error> {
        use self::InfoVeth::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            VETH_INFO_PEER => {
                let buffer = LinkMessageBuffer::new_checked(&payload)?;
                Peer(LinkMessage::parse(&buffer)?)
            }
            _ => Other(DefaultNla::parse(buf)?),
        })
    }
}
