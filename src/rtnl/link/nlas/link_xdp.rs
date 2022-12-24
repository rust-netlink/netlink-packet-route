// SPDX-License-Identifier: MIT

use std::{convert::TryFrom, mem::size_of, os::fd::RawFd};

use anyhow::Context;
use byteorder::{NativeEndian, WriteBytesExt};
use utils::parsers::parse_i32;

use crate::{
    constants::*,
    nlas::{Nla, NlaBuffer, NlasIterator},
    parsers::parse_u32,
    traits::Parseable,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Xdp {
    Unspec(Vec<u8>),
    Fd(RawFd),
    Attached(XdpAttached),
    Flags(u32),
    ProgId(u32),
    DrvProgId(u32),
    SkbProgId(u32),
    HwProgId(u32),
    ExpectedFd(u32),
}

impl Nla for Xdp {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Xdp::*;
        match self {
            Unspec(ref bytes)
                => bytes.len(),
            Fd(_) => size_of::<RawFd>(),
            Attached(_) => size_of::<XdpAttached>(),
            Flags(_) => size_of::<u32>(),
            ProgId(_) => size_of::<u32>(),
            DrvProgId(_) => size_of::<u32>(),
            SkbProgId(_) => size_of::<u32>(),
            HwProgId(_) => size_of::<u32>(),
            ExpectedFd(_) => size_of::<u32>(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, mut buffer: &mut [u8]) {
        use self::Xdp::*;
        match self {
            Unspec(ref bytes)
                => buffer.copy_from_slice(bytes),
            Fd(ref value) => buffer.write_i32::<NativeEndian>(*value).unwrap(),
            Attached(ref value) => buffer.write_u8(*value as u8).unwrap(),
            Flags(ref value) => buffer.write_u32::<NativeEndian>(*value).unwrap(),
            ProgId(ref value) => buffer.write_u32::<NativeEndian>(*value).unwrap(),
            DrvProgId(ref value) => buffer.write_u32::<NativeEndian>(*value).unwrap(),
            SkbProgId(ref value) => buffer.write_u32::<NativeEndian>(*value).unwrap(),
            HwProgId(ref value) => buffer.write_u32::<NativeEndian>(*value).unwrap(),
            ExpectedFd(ref value) => buffer.write_u32::<NativeEndian>(*value).unwrap(),
        }
    }

    fn kind(&self) -> u16 {
        use self::Xdp::*;
        match self {
            Unspec(_) => IFLA_XDP_UNSPEC as u16,
            Fd(_) => IFLA_XDP_FD as u16,
            Attached(_) => IFLA_XDP_ATTACHED as u16,
            Flags(_) => IFLA_XDP_FLAGS as u16,
            ProgId(_) => IFLA_XDP_PROG_ID as u16,
            DrvProgId(_) => IFLA_XDP_DRV_PROG_ID as u16,
            SkbProgId(_) => IFLA_XDP_SKB_PROG_ID as u16,
            HwProgId(_) => IFLA_XDP_HW_PROG_ID as u16,
            ExpectedFd(_) => IFLA_XDP_EXPECTED_FD as u16,
        }
    }
}

pub(crate) struct VecXdp(pub(crate) Vec<Xdp>);

// These NLAs are nested, meaning they are NLAs that contain NLAs. These NLAs
// can contain more nested NLAs nla->type     // IFLA_XDP
// nla->len
// nla->data[]   // <- You are here == Vec<Xdp>
//  nla->data[0].type   <- nla.kind()
//  nla->data[0].len
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for VecXdp {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut res = Vec::new();
        let nlas = NlasIterator::new(buf.into_inner());
        for nla in nlas {
            let nla = nla?;
            match nla.kind() as u32 {
                IFLA_XDP_UNSPEC => res.push(Xdp::Unspec(nla.value().to_vec())),
                IFLA_XDP_FD => res.push(Xdp::Fd(
                    parse_i32(nla.value())
                        .context("invalid IFLA_XDP_FD value")?,
                )),
                IFLA_XDP_ATTACHED => res.push(Xdp::Attached(
                    XdpAttached::try_from(nla.value()[0])
                        .context("invalid IFLA_XDP_ATTACHED value")?,
                )),
                IFLA_XDP_FLAGS => res.push(Xdp::Flags(
                    parse_u32(nla.value())
                        .context("invalid IFLA_XDP_FLAGS value")?,
                )),
                IFLA_XDP_PROG_ID => res.push(Xdp::ProgId(
                    parse_u32(nla.value())
                        .context("invalid IFLA_XDP_PROG_ID value")?,
                )),
                IFLA_XDP_DRV_PROG_ID => res.push(Xdp::DrvProgId(
                    parse_u32(nla.value())
                        .context("invalid IFLA_XDP_PROG_ID value")?,
                )),
                IFLA_XDP_SKB_PROG_ID => res.push(Xdp::SkbProgId(
                    parse_u32(nla.value())
                        .context("invalid IFLA_XDP_PROG_ID value")?,
                )),
                IFLA_XDP_HW_PROG_ID => res.push(Xdp::HwProgId(
                    parse_u32(nla.value())
                        .context("invalid IFLA_XDP_PROG_ID value")?,
                )),
                IFLA_XDP_EXPECTED_FD => res.push(Xdp::ExpectedFd(
                    parse_u32(nla.value())
                        .context("invalid IFLA_XDP_PROG_ID value")?,
                )),
                _ => {
                    return Err(
                        format!("unknown NLA type {}", nla.kind()).into()
                    )
                }
            }
        }
        Ok(VecXdp(res))
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum XdpAttached {
    /// XDP_ATTACHED_NONE
    None = XDP_ATTACHED_NONE,
    /// XDP_ATTACHED_DRV
    Driver = XDP_ATTACHED_DRV,
    /// XDP_ATTACHED_SKB
    SocketBuffer = XDP_ATTACHED_SKB,
    /// XDP_ATTACHED_HW
    Hardware = XDP_ATTACHED_HW,
    /// XDP_ATTACHED_MULTI
    Multiple = XDP_ATTACHED_MULTI,
}

impl TryFrom<u8> for XdpAttached {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            XDP_ATTACHED_NONE => Ok(XdpAttached::None),
            XDP_ATTACHED_DRV => Ok(XdpAttached::Driver),
            XDP_ATTACHED_SKB => Ok(XdpAttached::SocketBuffer),
            XDP_ATTACHED_HW => Ok(XdpAttached::Hardware),
            XDP_ATTACHED_MULTI => Ok(XdpAttached::Multiple),
            _ => Err(format!("unknown xdp attached type {}", value).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use utils::Emitable;

    use super::*;

    #[rustfmt::skip]
    static ATTACHED: [u8; 40] = [
        0x05, 0x00, // length = 5
        0x02, 0x00, // type = 2 = IFLA_XDP_ATTACHED
        0x00, 0x00, // none = XDP_ATTACHED_NONE
        0x00, 0x00, // padding
        0x05, 0x00, // length = 5
        0x02, 0x00, // type = 2 = IFLA_XDP_ATTACHED
        0x01, 0x00, // driver = XDP_ATTACHED_DRV
        0x00, 0x00, // padding
        0x05, 0x00, // length = 5
        0x02, 0x00, // type = 2 = IFLA_XDP_ATTACHED
        0x02, 0x00, // skb = XDP_ATTACHED_SKB
        0x00, 0x00, // padding
        0x05, 0x00, // length = 5
        0x02, 0x00, // type = 2 = IFLA_XDP_ATTACHED
        0x03, 0x00, // hw = XDP_ATTACHED_HW
        0x00, 0x00, // padding
        0x05, 0x00, // length = 5
        0x02, 0x00, // type = 2 = IFLA_XDP_ATTACHED
        0x04, 0x00, // hw = XDP_ATTACHED_MULTI
        0x00, 0x00, // padding
    ];

    #[test]
    fn parse_xdp_attached() {
        let nla = NlaBuffer::new_checked(&ATTACHED[..]).unwrap();
        let parsed = VecXdp::parse(&nla).unwrap().0;
        let expected = vec![
            Xdp::Attached(XdpAttached::None),
            Xdp::Attached(XdpAttached::Driver),
            Xdp::Attached(XdpAttached::SocketBuffer),
            Xdp::Attached(XdpAttached::Hardware),
            Xdp::Attached(XdpAttached::Multiple),
        ];
        assert_eq!(expected, parsed);
    }

    #[test]
    fn emit_xdp_attached() {
        // None
        let nlas = vec![Xdp::Attached(XdpAttached::None)];
        assert_eq!(nlas.as_slice().buffer_len(), 8);

        let mut vec = vec![0xff; 8];
        nlas.as_slice().emit(&mut vec);
        assert_eq!(&vec[..], &ATTACHED[..8]);

        // Driver
        let nlas = vec![Xdp::Attached(XdpAttached::Driver)];
        assert_eq!(nlas.as_slice().buffer_len(), 8);

        let mut vec = vec![0xff; 8];
        nlas.as_slice().emit(&mut vec);
        assert_eq!(&vec[..], &ATTACHED[8..16]);

        // SocketBuffer/skb
        let nlas = vec![Xdp::Attached(XdpAttached::SocketBuffer)];
        assert_eq!(nlas.as_slice().buffer_len(), 8);

        let mut vec = vec![0xff; 8];
        nlas.as_slice().emit(&mut vec);
        assert_eq!(&vec[..], &ATTACHED[16..24]);

        // Hardware
        let nlas = vec![Xdp::Attached(XdpAttached::Hardware)];
        assert_eq!(nlas.as_slice().buffer_len(), 8);

        let mut vec = vec![0xff; 8];
        nlas.as_slice().emit(&mut vec);
        assert_eq!(&vec[..], &ATTACHED[24..32]);

        // Multiple
        let nlas = vec![Xdp::Attached(XdpAttached::Multiple)];
        assert_eq!(nlas.as_slice().buffer_len(), 8);

        let mut vec = vec![0xff; 8];
        nlas.as_slice().emit(&mut vec);
        assert_eq!(&vec[..], &ATTACHED[32..]);
    }

    #[rustfmt::skip]
    static XDP: [u8; 68] = [
        0x09, 0x00, // length = 9
        0x00, 0x00, // type = 0 = IFLA_XDP_UNSPEC
        0x01, 0x02, 0x03, 0x04, 0x05, // gibberish
        0x00,       // padding
        0x00, 0x00, // padding
        0x08, 0x00, // length = 8
        0x01, 0x00, // type = 1 = IFLA_XDP_FD
        0xA0, 0x74, 0x00, 0x00, // 29856
        0x08, 0x00, // length = 8
        0x03, 0x00, // type = 3 = IFLA_XDP_FLAGS
        0x00, 0x00, 0x00, 0x00, // empty
        0x08, 0x00, // length = 8
        0x04, 0x00, // type = 4 = IFLA_XDP_PROG_ID
        0x67, 0x00, 0x00, 0x00, // 103
        0x08, 0x00, // length = 8
        0x05, 0x00, // type = 5 = IFLA_XDP_DRV_PROG_ID
        0x65, 0x00, 0x00, 0x00, // 101
        0x08, 0x00, // length = 8
        0x06, 0x00, // type = 6 = IFLA_XDP_DRV_SKB_ID
        0x65, 0x00, 0x00, 0x00, // 101
        0x08, 0x00, // length = 8
        0x07, 0x00, // type = 7 = IFLA_XDP_DRV_HW_ID
        0x65, 0x00, 0x00, 0x00, // 101
        0x08, 0x00, // length = 8
        0x08, 0x00, // type = 8 = IFLA_XDP_DRV_EXPECTED_FD
        0xA1, 0x74, 0x00, 0x00, // 29857
    ];

    #[test]
    fn parse_xdp() {
        let nla = NlaBuffer::new_checked(&XDP[..]).unwrap();
        let parsed = VecXdp::parse(&nla).unwrap().0;
        let expected = vec![
            Xdp::Unspec(vec![1, 2, 3, 4, 5]),
            Xdp::Fd(29856),
            Xdp::Flags(0),
            Xdp::ProgId(103),
            Xdp::DrvProgId(101),
            Xdp::SkbProgId(101),
            Xdp::HwProgId(101),
            Xdp::ExpectedFd(29857),
        ];
        assert_eq!(expected, parsed);
    }

    #[test]
    fn emit_xdp() {
        let nlas = vec![
            Xdp::Unspec(vec![1, 2, 3, 4, 5]),
            Xdp::Fd(29856),
            Xdp::Flags(0),
            Xdp::ProgId(103),
            Xdp::DrvProgId(101),
            Xdp::SkbProgId(101),
            Xdp::HwProgId(101),
            Xdp::ExpectedFd(29857),
        ];
        assert_eq!(nlas.as_slice().buffer_len(), XDP.len());

        let mut vec = vec![0xff; XDP.len()];
        nlas.as_slice().emit(&mut vec);
        assert_eq!(&vec[..], &XDP[..]);
    }
}
