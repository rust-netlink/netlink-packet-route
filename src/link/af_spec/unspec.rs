// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    traits::{Emitable, Parseable},
    DecodeError,
};

use crate::link::{
    af_spec::{VecAfSpecInet, VecAfSpecInet6},
    AfSpecInet, AfSpecInet6,
};
use crate::AddressFamily;

// For `AF_UNSPEC`, the `IFLA_AF_SPEC` is two layer array:
//
// [{nla_len=408, nla_type=IFLA_AF_SPEC},
//     [
//         [{nla_len=140, nla_type=AF_INET}, [
//             {nla_len=136, nla_type=IFLA_INET_CONF}, [
//                 [IPV4_DEVCONF_FORWARDING-1] = 0,
//                 <omitted>
//                 [IPV4_DEVCONF_ARP_EVICT_NOCARRIER-1] = 1]]],
//         [{nla_len=264, nla_type=AF_INET6}, [
//             [{nla_len=8, nla_type=IFLA_INET6_FLAGS}, IF_READY],
//             [{nla_len=20, nla_type=IFLA_INET6_CACHEINFO},
//                 {
//                     max_reasm_len=65535,
//                     tstamp=3794,
//                     reachable_time=37584,
//                     retrans_time=1000}],
//             [{nla_len=232, nla_type=IFLA_INET6_CONF},
//                 [[DEVCONF_FORWARDING] = 0,
//                 <omitted>
//                 [DEVCONF_NDISC_EVICT_NOCARRIER] = 1]]]]]]

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum AfSpecUnspec {
    Inet(Vec<AfSpecInet>),
    Inet6(Vec<AfSpecInet6>),
    Other(DefaultNla),
}

pub(crate) struct VecAfSpecUnspec(pub(crate) Vec<AfSpecUnspec>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for VecAfSpecUnspec
{
    type Error = DecodeError;

    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, Self::Error> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf.into_inner()) {
            let nla = nla?;
            nlas.push(match nla.kind() {
                k if k == u8::from(AddressFamily::Inet) as u16 => {
                    AfSpecUnspec::Inet(
                        VecAfSpecInet::parse(&NlaBuffer::new_checked(
                            &nla.value(),
                        )?)?
                        .0,
                    )
                }
                k if k == u8::from(AddressFamily::Inet6) as u16 => {
                    AfSpecUnspec::Inet6(
                        VecAfSpecInet6::parse(&NlaBuffer::new_checked(
                            &nla.value(),
                        )?)?
                        .0,
                    )
                }
                _ => AfSpecUnspec::Other(DefaultNla::parse(&nla)?),
            })
        }
        Ok(Self(nlas))
    }
}

impl Nla for AfSpecUnspec {
    fn value_len(&self) -> usize {
        match *self {
            Self::Inet(ref nlas) => nlas.as_slice().buffer_len(),
            Self::Inet6(ref nlas) => nlas.as_slice().buffer_len(),
            Self::Other(ref nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match *self {
            Self::Inet(ref nlas) => nlas.as_slice().emit(buffer),
            Self::Inet6(ref nlas) => nlas.as_slice().emit(buffer),
            Self::Other(ref nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match *self {
            Self::Inet(_) => u8::from(AddressFamily::Inet) as u16,
            Self::Inet6(_) => u8::from(AddressFamily::Inet6) as u16,
            Self::Other(ref nla) => nla.kind(),
        }
    }
}
