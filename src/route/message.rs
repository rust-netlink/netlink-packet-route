// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

use super::{
    super::AddressFamily, attribute::RTA_ENCAP_TYPE, RouteAttribute,
    RouteHeader, RouteLwEnCapType, RouteMessageBuffer, RouteType,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct RouteMessage {
    pub header: RouteHeader,
    pub attributes: Vec<RouteAttribute>,
}

impl Emitable for RouteMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.attributes.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.attributes
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl<T: AsRef<[u8]>> Parseable<RouteMessageBuffer<&T>> for RouteMessage {
    type Error = DecodeError;

    fn parse(buf: &RouteMessageBuffer<&T>) -> Result<Self, Self::Error> {
        let header = RouteHeader::parse(buf)?;
        let address_family = header.address_family;
        let route_type = header.kind;
        Ok(RouteMessage {
            header,
            attributes: Vec::<RouteAttribute>::parse_with_param(
                buf,
                (address_family, route_type),
            )?,
        })
    }
}

impl<T: AsRef<[u8]>>
    ParseableParametrized<RouteMessageBuffer<&T>, (AddressFamily, RouteType)>
    for Vec<RouteAttribute>
{
    type Error = DecodeError;

    fn parse_with_param(
        buf: &RouteMessageBuffer<&T>,
        (address_family, route_type): (AddressFamily, RouteType),
    ) -> Result<Self, Self::Error> {
        let mut attributes = vec![];
        let mut encap_type = RouteLwEnCapType::None;
        // The RTA_ENCAP_TYPE is provided __after__ RTA_ENCAP, we should find
        // RTA_ENCAP_TYPE first.
        for nla_buf in buf.attributes() {
            let nla = match nla_buf {
                Ok(n) => n,
                Err(_) => continue,
            };
            if nla.kind() == RTA_ENCAP_TYPE {
                if let Ok(RouteAttribute::EncapType(v)) =
                    RouteAttribute::parse_with_param(
                        &nla,
                        (address_family, route_type, encap_type),
                    )
                {
                    encap_type = v;
                    break;
                }
            }
        }
        for nla_buf in buf.attributes() {
            attributes.push(RouteAttribute::parse_with_param(
                &nla_buf?,
                (address_family, route_type, encap_type),
            )?);
        }
        Ok(attributes)
    }
}
