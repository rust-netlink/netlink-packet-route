// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    nlas::link::Nla,
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError, LinkHeader, LinkMessageBuffer,
};

use super::{link_attr::links::Device, nlas::VecInfo, Link, LinkAttrs};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct LinkMessage {
    pub header: LinkHeader,
    pub nlas: Vec<Nla>,
}

impl Emitable for LinkMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<LinkMessageBuffer<&'a T>>
    for LinkMessage
{
    fn parse(buf: &LinkMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let header = LinkHeader::parse(buf)
            .context("failed to parse link message header")?;
        let interface_family = header.interface_family;
        let nlas = Vec::<Nla>::parse_with_param(buf, interface_family)
            .context("failed to parse link message NLAs")?;
        Ok(LinkMessage { header, nlas })
    }
}

impl<'a, T: AsRef<[u8]> + 'a>
    ParseableParametrized<LinkMessageBuffer<&'a T>, u16> for Vec<Nla>
{
    fn parse_with_param(
        buf: &LinkMessageBuffer<&'a T>,
        family: u16,
    ) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse_with_param(&nla_buf?, family)?);
        }
        Ok(nlas)
    }
}

impl<'a, T: AsRef<[u8]> + 'a>
    ParseableParametrized<LinkMessageBuffer<&'a T>, u8> for Vec<Nla>
{
    fn parse_with_param(
        buf: &LinkMessageBuffer<&'a T>,
        family: u8,
    ) -> Result<Self, DecodeError> {
        Vec::<Nla>::parse_with_param(buf, u16::from(family))
    }
}

impl LinkMessage {
    pub fn get_link_from_message(self) -> Box<dyn Link> {
        let mut base = LinkAttrs {
            index: self.header.index,
            flags: self.header.flags,
            link_layer_type: self.header.link_layer_type,
            ..Default::default()
        };
        if self.header.flags & libc::IFF_PROMISC as u32 != 0 {
            base.promisc = 1;
        }
        let mut link: Option<Box<dyn Link>> = None;
        for attr in self.nlas {
            match attr {
                Nla::Info(infos) => {
                    link = VecInfo(infos).get_link_info();
                }
                Nla::Address(a) => {
                    base.hardware_addr = a;
                }
                Nla::IfName(i) => {
                    base.name = i;
                }
                Nla::Mtu(m) => {
                    base.mtu = m;
                }
                Nla::Link(l) => {
                    base.parent_index = l;
                }
                Nla::Master(m) => {
                    base.master_index = m;
                }
                Nla::TxQueueLen(t) => {
                    base.txq_len = t;
                }
                Nla::IfAlias(a) => {
                    base.alias = a;
                }
                Nla::Stats(_s) => {}
                Nla::Stats64(_s) => {}
                Nla::Xdp(_x) => {}
                Nla::ProtoInfo(_) => {}
                Nla::OperState(_) => {}
                Nla::NetnsId(n) => {
                    base.net_ns_id = n;
                }
                Nla::GsoMaxSize(i) => {
                    base.gso_max_size = i;
                }
                Nla::GsoMaxSegs(e) => {
                    base.gso_max_seqs = e;
                }
                Nla::VfInfoList(_) => {}
                Nla::NumTxQueues(t) => {
                    base.num_tx_queues = t;
                }
                Nla::NumRxQueues(r) => {
                    base.num_rx_queues = r;
                }
                Nla::Group(g) => {
                    base.group = g;
                }
                _ => {
                    // skip unused attr
                }
            }
        }
        let mut ret = link.unwrap_or_else(|| Box::new(Device::default()));
        ret.set_attrs(base);
        ret
    }
}

#[cfg(test)]
mod test {
    use crate::{
        constants::*,
        link::LinkAttrs,
        nlas::link::{InfoKind, Nla, State},
        traits::{Emitable, ParseableParametrized},
        LinkHeader, LinkMessage, LinkMessageBuffer,
    };

    use crate::link::nlas::Info::Kind;

    #[rustfmt::skip]
    static HEADER: [u8; 96] = [
        0x00, // interface family
        0x00, // reserved
        0x04, 0x03, // link layer type 772 = loopback
        0x01, 0x00, 0x00, 0x00, // interface index = 1
        // Note: in the wireshark capture, the thrid byte is 0x01
        // but that does not correpond to any of the IFF_ flags...
        0x49, 0x00, 0x00, 0x00, // device flags: UP, LOOPBACK, RUNNING, LOWERUP
        0x00, 0x00, 0x00, 0x00, // reserved 2 (aka device change flag)

        // nlas
        0x07, 0x00, 0x03, 0x00, 0x6c, 0x6f, 0x00, // device name L=7,T=3,V=lo
        0x00, // padding
        0x08, 0x00, 0x0d, 0x00, 0xe8, 0x03, 0x00, 0x00, // TxQueue length L=8,T=13,V=1000
        0x05, 0x00, 0x10, 0x00, 0x00, // OperState L=5,T=16,V=0 (unknown)
        0x00, 0x00, 0x00, // padding
        0x05, 0x00, 0x11, 0x00, 0x00, // Link mode L=5,T=17,V=0
        0x00, 0x00, 0x00, // padding
        0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, // MTU L=8,T=4,V=65536
        0x08, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, // Group L=8,T=27,V=9
        0x08, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, // Promiscuity L=8,T=30,V=0
        0x08, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00, // Number of Tx Queues L=8,T=31,V=1
        0x08, 0x00, 0x28, 0x00, 0xff, 0xff, 0x00, 0x00, // Maximum GSO segment count L=8,T=40,V=65536
        0x08, 0x00, 0x29, 0x00, 0x00, 0x00, 0x01, 0x00, // Maximum GSO size L=8,T=41,V=65536
    ];

    #[test]
    fn packet_header_read() {
        let packet = LinkMessageBuffer::new(&HEADER[0..16]);
        assert_eq!(packet.interface_family(), 0);
        assert_eq!(packet.reserved_1(), 0);
        assert_eq!(packet.link_layer_type(), ARPHRD_LOOPBACK);
        assert_eq!(packet.link_index(), 1);
        assert_eq!(packet.flags(), IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
        assert_eq!(packet.change_mask(), 0);
    }

    #[test]
    fn packet_header_build() {
        let mut buf = vec![0xff; 16];
        {
            let mut packet = LinkMessageBuffer::new(&mut buf);
            packet.set_interface_family(0);
            packet.set_reserved_1(0);
            packet.set_link_layer_type(ARPHRD_LOOPBACK);
            packet.set_link_index(1);
            packet.set_flags(IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
            packet.set_change_mask(0);
        }
        assert_eq!(&buf[..], &HEADER[0..16]);
    }

    #[test]
    fn packet_nlas_read() {
        let packet = LinkMessageBuffer::new(&HEADER[..]);
        assert_eq!(packet.nlas().count(), 10);
        let mut nlas = packet.nlas();

        // device name L=7,T=3,V=lo
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 7);
        assert_eq!(nla.kind(), 3);
        assert_eq!(nla.value(), &[0x6c, 0x6f, 0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::IfName(String::from("lo")));

        // TxQueue length L=8,T=13,V=1000
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 13);
        assert_eq!(nla.value(), &[0xe8, 0x03, 0x00, 0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::TxQueueLen(1000));

        // OperState L=5,T=16,V=0 (unknown)
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 5);
        assert_eq!(nla.kind(), 16);
        assert_eq!(nla.value(), &[0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::OperState(State::Unknown));

        // Link mode L=5,T=17,V=0
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 5);
        assert_eq!(nla.kind(), 17);
        assert_eq!(nla.value(), &[0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::Mode(0));

        // MTU L=8,T=4,V=65536
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 4);
        assert_eq!(nla.value(), &[0x00, 0x00, 0x01, 0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::Mtu(65_536));

        // 0x00, 0x00, 0x00, 0x00,
        // Group L=8,T=27,V=9
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 27);
        assert_eq!(nla.value(), &[0x00, 0x00, 0x00, 0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::Group(0));

        // Promiscuity L=8,T=30,V=0
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 30);
        assert_eq!(nla.value(), &[0x00, 0x00, 0x00, 0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::Promiscuity(0));

        // Number of Tx Queues L=8,T=31,V=1
        // 0x01, 0x00, 0x00, 0x00
        let nla = nlas.next().unwrap().unwrap();
        nla.check_buffer_length().unwrap();
        assert_eq!(nla.length(), 8);
        assert_eq!(nla.kind(), 31);
        assert_eq!(nla.value(), &[0x01, 0x00, 0x00, 0x00]);
        let parsed = Nla::parse_with_param(&nla, AF_INET).unwrap();
        assert_eq!(parsed, Nla::NumTxQueues(1));
    }

    #[test]
    fn emit() {
        let header = LinkHeader {
            link_layer_type: ARPHRD_LOOPBACK,
            index: 1,
            flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP,
            ..Default::default()
        };

        let nlas = vec![
            Nla::IfName("lo".into()),
            Nla::TxQueueLen(1000),
            Nla::OperState(State::Unknown),
            Nla::Mode(0),
            Nla::Mtu(0x1_0000),
            Nla::Group(0),
            Nla::Promiscuity(0),
            Nla::NumTxQueues(1),
            Nla::GsoMaxSegs(0xffff),
            Nla::GsoMaxSize(0x1_0000),
        ];

        let packet = LinkMessage { header, nlas };

        let mut buf = vec![0; 96];

        assert_eq!(packet.buffer_len(), 96);
        packet.emit(&mut buf[..]);
    }

    #[test]
    fn test_get_link_from_message() {
        let header = LinkHeader {
            link_layer_type: ARPHRD_LOOPBACK,
            index: 1,
            flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP,
            ..Default::default()
        };

        let nlas = vec![
            Nla::IfName("lo".into()),
            Nla::TxQueueLen(1000),
            Nla::OperState(State::Unknown),
            Nla::Mode(0),
            Nla::Mtu(0x1_0000),
            Nla::Group(0),
            Nla::Promiscuity(0),
            Nla::NumTxQueues(1),
            Nla::GsoMaxSegs(0xffff),
            Nla::GsoMaxSize(0x1_0000),
            Nla::Info(vec![Kind(InfoKind::Veth)]),
        ];

        let link_attr = LinkAttrs {
            name: "lo".to_string(),
            txq_len: 1000,
            mtu: 65536,
            index: 1,
            flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP,
            link_layer_type: ARPHRD_LOOPBACK,
            num_tx_queues: 1,
            gso_max_size: 65536,
            gso_max_seqs: 65535,
            ..Default::default()
        };
        let packet = LinkMessage { header, nlas };
        let link = packet.get_link_from_message();
        assert_eq!(link.r#type(), "veth");
        assert_eq!(link.attrs(), &link_attr);
    }
}
