// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    Emitable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP,
    NLM_F_REQUEST,
};
use netlink_packet_route::{
    link::{LinkAttribute, LinkExtentMask, LinkMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

fn main() {
    let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut message = LinkMessage::default();
    message.header.interface_family = AddressFamily::Bridge;
    message.attributes.push(LinkAttribute::ExtMask(vec![
        LinkExtentMask::BrvlanCompressed,
    ]));

    let mut packet = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::GetLink(message)),
    );
    packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    packet.header.sequence_number = 1;

    let mut buf = Vec::new();
    packet.emit(&mut buf).unwrap();

    println!(">>> {packet:?}");
    socket.send(&buf[..], 0).unwrap();

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;

    // we set the NLM_F_DUMP flag so we expect a multipart rx_packet in
    // response.
    loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();

        loop {
            let bytes = &receive_buffer[offset..];
            // `NetlinkMessage::deserialize` validates the netlink header and
            // decodes the payload according to the message type.
            let rx_packet: NetlinkMessage<RouteNetlinkMessage> =
                NetlinkMessage::deserialize(bytes).unwrap();

            println!("<<< {rx_packet:?}");

            if matches!(rx_packet.payload, NetlinkPayload::Done(_)) {
                println!("Done!");
                return;
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}
