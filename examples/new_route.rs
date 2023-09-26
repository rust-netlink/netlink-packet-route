// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::{
    constants::AF_INET, route, RouteFlags, RouteHeader, RouteMessage,
    RtnlMessage, RTN_UNICAST, RTPROT_BOOT, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::net::Ipv4Addr;

fn main() {
    let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let route_msg_hdr = RouteHeader {
        address_family: AF_INET as u8,
        table: RT_TABLE_MAIN,
        scope: RT_SCOPE_UNIVERSE,
        protocol: RTPROT_BOOT,
        kind: RTN_UNICAST,
        source_prefix_length: 0,
        destination_prefix_length: 32,
        flags: RouteFlags::RTNH_F_ONLINK,
        ..Default::default()
    };

    let mut route_msg = RouteMessage::default();
    route_msg.header = route_msg_hdr;
    route_msg.nlas = vec![
        // lo
        route::Nla::Oif(1),
        route::Nla::Gateway(
            "169.254.1.1".parse::<Ipv4Addr>().unwrap().octets().to_vec(),
        ),
        route::Nla::Destination(
            "1.1.1.1".parse::<Ipv4Addr>().unwrap().octets().to_vec(),
        ),
    ];
    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

    let mut msg = NetlinkMessage::new(
        nl_hdr,
        NetlinkPayload::from(RtnlMessage::NewRoute(route_msg)),
    );

    msg.finalize();
    let mut buf = vec![0; msg.header.length as usize];

    msg.serialize(&mut buf[..msg.buffer_len()]);

    println!(">>> {msg:?}");

    socket
        .send(&buf, 0)
        .expect("failed to send netlink message");

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;

    'outer: loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();

        loop {
            let bytes = &receive_buffer[offset..];
            // Parse the message
            let rx_packet: NetlinkMessage<RtnlMessage> =
                NetlinkMessage::deserialize(bytes).unwrap();

            if let NetlinkPayload::Error(err) = rx_packet.payload {
                match err.code {
                    None => {
                        println!("Done!");
                        break 'outer;
                    }
                    Some(_) => {
                        eprintln!("Received a netlink error message: {err:?}");
                        return;
                    }
                }
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}
