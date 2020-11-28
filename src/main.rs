use etherparse;
use etherparse::{
    InternetSlice::{Ipv4, Ipv6},
    TransportSlice::{Tcp, Udp},
};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::IpAddr;
use tun_tap;

use ip_proto_id::ip_protocol;

mod ip_proto_id;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct ConnectionId {
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
}

impl Display for ConnectionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port
        )
    }
}

fn main() -> io::Result<()> {
    // We don't care about the 4 byte header
    let iface = tun_tap::Iface::without_packet_info("tun_tit%d", tun_tap::Mode::Tun)?;

    loop {
        // Ethernet MTU = 1500
        let mut buf = [0u8; 1500];
        let num_bytes = iface.recv(&mut buf)?;

        let packet = &buf[..num_bytes];

        match etherparse::SlicedPacket::from_ip(packet) {
            Err(error) => eprintln!("Error: {}", error),
            Ok(sliced_packet) => {
                if let Some(ip) = sliced_packet.ip {
                    let (src, dst, protocol) = match ip {
                        Ipv4(header) => (
                            IpAddr::V4(header.source_addr()),
                            IpAddr::V4(header.destination_addr()),
                            header.protocol(),
                        ),
                        Ipv6(header, _extension) => (
                            IpAddr::V6(header.source_addr()),
                            IpAddr::V6(header.destination_addr()),
                            header.next_header(),
                        ),
                    };
                    // TODO: consider responding to pings (protocol=1 ICMP)
                    println!(
                        "{} -> {}\nprotocol: {:?} - payload: {} bytes ",
                        src,
                        dst,
                        ip_protocol(protocol).expect("Unknown IP protocol number"),
                        sliced_packet.payload.len(),
                    );
                    if let Some(transport) = sliced_packet.transport {
                        match transport {
                            Tcp(header) => {
                                let conn_id = ConnectionId {
                                    src_addr: src,
                                    src_port: header.source_port(),
                                    dst_addr: dst,
                                    dst_port: header.destination_port(),
                                };
                                println!("TCP {}", conn_id);
                            }
                            Udp(_header) => {}
                        }
                    }
                    println!();
                }
            }
        }
    }
}
