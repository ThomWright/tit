use etherparse;
use etherparse::TransportHeader;
use std::io;
use tun_tap;

use crate::ip_utils;
use crate::print;
use crate::tcp;

pub struct Interface {
    tun: tun_tap::Iface,
    tcp: tcp::Tcp,
}

impl Interface {
    pub fn new() -> io::Result<Interface> {
        // We don't care about the 4 byte header
        let iface = tun_tap::Iface::without_packet_info("tun_tit%d", tun_tap::Mode::Tun)?;

        let tcp_impl = tcp::Tcp::new();

        Ok(Interface {
            tun: iface,
            tcp: tcp_impl,
        })
    }

    pub fn listen(mut self) -> io::Result<()> {
        // Ethernet MTU = 1500
        // I don't like reusing these, feels like I could accidentally expose data from previous packets if I'm not careful
        let mut rec_buf = [0u8; 1500];
        let mut snd_buf = [0u8; 1500];
        loop {
            let num_bytes = self.tun.recv(&mut rec_buf)?;

            let raw_packet = &rec_buf[..num_bytes];

            let len = self.handle_packet(&raw_packet, &mut snd_buf);

            if let Some(len) = len {
                self.tun.send(&snd_buf[..len])?;
            }
        }
    }

    fn handle_packet(&mut self, raw_packet: &[u8], mut response: &mut [u8]) -> Option<usize> {
        match etherparse::PacketHeaders::from_ip_slice(&raw_packet) {
            Err(error) => eprintln!("Error: {}", error),
            Ok(packet) => {
                if let Some(ip) = &packet.ip {
                    let (src, dst) = ip_utils::get_ip_addresses(&ip);

                    // TODO: consider responding to pings (protocol=1 ICMP)

                    print::ip_packet_overview(&packet, &ip);

                    if let Some(transport) = &packet.transport {
                        match transport {
                            TransportHeader::Tcp(header) => {
                                let conn_id = tcp::ConnectionId::new(
                                    src,
                                    header.source_port,
                                    dst,
                                    header.destination_port,
                                );

                                println!("{}", conn_id);
                                print::tcp_header(&header);

                                return self.tcp.receive(
                                    conn_id,
                                    &header,
                                    &packet.payload,
                                    &mut response,
                                );
                            }
                            TransportHeader::Udp(_header) => {}
                        }
                    }
                    println!();
                }
            }
        }
        None
    }
}
