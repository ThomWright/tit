use etherparse;
use etherparse::TransportHeader;
use tun_tap;

use crate::errors::Result;
use crate::print;
use crate::print::Direction;
use crate::tcp;

pub struct Interface {
    tun: tun_tap::Iface,
    tcp: tcp::Tcp,
}

impl Interface {
    pub fn new(tcp_impl: tcp::Tcp) -> Result<Interface> {
        // We don't care about the 4 byte header
        let iface = tun_tap::Iface::without_packet_info(
            "tun_tit%d",
            tun_tap::Mode::Tun,
        )?;

        Ok(Interface {
            tun: iface,
            tcp: tcp_impl,
        })
    }

    pub fn listen(mut self) -> Result<()> {
        // Ethernet MTU = 1500
        // I don't like reusing these, feels like I could accidentally expose data from previous packets if I'm not careful
        let mut rec_buf = [0u8; 1500];
        let mut snd_buf = [0u8; 1500];
        loop {
            let num_bytes = self.tun.recv(&mut rec_buf)?;

            let raw_packet = &rec_buf[..num_bytes];

            let len = self.handle_packet(&raw_packet, &mut snd_buf)?;

            if let Some(len) = len {
                self.tun.send(&snd_buf[..len])?;
            }
        }
    }

    fn handle_packet(
        &mut self,
        raw_packet: &[u8],
        mut response: &mut [u8],
    ) -> Result<Option<usize>> {
        println!("RECEIVED");
        print::packet_overview(&raw_packet, Direction::Incoming);
        println!();

        match etherparse::PacketHeaders::from_ip_slice(&raw_packet) {
            Err(error) => eprintln!("Error: {}", error),
            Ok(packet) => {
                // TODO: would be nice to be able to respond to e.g. pings (ICMP)

                if let (Some(ip_header), Some(trans_header)) =
                    (&packet.ip, &packet.transport)
                {
                    match trans_header {
                        TransportHeader::Tcp(tcp_header) => {
                            let res_len = self.tcp.receive(
                                &ip_header,
                                &tcp_header,
                                &packet.payload,
                                &mut response,
                            )?;

                            if let Some(len) = res_len {
                                println!("SENDING");
                                print::packet_overview(
                                    &response[..len],
                                    Direction::Outgoing,
                                );
                                println!();
                            }

                            return Ok(res_len);
                        }
                        TransportHeader::Udp(_header) => {}
                    }
                }
            }
        }
        Ok(None)
    }
}
