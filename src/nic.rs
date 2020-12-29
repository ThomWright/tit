use etherparse;
use etherparse::TransportHeader;
use std::sync::{mpsc, Arc};
use tun_tap;

use crate::errors::TitError;
use crate::errors::{Result, TcpChannelError};
use crate::print;
use crate::print::Direction;
use crate::tcp;
use crate::tcp::TcpPacket;

/// Ethernet MTU = 1500
pub type EthernetPacket = [u8; 1500];
pub type NetworkChannelContents = (Box<EthernetPacket>, usize);
pub type SendEthernetPacket = mpsc::Sender<NetworkChannelContents>;

pub fn start_nic(tcp: tcp::IncomingPackets) -> Result<SendEthernetPacket> {
    // We don't care about the 4 byte header
    let tun = Arc::new(tun_tap::Iface::without_packet_info(
        "tun_tit%d",
        tun_tap::Mode::Tun,
    )?);

    let (incoming_packets, outgoing_packets) =
        mpsc::channel::<(Box<EthernetPacket>, usize)>();

    let write_tun = tun.clone();
    let _write = std::thread::spawn(move || {
        let tun = write_tun;
        let send_packet = move || -> Result<()> {
            let (packet, len) = outgoing_packets
                .recv()
                .map_err(|e| TitError::OutgoingNetworkChannelClosed(e))?;

            println!("SENDING");
            print::packet_overview(&packet[..len], Direction::Outgoing);
            println!();

            tun.send(&packet[..len])?;

            Ok(())
        };

        loop {
            send_packet().expect("error on NIC send thread");
        }
    });

    let _read = std::thread::spawn(|| {
        // I don't like reusing these, feels like I could accidentally expose data from previous packets if I'm not careful
        let mut rec_buf: EthernetPacket = [0u8; 1500];

        let mut receive_packet = move || -> Result<()> {
            let num_bytes = (&tun).recv(&mut rec_buf)?;
            assert!(num_bytes <= 1500);

            let raw_packet = &rec_buf[..num_bytes];

            handle_packet(&tcp, &raw_packet)?;

            Ok(())
        };
        loop {
            receive_packet().expect("error on NIC read thread");
        }
    });

    Ok(incoming_packets)
}

fn handle_packet(tcp: &tcp::IncomingPackets, raw_packet: &[u8]) -> Result<()> {
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
                        tcp.0
                            .send(TcpPacket::new(
                                ip_header.clone(),
                                tcp_header.clone(),
                                &packet.payload,
                            ))
                            .map_err(|e| {
                                TitError::IncomingTcpChannelClosed(
                                    TcpChannelError::Send(e.into()),
                                )
                            })?;
                    }
                    TransportHeader::Udp(_header) => {}
                }
            }
        }
    }
    Ok(())
}
