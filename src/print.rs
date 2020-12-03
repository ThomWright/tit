use ansi_term::Colour;
use etherparse;
use etherparse::{TcpHeader, TransportHeader};

use crate::ip_utils;
use crate::ip_utils::IpPair;
use crate::tcp;

// TODO: Would be nice to define these as `Style`s, not colours, and maybe to use unique styles
const SRC_PORT: Colour = Colour::Red;
const DST_PORT: Colour = Colour::Cyan;
const SEQ_NUM: Colour = Colour::Blue;
const ACK_NUM: Colour = Colour::Purple;
const DATA_OFFSET: Colour = Colour::Green;
const RESERVED: Colour = Colour::White;
/// RFC 3540
const NS: Colour = Colour::Yellow;
/// RFC 3168
const CWR: Colour = Colour::Blue;
/// RFC 3168
const ECE: Colour = Colour::Cyan;
const URG: Colour = Colour::Red;
const ACK: Colour = Colour::Purple;
const PSH: Colour = Colour::Green;
const RST: Colour = Colour::Yellow;
const SYN: Colour = Colour::Blue;
const FIN: Colour = Colour::Red;
const WINDOW: Colour = Colour::Green;
const CHECKSUM: Colour = Colour::Cyan;
const URGENT: Colour = Colour::Red;
const OPTIONS: Colour = Colour::Purple;

pub fn tcp_key() {
    for s in &[
        SRC_PORT.paint("Source port"),
        DST_PORT.paint("Destination port"),
        SEQ_NUM.paint("Sequence number"),
        ACK_NUM.paint("Acknowledgement number"),
        DATA_OFFSET.paint("Data offset"),
        RESERVED.paint("Reserved"),
        NS.paint("NS: Nonce sum"),
        CWR.paint("CWR: Congestion window reduced"),
        ECE.paint("ECE: Explicit congestion notification echo"),
        URG.paint("URG: Urgent Pointer field significant"),
        ACK.paint("ACK: Acknowledgment field significant"),
        PSH.paint("PSH: Push function"),
        RST.paint("RST: Reset the connection"),
        SYN.paint("SYN: Synchronize sequence numbers"),
        FIN.paint("FIN: No more data from sender"),
        WINDOW.paint("Window"),
        CHECKSUM.paint("Checksum"),
        URGENT.paint("Urgent pointer"),
        OPTIONS.paint("Options"),
    ] {
        println!("{}", s);
    }
}

// TODO: print like this from the spec!
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// TODO: we should look at the actual data in the header
const RESERVED_VAL: u8 = 0;

pub fn tcp_header(header: &TcpHeader) {
    tcp_header_hex_line(&header);
    tcp_header_binary(&header);
    tcp_header_flags(&header);
    // TODO: print options
    // println!("{:#?}", tcp_header.options_iterator().collect::<Vec<_>>());
}

fn tcp_header_flags(header: &TcpHeader) {
    let mut flags = vec![];
    if header.ns {
        flags.push(NS.paint("NS"));
    };
    if header.cwr {
        flags.push(CWR.paint("CWR"));
    };
    if header.ece {
        flags.push(ECE.paint("ECE"));
    };
    if header.urg {
        flags.push(URG.paint("URG"));
    };
    if header.ack {
        flags.push(ACK.paint("ACK"));
    };
    if header.psh {
        flags.push(PSH.paint("PSH"));
    };
    if header.rst {
        flags.push(RST.paint("RST"));
    };
    if header.syn {
        flags.push(SYN.paint("SYN"));
    };
    if header.fin {
        flags.push(FIN.paint("FIN"));
    };

    if !flags.is_empty() {
        print!("Flags: ");
        for f in flags {
            print!("{} ", f);
        }
        println!();
    }
}

fn tcp_header_binary(header: &TcpHeader) {
    let bin_source_port = format!("{:016b}", header.source_port);
    let bin_destination_port = format!("{:016b}", header.destination_port);
    let bin_sequence_number = format!("{:032b}", header.sequence_number);
    let bin_acknowledgment_number =
        format!("{:032b}", header.acknowledgment_number);
    let bin_data_offset = format!("{:04b}", header.data_offset());
    let bin_reserved = format!("{:03b}", RESERVED_VAL);
    let bin_ns = format!("{:01b}", if header.ns { 1 } else { 0 });
    let bin_cwr = format!("{:01b}", if header.cwr { 1 } else { 0 });
    let bin_ece = format!("{:01b}", if header.ece { 1 } else { 0 });
    let bin_urg = format!("{:01b}", if header.urg { 1 } else { 0 });
    let bin_ack = format!("{:01b}", if header.ack { 1 } else { 0 });
    let bin_psh = format!("{:01b}", if header.psh { 1 } else { 0 });
    let bin_rst = format!("{:01b}", if header.rst { 1 } else { 0 });
    let bin_syn = format!("{:01b}", if header.syn { 1 } else { 0 });
    let bin_fin = format!("{:01b}", if header.fin { 1 } else { 0 });
    let bin_window_size = format!("{:016b}", header.window_size);
    let bin_checksum = format!("{:016b}", header.checksum);
    let bin_urgent_pointer = format!("{:016b}", header.urgent_pointer);

    println!(
        "{}{}\n{}\n{}\n{}{}{}{}{}{}{}{}{}{}{}{}\n{}{}",
        SRC_PORT.paint(bin_source_port),
        DST_PORT.paint(bin_destination_port),
        SEQ_NUM.paint(bin_sequence_number),
        ACK_NUM.paint(bin_acknowledgment_number),
        DATA_OFFSET.paint(bin_data_offset),
        RESERVED.paint(bin_reserved),
        NS.paint(bin_ns),
        CWR.paint(bin_cwr),
        ECE.paint(bin_ece),
        URG.paint(bin_urg),
        ACK.paint(bin_ack),
        PSH.paint(bin_psh),
        RST.paint(bin_rst),
        SYN.paint(bin_syn),
        FIN.paint(bin_fin),
        WINDOW.paint(bin_window_size),
        CHECKSUM.paint(bin_checksum),
        URGENT.paint(bin_urgent_pointer),
    );

    for four_bytes in header.options().chunks(4) {
        for byte in four_bytes {
            print!("{}", OPTIONS.paint(format!("{:08b}", byte)));
        }
        println!();
    }
}

fn tcp_header_hex_line(header: &TcpHeader) {
    let hex_source_port = format!("{:04x}", header.source_port);
    let hex_destination_port = format!("{:04x}", header.destination_port);
    let hex_sequence_number = format!("{:08x}", header.sequence_number);
    let hex_acknowledgment_number =
        format!("{:08x}", header.acknowledgment_number);
    let hex_data_offset = format!("{:01x}", header.data_offset());
    let hex_reserved = format!("{:01x}", RESERVED_VAL);
    let hex_ns = format!("{:01x}", if header.ns { 1 } else { 0 });
    let hex_cwr = format!("{:01x}", if header.cwr { 1 } else { 0 });
    let hex_ece = format!("{:01x}", if header.ece { 1 } else { 0 });
    let hex_urg = format!("{:01x}", if header.urg { 1 } else { 0 });
    let hex_ack = format!("{:01x}", if header.ack { 1 } else { 0 });
    let hex_psh = format!("{:01x}", if header.psh { 1 } else { 0 });
    let hex_rst = format!("{:01x}", if header.rst { 1 } else { 0 });
    let hex_syn = format!("{:01x}", if header.syn { 1 } else { 0 });
    let hex_fin = format!("{:01x}", if header.fin { 1 } else { 0 });
    let hex_window_size = format!("{:04x}", header.window_size);
    let hex_checksum = format!("{:04x}", header.checksum);
    let hex_urgent_pointer = format!("{:04x}", header.urgent_pointer);

    for s in &[
        SRC_PORT.paint(&hex_source_port),
        DST_PORT.paint(&hex_destination_port),
        SEQ_NUM.paint(&hex_sequence_number),
        ACK_NUM.paint(&hex_acknowledgment_number),
        DATA_OFFSET.paint(&hex_data_offset),
        RESERVED.paint(&hex_reserved),
    ] {
        print!("{} ", s);
    }

    for f in &[
        NS.paint(&hex_ns),
        CWR.paint(&hex_cwr),
        ECE.paint(&hex_ece),
        URG.paint(&hex_urg),
        ACK.paint(&hex_ack),
        PSH.paint(&hex_psh),
        RST.paint(&hex_rst),
        SYN.paint(&hex_syn),
        FIN.paint(&hex_fin),
    ] {
        print!("{}", f);
    }
    print!(" ");

    for s in &[
        WINDOW.paint(&hex_window_size),
        CHECKSUM.paint(&hex_checksum),
        URGENT.paint(&hex_urgent_pointer),
    ] {
        print!("{} ", s);
    }

    for o in header.options() {
        print!("{}", OPTIONS.paint(format!("{:x}", o)));
    }
    println!();
}

pub fn packet_overview(raw_packet: &[u8]) {
    match etherparse::PacketHeaders::from_ip_slice(&raw_packet) {
        Err(error) => eprintln!("Error: {}", error),
        Ok(packet) => match &packet.ip {
            Some(ip_hdr) => match &packet.transport {
                Some(tran_hdr) => match tran_hdr {
                    TransportHeader::Tcp(tcp_hdr) => {
                        let conn_id = tcp::ConnectionId::new(ip_hdr, tcp_hdr);
                        let inner_protocol =
                            ip_utils::get_next_protocol(ip_hdr);
                        print!("{}\n", conn_id);
                        println!(
                            "protocol: {:?} - payload: {} bytes ",
                            inner_protocol,
                            packet.payload.len(),
                        );
                        tcp_header(&tcp_hdr);
                    }
                    TransportHeader::Udp(_hdr) => {
                        let ip_pair = IpPair::from(ip_hdr);
                        let inner_protocol =
                            ip_utils::get_next_protocol(ip_hdr);
                        print!("{}\n", ip_pair);
                        println!(
                            "protocol: {:?} - payload: {} bytes ",
                            inner_protocol,
                            packet.payload.len(),
                        );
                    }
                },
                None => {
                    let ip_pair = IpPair::from(ip_hdr);
                    let inner_protocol = ip_utils::get_next_protocol(ip_hdr);
                    print!("{}\n", ip_pair);
                    println!(
                        "protocol: {:?} - payload: {} bytes ",
                        inner_protocol,
                        packet.payload.len(),
                    );
                }
            },
            None => {
                println!("Unknown packet");
            }
        },
    }
}
